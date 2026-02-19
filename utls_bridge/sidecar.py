"""
SidecarManager — manages the Go TLS sidecar subprocess from Python.

Drop this file alongside your proxy.py and import SidecarManager.

Usage::

    from sidecar import SidecarManager

    # As context manager
    async with SidecarManager("/path/to/tls-sidecar") as sidecar:
        proxy = SessionProxy(..., sidecar=sidecar)
        ...

    # Or manual lifecycle
    sidecar = SidecarManager("/path/to/tls-sidecar")
    await sidecar.start()
    ...
    await sidecar.stop()
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


# ── Sentinel for fields we know about ──
_STATS_FIELDS = frozenset({
    "active_conns", "total_conns", "total_bytes",
    "tls_handshakes", "tls_errors", "socks_conns",
    "uptime_seconds", "goroutines",
})


@dataclass
class SidecarStats:
    """Stats snapshot from the Go sidecar."""
    active_conns: int = 0
    total_conns: int = 0
    total_bytes: int = 0
    tls_handshakes: int = 0
    tls_errors: int = 0
    socks_conns: int = 0
    uptime_seconds: float = 0.0
    goroutines: int = 0


class SidecarManager:
    """Manages the Go TLS sidecar process lifecycle.

    Starts the sidecar as an asyncio subprocess, waits for the READY
    signal, provides health checks and stats, handles graceful shutdown
    and optional auto-restart.

    The sidecar is shared across all SessionProxy instances. Each proxy
    passes its own SOCKS address per-connection via the CONNECT command.

    Parameters
    ----------
    binary_path : str
        Path to the compiled ``tls-sidecar`` Go binary.
    listen_host : str
        Host for the sidecar to bind to. Default ``127.0.0.1``.
    listen_port : int
        Port to listen on. ``0`` = OS-assigned (recommended).
    connect_timeout : float
        Sidecar's timeout for TCP + SOCKS + TLS handshake (seconds).
    idle_timeout : float
        Sidecar's pipe idle timeout (seconds).
    stats_interval : float
        How often the sidecar logs internal stats (seconds). 0 = disabled.
    max_conns : int
        Max concurrent connections. 0 = unlimited.
    auto_restart : bool
        If True, automatically restart the sidecar if it crashes.
    restart_delay : float
        Seconds to wait before restarting after a crash.
    max_restarts : int
        Maximum consecutive restarts before giving up. Reset on successful ping.
    startup_timeout : float
        Max seconds to wait for READY signal on startup.
    extra_args : list[str]
        Additional CLI arguments to pass to the sidecar binary.
    """

    def __init__(
        self,
        binary_path: str,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
        connect_timeout: float = 30.0,
        idle_timeout: float = 90.0,
        stats_interval: float = 60.0,
        max_conns: int = 0,
        auto_restart: bool = True,
        restart_delay: float = 1.0,
        max_restarts: int = 10,
        startup_timeout: float = 15.0,
        extra_args: Optional[list[str]] = None,
    ):
        self.binary_path = binary_path
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self.stats_interval = stats_interval
        self.max_conns = max_conns
        self.auto_restart = auto_restart
        self.restart_delay = restart_delay
        self.max_restarts = max_restarts
        self.startup_timeout = startup_timeout
        self.extra_args = extra_args or []

        # Runtime state
        self._process: Optional[asyncio.subprocess.Process] = None
        self._addr: Optional[str] = None
        self._bound_port: Optional[int] = None  # Remembered for stable restarts
        self._monitor_task: Optional[asyncio.Task] = None
        self._io_tasks: list[asyncio.Task] = []  # stdout/stderr forwarders
        self._stopping = False
        self._restart_count = 0
        self._started_at: Optional[float] = None

    # -- properties --------------------------------------------------------

    @property
    def addr(self) -> Optional[str]:
        """The sidecar's bound address ("127.0.0.1:PORT") or None if not running."""
        return self._addr

    @property
    def running(self) -> bool:
        """True if the sidecar process is alive."""
        return self._process is not None and self._process.returncode is None

    @property
    def pid(self) -> Optional[int]:
        """PID of the sidecar process, or None."""
        return self._process.pid if self._process else None

    @property
    def uptime(self) -> float:
        """Seconds since the sidecar was started."""
        if self._started_at is None:
            return 0.0
        return time.monotonic() - self._started_at

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> str:
        """Start the sidecar and wait for it to be ready.

        Returns the bound address string ("host:port").
        Raises RuntimeError if the sidecar fails to start.
        """
        if self.running:
            logger.warning("Sidecar already running (pid=%d)", self.pid)
            if self._addr is None:
                raise RuntimeError("Sidecar running but addr not set")
            return self._addr

        self._stopping = False
        self._addr = await self._spawn()
        self._started_at = time.monotonic()
        self._restart_count = 0

        # Remember port for stable restarts (so addr doesn't change)
        _, port_str = self._addr.rsplit(":", 1)
        self._bound_port = int(port_str)

        # Start background monitor for auto-restart
        if self.auto_restart:
            self._monitor_task = asyncio.create_task(
                self._monitor_loop(), name="sidecar-monitor"
            )

        logger.info("Sidecar started on %s (pid=%d)", self._addr, self.pid)
        return self._addr

    async def stop(self, timeout: float = 10.0) -> None:
        """Gracefully stop the sidecar.

        Sends SIGTERM, waits up to ``timeout`` seconds, then SIGKILL.
        """
        self._stopping = True
        self._addr = None  # Immediately signal "unavailable" to SessionProxy

        # Cancel monitor
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None

        # Cancel I/O forwarders
        await self._cancel_io_tasks()

        if not self._process:
            return

        proc = self._process
        if proc.returncode is not None:
            logger.debug("Sidecar already exited (rc=%d)", proc.returncode)
            self._process = None
            return

        logger.info("Stopping sidecar (pid=%d)...", proc.pid)

        # SIGTERM for graceful shutdown
        try:
            proc.send_signal(signal.SIGTERM)
        except ProcessLookupError:
            self._process = None
            return

        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
            logger.info("Sidecar stopped gracefully (rc=%d)", proc.returncode)
        except asyncio.TimeoutError:
            logger.warning("Sidecar didn't stop in %.1fs, sending SIGKILL", timeout)
            try:
                proc.kill()
                await asyncio.wait_for(proc.wait(), timeout=3.0)
            except (ProcessLookupError, asyncio.TimeoutError):
                pass
            logger.info("Sidecar killed")

        self._process = None

    async def restart(self) -> str:
        """Stop and restart the sidecar. Returns new bound address."""
        was_auto = self.auto_restart
        self.auto_restart = False  # prevent monitor from interfering
        await self.stop()
        self.auto_restart = was_auto
        return await self.start()

    # -- health checks -----------------------------------------------------

    async def ping(self, timeout: float = 5.0) -> bool:
        """Send PING to sidecar, expect PONG. Returns True if healthy."""
        if not self._addr:
            return False
        try:
            host, port_str = self._addr.rsplit(":", 1)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, int(port_str)),
                timeout=timeout,
            )
            try:
                writer.write(b"PING\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readline(), timeout=timeout)
                ok = resp.strip() == b"PONG"
                if ok:
                    self._restart_count = 0
                return ok
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        except Exception as e:
            logger.debug("Sidecar ping failed: %s", e)
            return False

    async def stats(self, timeout: float = 5.0) -> Optional[SidecarStats]:
        """Query sidecar stats. Returns SidecarStats or None on failure."""
        if not self._addr:
            return None
        try:
            host, port_str = self._addr.rsplit(":", 1)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, int(port_str)),
                timeout=timeout,
            )
            try:
                writer.write(b"STATS\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readline(), timeout=timeout)
                data = json.loads(resp.decode("utf-8").strip())
                # Filter to known fields so new Go-side fields don't break us
                filtered = {k: v for k, v in data.items() if k in _STATS_FIELDS}
                return SidecarStats(**filtered)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        except Exception as e:
            logger.debug("Sidecar stats failed: %s", e)
            return None

    # -- internal ----------------------------------------------------------

    def _build_args(self) -> list[str]:
        """Build CLI arguments for the sidecar binary."""
        # On restart, use the previously bound port for address stability.
        # This way all existing SessionProxy instances keep working.
        port = self._bound_port if self._bound_port is not None else self.listen_port
        args = [
            self.binary_path,
            "--listen", f"{self.listen_host}:{port}",
            "--connect-timeout", f"{self.connect_timeout}s",
            "--idle-timeout", f"{self.idle_timeout}s",
            "--stats-interval", f"{self.stats_interval}s",
        ]
        if self.max_conns > 0:
            args.extend(["--max-conns", str(self.max_conns)])
        args.extend(self.extra_args)
        return args

    async def _spawn(self) -> str:
        """Spawn the sidecar process and wait for READY signal.

        Returns the bound address from the READY line.
        """
        # Cancel any leftover I/O tasks from a previous process
        await self._cancel_io_tasks()

        args = self._build_args()
        logger.debug("Spawning sidecar: %s", " ".join(args))

        self._process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Start stderr forwarder (Go log output goes to stderr)
        stderr_task = asyncio.create_task(
            self._forward_stderr(), name="sidecar-stderr"
        )
        self._io_tasks.append(stderr_task)

        # Wait for READY line on stdout
        try:
            addr = await asyncio.wait_for(
                self._wait_ready(), timeout=self.startup_timeout
            )
            return addr
        except asyncio.TimeoutError:
            logger.error("Sidecar failed to start within %.1fs", self.startup_timeout)
            await self._kill_process()
            raise RuntimeError(
                f"Sidecar failed to start within {self.startup_timeout}s"
            )
        except Exception:
            await self._kill_process()
            raise

    async def _wait_ready(self) -> str:
        """Read stdout until we see 'READY <addr>' or 'ERROR <msg>'."""
        assert self._process and self._process.stdout

        while True:
            line = await self._process.stdout.readline()
            if not line:
                rc = await self._process.wait()
                raise RuntimeError(f"Sidecar exited during startup (rc={rc})")

            decoded = line.decode("utf-8", errors="replace").strip()

            if decoded.startswith("READY "):
                addr = decoded[6:].strip()
                logger.debug("Sidecar signaled READY on %s", addr)
                # Continue forwarding remaining stdout in background
                stdout_task = asyncio.create_task(
                    self._forward_stdout(), name="sidecar-stdout"
                )
                self._io_tasks.append(stdout_task)
                return addr

            if decoded.startswith("ERROR "):
                msg = decoded[6:].strip()
                raise RuntimeError(f"Sidecar startup error: {msg}")

            logger.debug("[sidecar:stdout] %s", decoded)

    async def _forward_stdout(self) -> None:
        """Forward remaining sidecar stdout to Python logger."""
        try:
            if not self._process or not self._process.stdout:
                return
            async for line in self._process.stdout:
                decoded = line.decode("utf-8", errors="replace").rstrip()
                if decoded:
                    logger.debug("[sidecar:stdout] %s", decoded)
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def _forward_stderr(self) -> None:
        """Forward sidecar stderr (Go log output) to Python logger."""
        try:
            if not self._process or not self._process.stderr:
                return
            async for line in self._process.stderr:
                decoded = line.decode("utf-8", errors="replace").rstrip()
                if decoded:
                    logger.debug("[sidecar] %s", decoded)
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def _cancel_io_tasks(self) -> None:
        """Cancel and await all I/O forwarder tasks."""
        tasks = self._io_tasks[:]
        self._io_tasks.clear()
        for t in tasks:
            if not t.done():
                t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _kill_process(self) -> None:
        """Force-kill the process if it's still running."""
        await self._cancel_io_tasks()
        if self._process and self._process.returncode is None:
            try:
                self._process.kill()
                await asyncio.wait_for(self._process.wait(), timeout=3.0)
            except (ProcessLookupError, asyncio.TimeoutError):
                pass

    async def _monitor_loop(self) -> None:
        """Background task: monitor sidecar process and auto-restart on crash."""
        try:
            while not self._stopping:
                await asyncio.sleep(5.0)

                if self._stopping:
                    break

                if self._process and self._process.returncode is not None:
                    rc = self._process.returncode
                    logger.warning("Sidecar exited unexpectedly (rc=%d)", rc)
                    self._addr = None  # Immediately signal "unavailable"

                    if self._restart_count >= self.max_restarts:
                        logger.error(
                            "Sidecar crashed %d times, giving up",
                            self._restart_count,
                        )
                        self._addr = None
                        break

                    self._restart_count += 1
                    logger.info(
                        "Restarting sidecar (attempt %d/%d) in %.1fs...",
                        self._restart_count, self.max_restarts, self.restart_delay,
                    )
                    await asyncio.sleep(self.restart_delay)

                    if self._stopping:
                        break

                    try:
                        self._addr = await self._spawn()
                        self._started_at = time.monotonic()
                        logger.info(
                            "Sidecar restarted on %s (pid=%d)",
                            self._addr, self.pid,
                        )
                    except RuntimeError as e:
                        logger.error("Sidecar restart failed: %s", e)
                    except asyncio.CancelledError:
                        # stop() was called during restart — kill any
                        # partially-started process and exit cleanly
                        await self._kill_process()
                        raise

        except asyncio.CancelledError:
            pass

    # -- context manager ---------------------------------------------------

    async def __aenter__(self) -> SidecarManager:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()

    def __repr__(self) -> str:
        status = "running" if self.running else "stopped"
        return f"<SidecarManager addr={self._addr} {status} pid={self.pid}>"