"""
SidecarManager — manages the Go TLS sidecar subprocess from Python.

The Go sidecar provides Chrome-fingerprinted TLS connections that are
indistinguishable from a real Chrome browser at the JA3/JA4 fingerprint
level.  This module handles the full lifecycle of that subprocess:
spawning, readiness detection, health checks, graceful shutdown, and
automatic restart on crash.

Architecture
~~~~~~~~~~~~
The sidecar is a single long-lived process shared across all
``SessionProxy`` instances.  Each proxy communicates its own SOCKS
address per-connection via the ``CONNECT`` command — there is no global
SOCKS configuration baked into the sidecar.

The manager reads the sidecar's ``READY <addr>`` line on startup to
learn the bound address.  If the sidecar crashes, the monitor loop
detects the exit and restarts the process on the **same port** so that
existing ``SessionProxy`` instances don't need to be reconfigured.

Thread safety
~~~~~~~~~~~~~
The manager is designed for use from a single asyncio event loop.  The
``addr`` property is read by ``SessionProxy`` tasks on that same loop.
No cross-thread synchronisation is needed because all access is
single-threaded under asyncio's cooperative scheduling.

Usage::

    from sidecar import SidecarManager

    # As async context manager (recommended)
    async with SidecarManager("/path/to/tls-sidecar") as sidecar:
        proxy = SessionProxy(..., sidecar=sidecar)
        ...

    # Manual lifecycle
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


# ── Known stat fields — guards against new Go-side fields breaking us ──
_STATS_FIELDS = frozenset({
    "active_conns", "total_conns", "total_bytes",
    "tls_handshakes", "tls_errors", "socks_conns",
    "uptime_seconds", "goroutines",
})


@dataclass
class SidecarStats:
    """Point-in-time stats snapshot from the Go sidecar.

    Mirrors the ``StatsSnapshot`` struct in the Go code.  Fields are
    populated from the JSON response to the ``STATS`` command.

    Attributes
    ----------
    active_conns:
        Currently open CONNECT pipes.
    total_conns:
        Lifetime CONNECT count since the sidecar started.
    total_bytes:
        Total bytes piped in both directions.
    tls_handshakes:
        Successful TLS handshakes.
    tls_errors:
        Failed TLS handshakes.
    socks_conns:
        Successful SOCKS5 tunnel establishments.
    uptime_seconds:
        Seconds since the sidecar process started.
    goroutines:
        Current Go runtime goroutine count.
    """
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

    Starts the sidecar as an asyncio subprocess, waits for the
    ``READY`` signal, provides health checks and stats, handles
    graceful shutdown and optional auto-restart.

    Parameters
    ----------
    binary_path:
        Path to the compiled ``tls-sidecar`` Go binary.
    listen_host:
        Host for the sidecar to bind to.  Default ``127.0.0.1``.
    listen_port:
        Port to listen on.  ``0`` means OS-assigned (recommended).
    connect_timeout:
        Sidecar's timeout for TCP + SOCKS5 + TLS handshake (seconds).
    idle_timeout:
        Sidecar's pipe idle timeout (seconds).
    stats_interval:
        How often the sidecar logs internal stats (seconds).  0 disables.
    max_conns:
        Max concurrent connections.  0 means unlimited.
    auto_restart:
        If ``True``, automatically restart the sidecar if it crashes.
    restart_delay:
        Seconds to wait before restarting after a crash.
    max_restarts:
        Maximum consecutive restarts before giving up.  The counter
        resets on a successful ``ping()``.
    startup_timeout:
        Max seconds to wait for the ``READY`` signal on startup.
    extra_args:
        Additional CLI arguments to pass to the sidecar binary.
    verify_ssl:
        Whether the sidecar should verify target TLS certificates.
        Set ``False`` only for development/testing.
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
        verify_ssl: bool = True,
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
        self.verify_ssl = verify_ssl

        # ── Runtime state ──
        self._process: Optional[asyncio.subprocess.Process] = None
        self._addr: Optional[str] = None
        self._bound_port: Optional[int] = None  # remembered for stable restarts
        self._monitor_task: Optional[asyncio.Task] = None
        self._io_tasks: list[asyncio.Task] = []  # stdout/stderr forwarders
        self._stopping = False
        self._restart_count = 0
        self._started_at: Optional[float] = None

    # ── properties ────────────────────────────────────────────────────────

    @property
    def addr(self) -> Optional[str]:
        """The sidecar's bound address (``"127.0.0.1:PORT"``) or ``None``."""
        return self._addr

    @property
    def running(self) -> bool:
        """``True`` if the sidecar process is alive."""
        return self._process is not None and self._process.returncode is None

    @property
    def pid(self) -> Optional[int]:
        """PID of the sidecar process, or ``None``."""
        return self._process.pid if self._process else None

    @property
    def uptime(self) -> float:
        """Seconds since the sidecar was started (0.0 if not running)."""
        if self._started_at is None:
            return 0.0
        return time.monotonic() - self._started_at

    # ── lifecycle ─────────────────────────────────────────────────────────

    async def start(self) -> str:
        """Start the sidecar and wait for it to be ready.

        Returns
        -------
        str
            The bound address (``"host:port"``).

        Raises
        ------
        RuntimeError
            If the sidecar fails to start within ``startup_timeout``.
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

        # Remember the port so restarts bind to the same address.
        # This means SessionProxy instances don't need to be
        # reconfigured after a sidecar crash + restart.
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

        Sends ``SIGTERM``, waits up to *timeout* seconds, then ``SIGKILL``.

        Parameters
        ----------
        timeout:
            Maximum seconds to wait for graceful shutdown before killing.
        """
        self._stopping = True
        # Immediately signal "unavailable" so SessionProxy connections
        # fail fast rather than trying to use a dying process.
        self._addr = None

        # Cancel monitor task
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

        # SIGTERM → the Go sidecar closes its listener and drains
        try:
            proc.send_signal(signal.SIGTERM)
        except ProcessLookupError:
            self._process = None
            return

        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
            logger.info("Sidecar stopped gracefully (rc=%d)", proc.returncode)
        except asyncio.TimeoutError:
            logger.warning(
                "Sidecar didn't stop in %.1fs, sending SIGKILL", timeout
            )
            try:
                proc.kill()
                await asyncio.wait_for(proc.wait(), timeout=3.0)
            except (ProcessLookupError, asyncio.TimeoutError):
                pass
            logger.info("Sidecar killed")

        self._process = None

    async def restart(self) -> str:
        """Stop and restart the sidecar.

        Returns
        -------
        str
            The new bound address (should match the old one if the port
            was successfully reused).
        """
        was_auto = self.auto_restart
        self.auto_restart = False  # prevent monitor from interfering
        await self.stop()
        self.auto_restart = was_auto
        return await self.start()

    # ── health checks ─────────────────────────────────────────────────────

    async def ping(self, timeout: float = 5.0) -> bool:
        """Send ``PING`` to the sidecar, expect ``PONG``.

        Returns ``True`` if the sidecar responded correctly.  A
        successful ping resets the consecutive restart counter, so
        transient crashes don't exhaust the restart budget.
        """
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
                resp = await asyncio.wait_for(
                    reader.readline(), timeout=timeout
                )
                ok = resp.strip() == b"PONG"
                if ok:
                    self._restart_count = 0  # healthy → reset counter
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
        """Query sidecar stats.

        Returns
        -------
        SidecarStats or None
            Stats snapshot, or ``None`` if the query failed.
        """
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
                resp = await asyncio.wait_for(
                    reader.readline(), timeout=timeout
                )
                data = json.loads(resp.decode("utf-8").strip())
                # Filter to known fields so new Go-side fields don't
                # break the dataclass constructor.
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

    # ── internal ──────────────────────────────────────────────────────────

    def _build_args(self) -> list[str]:
        """Build the CLI argument list for the sidecar binary.

        On restart, reuses ``_bound_port`` so the address stays stable
        and existing ``SessionProxy`` instances keep working without
        reconfiguration.
        """
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
        if not self.verify_ssl:
            args.append("--insecure")
        args.extend(self.extra_args)
        return args

    async def _spawn(self) -> str:
        """Spawn the sidecar process and wait for the ``READY`` signal.

        Returns the bound address from the ``READY`` line.

        Raises
        ------
        RuntimeError
            If the sidecar exits during startup, prints ``ERROR``, or
            doesn't become ready within ``startup_timeout``.
        """
        # Clean up any leftover I/O tasks from a previous process
        await self._cancel_io_tasks()

        args = self._build_args()
        logger.debug("Spawning sidecar: %s", " ".join(args))

        self._process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Start stderr forwarder (Go's log.Printf writes to stderr)
        stderr_task = asyncio.create_task(
            self._forward_stderr(), name="sidecar-stderr"
        )
        self._io_tasks.append(stderr_task)

        # Wait for the READY line on stdout
        try:
            addr = await asyncio.wait_for(
                self._wait_ready(), timeout=self.startup_timeout
            )
            return addr
        except asyncio.TimeoutError:
            logger.error(
                "Sidecar failed to start within %.1fs", self.startup_timeout
            )
            await self._kill_process()
            raise RuntimeError(
                f"Sidecar failed to start within {self.startup_timeout}s"
            )
        except Exception:
            await self._kill_process()
            raise

    async def _wait_ready(self) -> str:
        """Read stdout until we see ``READY <addr>`` or ``ERROR <msg>``.

        Any other lines are forwarded to the Python logger at DEBUG
        level (the sidecar shouldn't print anything else before READY,
        but we handle it gracefully).
        """
        assert self._process and self._process.stdout

        while True:
            line = await self._process.stdout.readline()
            if not line:
                # Process exited before printing READY
                rc = await self._process.wait()
                raise RuntimeError(
                    f"Sidecar exited during startup (rc={rc})"
                )

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

            # Unexpected pre-READY output — log and continue waiting
            logger.debug("[sidecar:stdout] %s", decoded)

    async def _forward_stdout(self) -> None:
        """Forward remaining sidecar stdout to the Python logger."""
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
        """Forward sidecar stderr (Go ``log.Printf`` output) to the Python logger."""
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
        """Force-kill the sidecar process if it's still running."""
        await self._cancel_io_tasks()
        if self._process and self._process.returncode is None:
            try:
                self._process.kill()
                await asyncio.wait_for(self._process.wait(), timeout=3.0)
            except (ProcessLookupError, asyncio.TimeoutError):
                pass

    async def _monitor_loop(self) -> None:
        """Background task: detect sidecar crashes and auto-restart.

        Polls every 5 seconds.  On crash detection:

        1. Sets ``_addr = None`` so SessionProxy connections fail fast.
        2. Checks the restart budget (``max_restarts``).
        3. Waits ``restart_delay`` seconds.
        4. Spawns a new process on the same port.

        If the restart also fails (e.g. port conflict), the error is
        logged and the loop retries on the next poll.

        The restart counter is reset whenever ``ping()`` succeeds, so
        a sidecar that crashes once but then runs stably doesn't
        accumulate towards the budget.

        FIX: On ``EADDRINUSE`` during restart (the OS reassigned the
        port in the brief window between crash and restart), fall back
        to port 0 (OS-assigned) and update ``_bound_port`` so
        subsequent restarts use the new port.
        """
        try:
            while not self._stopping:
                await asyncio.sleep(5.0)

                if self._stopping:
                    break

                if self._process and self._process.returncode is not None:
                    rc = self._process.returncode
                    logger.warning(
                        "Sidecar exited unexpectedly (rc=%d)", rc
                    )
                    self._addr = None

                    if self._restart_count >= self.max_restarts:
                        logger.error(
                            "Sidecar crashed %d times, giving up",
                            self._restart_count,
                        )
                        break

                    self._restart_count += 1
                    logger.info(
                        "Restarting sidecar (attempt %d/%d) in %.1fs...",
                        self._restart_count,
                        self.max_restarts,
                        self.restart_delay,
                    )
                    await asyncio.sleep(self.restart_delay)

                    if self._stopping:
                        break

                    try:
                        self._addr = await self._spawn()
                        self._started_at = time.monotonic()
                        logger.info(
                            "Sidecar restarted on %s (pid=%d)",
                            self._addr,
                            self.pid,
                        )
                    except RuntimeError as e:
                        err_msg = str(e)
                        # If the port is taken, fall back to OS-assigned
                        if "address already in use" in err_msg.lower():
                            logger.warning(
                                "Port %d in use, falling back to OS-assigned",
                                self._bound_port or 0,
                            )
                            self._bound_port = 0
                        else:
                            logger.error("Sidecar restart failed: %s", e)
                    except asyncio.CancelledError:
                        # stop() was called during restart — clean up
                        await self._kill_process()
                        raise

        except asyncio.CancelledError:
            pass

    # ── context manager ───────────────────────────────────────────────────

    async def __aenter__(self) -> SidecarManager:
        """Start the sidecar on entering the ``async with`` block."""
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        """Stop the sidecar on exiting the ``async with`` block."""
        await self.stop()

    def __repr__(self) -> str:
        status = "running" if self.running else "stopped"
        return f"<SidecarManager addr={self._addr} {status} pid={self.pid}>"
