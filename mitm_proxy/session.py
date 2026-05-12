"""SessionProxy — public API — and _ProxyHandler — per-connection dispatcher.

* ``_ProxyHandler`` — accepts each browser connection (``handle_client``
  is the asyncio.Server callback), determines whether it's a plain
  HTTP request or a CONNECT tunnel, performs MITM TLS for HTTPS, and
  dispatches to the appropriate protocol handler based on negotiated
  ALPN.
* ``SessionProxy`` — the user-facing class.  Owns the listening
  socket, the active policy, the interceptor registry, the connection
  pool for graceful teardown, and (optionally) a SOCKS5 proxy pool
  and TLS sidecar.

Anything a caller imports from the package goes through this module
or its re-exports in ``__init__``.
"""

from __future__ import annotations

import asyncio
import socket as _socket
import threading
import traceback
from asyncio import StreamReader, StreamWriter
from typing import Coroutine, Optional, Sequence
from urllib.parse import urlparse

import h2.connection

from .utls_bridge.sidecar import SidecarManager

from ._common import logger, ProxyConfig, DEFAULT_CONFIG, Protocol
from ._interceptor import (
    InterceptedResponse,
    RequestInterceptor,
    _ResponseCapture,
)
from ._io import (
    ManagedConnection,
    Socks5Client,
    SocksProxyPool,
    TLSInterceptor,
)
from ._policy import DefaultPolicy, Policy
from ._http1 import Http1Handler
from ._http2 import Http2Handler


class _ProxyHandler:
    """Accepts individual browser connections and dispatches them.

    Plain HTTP requests are forwarded directly.  CONNECT tunnels are
    intercepted with a MITM TLS handshake so traffic can be inspected.
    """

    __slots__ = ("_proxy", "tls", "http1", "http2", "config")

    def __init__(
        self, proxy: SessionProxy, tls: TLSInterceptor, config: ProxyConfig
    ):
        # Strong reference.  ``SessionProxy.stop()`` is the single
        # end-of-life moment: it closes the listening server, then awaits
        # every in-flight handler task (registered via ``_spawn``), then
        # drops ``self._handler``.  By the time the SessionProxy becomes
        # eligible for collection, no handler is observably running, so
        # no handler can witness a "destroyed proxy".  The cycle
        # SessionProxy → _ProxyHandler → _proxy is broken in stop() by
        # clearing ``self._handler``.
        self._proxy = proxy
        self.tls = tls
        self.config = config
        self.http1 = Http1Handler(proxy, config)
        self.http2 = Http2Handler(proxy, config)

    async def handle_client(
        self, reader: StreamReader, writer: StreamWriter
    ) -> None:
        """Entry point for each new browser connection (called by ``asyncio.Server``)."""
        # Register the current connection task with the SessionProxy so
        # ``stop()`` can await it.  ``_spawn`` (used by start()) also
        # registers the task on creation; calling _register_task here is
        # idempotent (set semantics) and also covers the case where
        # start_server invokes us directly.
        task = asyncio.current_task()
        if task is not None:
            self._proxy._register_task(task)

        client = ManagedConnection(reader, writer)
        self._proxy._track_connection(client)

        try:
            req = await self.http1._read_request(client)
            if req is None:
                return

            method, path, version, raw_headers, body = req

            if method == "CONNECT":
                await self._handle_connect(client, path)
            else:
                headers_dict = {k.lower(): v for k, v in raw_headers}
                await self._handle_plain_http(
                    client, method, path, version, raw_headers, body, headers_dict,
                )

        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            # Shutdown-initiated; let it propagate after cleanup.
            raise
        except Exception:
            logger.debug("Client handler error: %s", traceback.format_exc())
        finally:
            self._proxy._untrack_connection(client)
            await client.close()

    # -- plain HTTP --------------------------------------------------------

    async def _handle_plain_http(
        self,
        client: ManagedConnection,
        method: str,
        target_url: str,
        version: str,
        raw_headers: list[tuple[str, str]],
        body: bytes,
        headers_dict: dict[str, str],
    ) -> None:
        """Forward a plain (non-CONNECT) HTTP request."""
        target: Optional[ManagedConnection] = None

        try:
            parsed = urlparse(target_url)
            if parsed.scheme and parsed.scheme.lower() == "https":
                client.writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await client.writer.drain()
                return

            if parsed.netloc:
                host = parsed.hostname or ""
                port = parsed.port or 80
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"
            else:
                host_header = headers_dict.get("host", "")
                if not host_header:
                    client.writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    await client.writer.drain()
                    return
                if ":" in host_header:
                    host, port_str = host_header.rsplit(":", 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        logger.warning(
                            "Malformed Host header port %r", host_header,
                        )
                        client.writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                        await client.writer.drain()
                        return
                else:
                    host, port = host_header, 80
                path = target_url

            if not host:
                client.writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await client.writer.drain()
                return

            target = await self._connect_to_target(host, port)
            self._proxy._track_connection(target)
            display_host = f"{host}:{port}" if port != 80 else host

            socks = self._proxy.socks_proxy
            logger.trace(
                "[REQ] %s http://%s%s via %s",
                method,
                display_host,
                path,
                socks or "direct",
            )

            await self.http1.handle_with_buffered(
                client, target, display_host,
                method, path, version, raw_headers, body,
                is_https=False,
            )

        except asyncio.TimeoutError:
            self._try_error(
                client, b"HTTP/1.1 504 Gateway Timeout\r\n\r\n"
            )
        except (ConnectionRefusedError, ConnectionError):
            self._try_error(client, b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except Exception as e:
            logger.error("[HTTP] Error: %s", e)
            self._try_error(
                client, b"HTTP/1.1 500 Internal Server Error\r\n\r\n"
            )
        finally:
            if target:
                self._proxy._untrack_connection(target)
                await target.close()

    # -- CONNECT -----------------------------------------------------------

    async def _handle_connect(
        self, client: ManagedConnection, target_url: str
    ) -> None:
        """Handle a CONNECT tunnel (HTTPS interception).

        Sequence:
        1. Send ``200 Connection Established`` to the browser.
        2. Pause reading so the browser's ClientHello stays in the
           kernel buffer (not in asyncio's StreamReader).
        3. Connect to the target and negotiate TLS (possibly via
           sidecar for Chrome fingerprinting).
        4. Learn the target's ALPN (h2 vs http/1.1).
        5. Perform the browser-side MITM TLS handshake, offering only
           protocols the target supports.
        6. Proxy traffic using the appropriate handler.
        """
        if ":" in target_url:
            host, port_str = target_url.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                logger.warning(
                    "Malformed CONNECT target %r — closing connection",
                    target_url,
                )
                try:
                    client.writer.write(
                        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
                    )
                    await client.writer.drain()
                except Exception:
                    pass
                return
        else:
            host, port = target_url, 443

        target: Optional[ManagedConnection] = None
        client_tls: Optional[ManagedConnection] = None
        target_tls: Optional[ManagedConnection] = None

        try:
            # Step 1: Send "200" and pause reading
            client.writer.write(
                b"HTTP/1.1 200 Connection Established\r\n\r\n"
            )
            await client.writer.drain()
            client.writer.transport.pause_reading() # type: ignore

            # Step 2: Connect to target, learn its protocol.
            use_sidecar = self._proxy.sidecar is not None

            if use_sidecar:
                target_tls, target_protocol = (
                    await self._connect_via_sidecar(host, port)
                )
                self._proxy._track_connection(target_tls)
            else:
                target = await self._connect_to_target(host, port)
                self._proxy._track_connection(target)

                target_tls, target_protocol = await self._start_tls(
                    target, side="target", hostname=host,
                )
                self._proxy._track_connection(target_tls)

            # Step 3: Browser MITM TLS with matching protocol
            if target_protocol == Protocol.HTTP2:
                browser_alpn = ("h2", "http/1.1")
            else:
                browser_alpn = ("http/1.1",)

            client_tls, protocol = await self._start_tls(
                client, side="client", hostname=host, alpn=browser_alpn,
            )
            self._proxy._track_connection(client_tls)

            # Step 4: Proxy traffic
            if protocol == Protocol.HTTP2:
                await self.http2.start_session(client_tls, target_tls, host)
            else:
                await self.http1.handle(
                    client_tls, target_tls, host, is_https=True
                )

        except asyncio.TimeoutError:
            logger.warning("[%s:%d] Timeout", host, port)
            self._proxy._deliver_connect_error(
                host,
                port,
                TimeoutError(f"CONNECT to {host}:{port} timed out"),
            )
        except (ConnectionRefusedError, ConnectionError, OSError) as e:
            logger.warning("[%s:%d] Connection error: %s", host, port, e)
            self._proxy._deliver_connect_error(host, port, e)
        except Exception as e:
            logger.error(
                "[%s:%d] Error: %s\n%s",
                host,
                port,
                e,
                traceback.format_exc(),
            )
            self._proxy._deliver_connect_error(host, port, e)
        finally:
            for conn in (target_tls, client_tls, target):
                if conn:
                    self._proxy._untrack_connection(conn)
                    await conn.close()

    async def _connect_via_sidecar(
        self, host: str, port: int
    ) -> tuple[ManagedConnection, Protocol]:
        """Connect to target through the Go TLS sidecar.

        The sidecar handles TCP → (optional SOCKS5) → Chrome-fingerprinted
        TLS.  Returns a plaintext ``ManagedConnection`` (the TLS
        termination lives in the Go process) and the protocol the target
        negotiated.
        """
        sidecar = self._proxy.sidecar
        if sidecar is None or sidecar.addr is None:
            raise ConnectionError("Sidecar not available")

        sidecar_addr = sidecar.addr
        socks = self._proxy.socks_proxy

        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        try:
            # NOTE: We use the blocking ``sock.connect()`` here, not
            # ``loop.sock_connect()``, because uvloop's sock_connect
            # rejects null bytes in the path and we need them for the
            # Linux abstract namespace ("\x00<name>").  An abstract-
            # namespace connect to a local listener is a single syscall
            # with no network round-trip, so the blocking call resolves
            # essentially instantly — it does not stall the event loop
            # in any measurable way.
            sock.connect(b"\x00" + sidecar_addr.lstrip("@").encode("ascii"))
            sock.setblocking(False)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(sock=sock),
                timeout=5.0,
            )
        except Exception:
            sock.close()
            raise

        try:
            target = f"{host}:{port}"
            if socks:
                cmd = f"CONNECT {target} socks5://{socks}\n"
            else:
                cmd = f"CONNECT {target}\n"

            writer.write(cmd.encode("utf-8"))
            await writer.drain()

            async with asyncio.timeout(self.config.connect_timeout):
                resp_line = await reader.readline()

            if not resp_line:
                raise ConnectionError(
                    f"Sidecar closed connection for {target}"
                )

            resp = resp_line.decode("utf-8", errors="replace").strip()

            if resp.startswith("ERR "):
                raise ConnectionError(
                    f"Sidecar error for {target}: {resp[4:]}"
                )
            if not resp.startswith("OK "):
                raise ConnectionError(
                    f"Sidecar unexpected response: {resp}"
                )

            alpn = resp[3:].strip()
            protocol = Protocol.HTTP2 if alpn == "h2" else Protocol.HTTP1

            logger.debug(
                "[SIDECAR] %s via %s (alpn=%s)",
                target,
                socks or "direct",
                alpn,
            )
            return ManagedConnection(reader, writer), protocol

        except Exception:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            except Exception:
                pass
            raise

    # -- TLS ---------------------------------------------------------------

    async def _start_tls(
        self,
        conn: ManagedConnection,
        *,
        side: str,  # "client" or "target"
        hostname: str,
        alpn: Sequence[str] = ("h2", "http/1.1"),
    ) -> tuple[ManagedConnection, Protocol]:
        """Upgrade *conn* to TLS using the existing transport.

        ``side="client"``: server-side handshake against the browser,
        using the per-host MITM cert from ``TLSInterceptor``.  *alpn*
        is what we offer the browser — typically restricted to what
        the target side just negotiated, so we never offer h2 if the
        origin doesn't support it.

        ``side="target"``: client-side handshake against the origin,
        using the standard verifying client context.  *alpn* is what
        we offer the origin (typically ``("h2", "http/1.1")``).

        Returns ``(wrapped_connection, negotiated_protocol)``.  The
        caller is responsible for tracking the new ManagedConnection
        in ``SessionProxy._active_connections``.
        """
        loop = asyncio.get_running_loop()
        transport = conn.writer.transport
        proto_obj = transport.get_protocol()

        async with asyncio.timeout(self.config.connect_timeout):
            if side == "client":
                ctx = self.tls.get_server_context(tuple(alpn))
                error_label = "Client"
                ssl_transport = await loop.start_tls(
                    transport, proto_obj, ctx, server_side=True,
                )
            else:
                ctx = self.tls.create_client_context(
                    alpn=list(alpn), verify=self.config.verify_ssl
                )
                error_label = "Target"
                ssl_transport = await loop.start_tls(
                    transport, proto_obj, ctx,
                    server_side=False,
                    server_hostname=hostname,
                )

        if ssl_transport is None:
            raise ConnectionError(f"{error_label} TLS handshake failed")

        ssl_obj = ssl_transport.get_extra_info("ssl_object")
        negotiated = ssl_obj.selected_alpn_protocol() if ssl_obj else None
        protocol = Protocol.HTTP2 if negotiated == "h2" else Protocol.HTTP1

        # Build the asyncio StreamReader/Writer pair around the new
        # SSL transport.  This is the only way to get a Stream-style
        # interface back after start_tls() — there's no public helper.
        tls_reader = StreamReader()
        tls_proto = asyncio.StreamReaderProtocol(tls_reader)
        ssl_transport.set_protocol(tls_proto)
        tls_proto.connection_made(ssl_transport)
        tls_writer = StreamWriter(ssl_transport, tls_proto, tls_reader, loop)

        return ManagedConnection(tls_reader, tls_writer), protocol

    # -- target connection -------------------------------------------------

    async def _connect_to_target(
        self, host: str, port: int
    ) -> ManagedConnection:
        """Open a TCP connection to the target, optionally through SOCKS5."""
        socks = self._proxy.socks_proxy
        if socks:
            reader, writer = await Socks5Client.connect(
                socks, host, port, self.config.connect_timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.connect_timeout,
            )
        return ManagedConnection(reader, writer)

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _try_error(client: ManagedConnection, msg: bytes) -> None:
        """Best-effort error response — swallows exceptions."""
        try:
            if not client.closed:
                client.writer.write(msg)
        except Exception:
            pass


# ============================================================================
# SessionProxy — one instance per browser session
# ============================================================================


class SessionProxy:
    """A per-session MITM proxy server with response interception.

    Each instance binds a local port and acts as an HTTP/HTTPS proxy for
    a single browser session.  Features include:

    * SOCKS5 proxy chaining (optional, auto-assigned from a pool)
    * Go TLS sidecar for Chrome-fingerprinted connections (optional)
    * Header modification rules (declarative, via :meth:`set_header_rule`)
    * Custom request/response policies (programmatic, via :meth:`set_policy`)
    * Async response interception for specific URLs

    Two extension points
    ~~~~~~~~~~~~~~~~~~~~
    * :meth:`set_header_rule` — flat URL→headers map.  Use this for
      declarative header overrides driven by config or CLI.  Stored
      as state on the active policy; clearing rules doesn't disturb
      a custom policy.
    * :meth:`set_policy` — full programmatic control.  Subclass
      :class:`DefaultPolicy` to inherit hygiene + rule handling.

    Usage::

        pool = SocksProxyPool("proxies.txt")

        proxy = SessionProxy(
            ca_cert="certs/ca.pem",
            ca_key="certs/ca.key",
            socks_pool=pool,
        )
        port = await proxy.start()

        # configure browser: --proxy-server=127.0.0.1:{port}

        proxy.set_header_rule(
            {"https://api.example.com/*"},
            [("X-API-Key", "secret")],
        )

        async with proxy.intercept(["https://api.example.com/data"]) as cap:
            driver.get("https://example.com")
            resp = await cap.get("https://api.example.com/data", timeout=30)
            print(resp.status_code, len(resp.body))

        await proxy.stop()
    """

    def __init__(
        self,
        ca_cert: str,
        ca_key: str,
        socks_pool: Optional[SocksProxyPool] = None,
        host: str = "127.0.0.1",
        port: int = 0,
        config: ProxyConfig = DEFAULT_CONFIG,
        sidecar: Optional[SidecarManager] = None,
        policy: Optional[Policy] = None,
        ):

        self.host = host
        self.port = port
        self.config = config

        self._socks_pool = socks_pool

        if socks_pool:
            self.socks_proxy = socks_pool.assign()
        else:
            self.socks_proxy = None

        self.sidecar: Optional[SidecarManager] = sidecar

        self._tls = TLSInterceptor(ca_cert, ca_key)
        self._handler: Optional[_ProxyHandler] = None
        self._server: Optional[asyncio.Server] = None
        self._interceptors: list[RequestInterceptor] = []
        # threading.Lock is intentional: interceptors may be registered from
        # a different thread than the proxy's event loop.  The critical
        # sections are extremely short (list append/remove) so event loop
        # blocking is negligible.
        self._interceptor_lock = threading.Lock()
        self._active_connections: set[ManagedConnection] = set()
        # Every proxy-owned task (per-connection handler tasks created
        # by start_server, plus anything _spawn'd internally) is
        # registered here so ``stop()`` can await orderly termination.
        # Tasks remove themselves via add_done_callback.
        self._tasks: set[asyncio.Task[None]] = set()
        self._active_h2_states: list[
            tuple[
                h2.connection.H2Connection,  # client h2 conn
                h2.connection.H2Connection,  # target h2 conn
                ManagedConnection,  # client
                ManagedConnection,  # target
            ]
        ] = []

        # The policy controls header transformation and capture lifecycle.
        # Custom implementations must satisfy ``Policy`` 
        # (see DefaultPolicy for the reference impl).
        # DefaultPolicy holds us via weakref.proxy so there is no
        # reference cycle requiring cyclic GC to collect.
        self.policy = policy if policy is not None else DefaultPolicy(self)

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> int:
        """Start listening.  Returns the bound port number."""
        self._handler = _ProxyHandler(self, self._tls, self.config)

        def _on_connect(reader: StreamReader, writer: StreamWriter) -> None:
            # Plain (non-coroutine) callback: we manage the task lifecycle
            # ourselves via _spawn so stop() can await it.  Returning a
            # coroutine here instead would have asyncio create an
            # untracked Task internally — which is exactly the situation
            # the task set is meant to avoid.
            assert self._handler is not None
            self._spawn(
                self._handler.handle_client(reader, writer),
                name="proxy-client",
            )

        self._server = await asyncio.start_server(
            _on_connect,
            self.host,
            self.port,
            reuse_address=True,
        )

        sock = self._server.sockets[0]
        self.port = sock.getsockname()[1]
        logger.info(
            "SessionProxy listening on %s:%d (socks: %s)",
            self.host,
            self.port,
            self.socks_proxy or "direct",
        )
        return self.port

    async def stop(self) -> None:
        """Stop accepting new connections and close all active ones.

        Returns when all proxy-owned tasks have terminated (or the
        per-phase timeouts have elapsed).  Callers can rely on this:
        after ``stop()`` returns, no handler task is observably running,
        so dropping the last user-held reference collects the proxy and
        everything it owned via normal refcounting.
        """
        # Phase 1: stop accepting new connections.
        if self._server:
            if self._server.is_serving():
                self._server.close()
                await self._server.wait_closed()
            self._server = None

        # Phase 2: graceful teardown of in-flight sessions (GOAWAY +
        # force-close).  This will cause most handler tasks to exit
        # their await sites with ConnectionError; they'll fall through
        # their finally blocks and remove themselves from _tasks.
        await self.close_all_handlers()

        # Phase 3: cancel anything still alive and wait for it.  We snapshot
        # the set because done-callbacks mutate it during iteration.
        tasks = [t for t in self._tasks if not t.done()]
        if tasks:
            for t in tasks:
                t.cancel()
            _, pending = await asyncio.wait(tasks, timeout=2.0)
            if pending:
                logger.warning(
                    "SessionProxy.stop: %d task(s) did not terminate: %s",
                    len(pending),
                    [t.get_name() for t in pending],
                )

        # Now safe to drop the handler — no live task references it any
        # more, so the (SessionProxy → _handler → _proxy) cycle resolves
        # by refcount alone.
        self._handler = None
        # Reset the policy back to a fresh DefaultPolicy with no rules,
        # so a stopped-then-restarted SessionProxy behaves like new.
        # Custom policies installed via set_policy are also dropped.
        self.policy = DefaultPolicy(self)
        self.socks_proxy = None
        logger.info("SessionProxy stopped (was :%d)", self.port)

    # -- task management ---------------------------------------------------

    def _spawn(
        self, coro: Coroutine[object, object, None], *, name: Optional[str] = None
    ) -> asyncio.Task[None]:
        """Create and register a proxy-owned task.

        Every task that should be awaited by ``stop()`` must be created
        through this method (or registered via ``_register_task`` if it
        was created elsewhere, e.g. by ``asyncio.start_server``).
        """
        task = asyncio.create_task(coro, name=name)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def _register_task(self, task: asyncio.Task[None]) -> None:
        """Register a task created outside _spawn (idempotent, set semantics)."""
        if task in self._tasks:
            return
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # -- SOCKS proxy management --------------------------------------------

    def rotate_proxy(self) -> Optional[str]:
        """Switch to a different SOCKS proxy from the pool.

        Returns the new proxy address, or ``None`` if no pool is configured.
        """
        if not self._socks_pool:
            logger.warning("No SOCKS pool configured, cannot rotate")
            return None
        new_proxy = self._socks_pool.rotate(self.socks_proxy)
        old = self.socks_proxy
        self.socks_proxy = new_proxy
        logger.info("Rotated SOCKS proxy: %s -> %s", old, new_proxy)
        return new_proxy

    def set_proxy(self, proxy: str) -> Optional[str]:
        self.socks_proxy = proxy
        logger.info("Set SOCKS proxy %s", proxy)
        return self.socks_proxy

    def get_proxy(self) -> Optional[str]:
        """Return the currently assigned SOCKS proxy address."""
        return self.socks_proxy

    # -- header rules ------------------------------------------------------

    def set_header_rule(
        self, urls: set[str], headers: list[tuple[str, str]]
    ) -> None:
        """Set a header-modification rule on the active policy.

        When a request URL matches any pattern in *urls*, the given
        *headers* are merged into the outgoing request headers.

        URL matching is consistent with :meth:`intercept`: patterns
        without ``*`` or ``?`` are exact-string matches, patterns
        containing them use :func:`fnmatch.fnmatch`-style globbing.
        Mix exact and glob in the same call freely::

            proxy.set_header_rule(
                {"https://api.example.com/health",
                 "https://api.example.com/v1/*"},
                [("X-API-Key", "secret")],
            )

        Calling :meth:`set_header_rule` *replaces* any previous rule
        on this policy.  The policy itself is preserved (custom
        subclasses of :class:`DefaultPolicy` continue to apply their
        overrides).

        For request-time logic that can't be expressed as a flat
        URL→headers map (cross-request state, conditional rewrites,
        body inspection), subclass :class:`DefaultPolicy` and use
        :meth:`set_policy` instead.

        Raises:
            TypeError: if the active policy doesn't support header rules
                (i.e. it isn't a :class:`DefaultPolicy` or subclass).
        """
        if not isinstance(self.policy, DefaultPolicy):
            raise TypeError(
                f"set_header_rule requires a DefaultPolicy-compatible "
                f"policy (got {type(self.policy).__name__}). "
                f"Use set_policy(...) directly to install a custom policy."
            )
        self.policy.set_header_rule(urls, headers)

    def clear_header_rule(self) -> None:
        """Remove the active policy's header rule (policy itself stays installed).

        Raises:
            TypeError: if the active policy doesn't support header rules.
        """
        if not isinstance(self.policy, DefaultPolicy):
            raise TypeError(
                f"clear_header_rule requires a DefaultPolicy-compatible "
                f"policy (got {type(self.policy).__name__})."
            )
        self.policy.clear_header_rule()

    # -- interception API --------------------------------------------------

    def intercept(self, urls: list[str]) -> RequestInterceptor:
        """Create a :class:`RequestInterceptor` for the given URL patterns.

        Must be used as an ``async with`` context manager::

            async with proxy.intercept(["https://..."]) as cap:
                resp = await cap.get("https://...", timeout=30)
        """
        return RequestInterceptor(urls, self)

    def _register_interceptor(self, interceptor: RequestInterceptor) -> None:
        with self._interceptor_lock:
            self._interceptors.append(interceptor)

    def _unregister_interceptor(self, interceptor: RequestInterceptor) -> None:
        with self._interceptor_lock:
            try:
                self._interceptors.remove(interceptor)
            except ValueError:
                pass

    def _start_capture(self, url: str) -> Optional[_ResponseCapture]:
        """If any active interceptor wants this URL, return a capture buffer."""
        with self._interceptor_lock:
            for ic in self._interceptors:
                if ic.matches(url) is not None:
                    return _ResponseCapture(url=url)
        return None

    def _deliver_capture(self, capture: _ResponseCapture) -> None:
        """Deliver a completed (or partial) capture to all matching interceptors.

        Safe to call from the proxy's event loop thread.  Actual future
        resolution happens on the caller's loop via ``call_soon_threadsafe``.
        """
        response = capture.finalise()
        with self._interceptor_lock:
            for ic in self._interceptors:
                pattern = ic.matches(response.url)
                if pattern is not None:
                    ic._deliver_threadsafe(pattern, response)

    def _deliver_connect_error(
        self, host: str, port: int, error: Exception
    ) -> None:
        """Notify interceptors that a CONNECT tunnel to *host:port* failed.

        Synthesises a 502 ``InterceptedResponse`` for every registered
        pattern whose URL targets this host, so that callers blocked on
        ``cap.get()`` / ``cap.all()`` are unblocked immediately instead
        of hanging until their timeout.
        """
        scheme = "https" if port == 443 else "http"
        prefix = f"{scheme}://{host}"
        error_body = f"CONNECT tunnel failed: {error}".encode("utf-8")

        with self._interceptor_lock:
            for ic in self._interceptors:
                matched_patterns: list[str] = []

                for pat in ic._exact_urls:
                    if (
                        pat == prefix
                        or pat.startswith(prefix + "/")
                        or pat.startswith(prefix + ":")
                    ):
                        matched_patterns.append(pat)

                for pat in ic._glob_patterns:
                    if (
                        pat.startswith(prefix + "/")
                        or pat.startswith(prefix + ":")
                        or pat == prefix
                    ):
                        matched_patterns.append(pat)

                for pat in matched_patterns:
                    resp = InterceptedResponse(
                        url=pat,
                        status_code=502,
                        headers=[("content-type", "text/plain")],
                        body=error_body,
                        content_type="text/plain",
                        content_encoding="",
                    )
                    ic._deliver_threadsafe(pat, resp)
                    logger.debug(
                        "[CONNECT-ERR] Delivered 502 to interceptor for pattern: %s",
                        pat,
                    )

    # -- connection tracking -----------------------------------------------

    async def close_all_handlers(self) -> None:
        """Forcefully close all active connections with clean HTTP/2 teardown.

        Does **not** stop the server — new connections can still be accepted.
        Useful for rotating SOCKS proxies without a full restart.
        """
        # Send GOAWAY on all tracked HTTP/2 sessions
        h2_states = list(self._active_h2_states)
        self._active_h2_states.clear()

        async def _goaway(
            client_h2: h2.connection.H2Connection,
            target_h2: h2.connection.H2Connection,
            client_io: ManagedConnection,
            target_io: ManagedConnection,
        ) -> None:
            for h2c, io in ((client_h2, client_io), (target_h2, target_io)):
                try:
                    h2c.close_connection(error_code=0)
                    data = h2c.data_to_send()
                    if data and not io.closed:
                        io.writer.write(data)
                        await io.writer.drain()
                except Exception as e:
                    logger.debug("h2 GOAWAY flush failed: %s", e)

        if h2_states:
            await asyncio.wait_for(
                asyncio.gather(*(_goaway(*s) for s in h2_states), return_exceptions=True),
                timeout=5.0,
            )

        # Force-close all remaining TCP connections
        connections = list(self._active_connections)
        self._active_connections.clear()
        if connections:
            logger.info(
                "Force-closing %d active connection(s)", len(connections)
            )
            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        *(conn.close(force=True) for conn in connections),
                        return_exceptions=True,
                    ),
                    timeout=5.0,
                )
            except asyncio.TimeoutError:
                # Some connections didn't close in time — they'll be GC'd
                logger.warning(
                    "Timed out closing connections, %d may linger",
                    sum(1 for c in connections if not c.closed),
                )

    def _track_connection(self, conn: ManagedConnection) -> None:
        self._active_connections.add(conn)

    def _untrack_connection(self, conn: ManagedConnection) -> None:
        self._active_connections.discard(conn)

    def _track_h2_state(self, client_h2: h2.connection.H2Connection, target_h2: h2.connection.H2Connection,
                        client_io: ManagedConnection, target_io: ManagedConnection) -> None:
        self._active_h2_states.append(
            (client_h2, target_h2, client_io, target_io)
        )

    def _untrack_h2_state(self, client_h2: h2.connection.H2Connection, target_h2: h2.connection.H2Connection,
                            client_io: ManagedConnection, target_io: ManagedConnection) -> None:
        try:
            self._active_h2_states.remove(
                (client_h2, target_h2, client_io, target_io)
            )
        except ValueError:
            pass
