"""HTTP/1.1 bidirectional forwarding handler.

Reads requests from the browser, applies policy, forwards them to the
target, then streams responses back.  Handles keep-alive connection
reuse, chunked transfer encoding, and ``101 Switching Protocols``
upgrades (WebSocket, HTTP/2 upgrade — though browsers don't use h2
upgrade in practice; they use ALPN over TLS).

Two entry points:

* ``handle()`` — full keep-alive loop, used after CONNECT tunnel
  setup (HTTPS) when no request bytes have been read yet.
* ``handle_with_buffered()`` — forwards one already-read request
  (passed as raw fields), then enters the keep-alive loop.  Used
  for plain-HTTP requests where the proxy handler had to peek at
  the first request to determine the target host.

Both share ``_forward_one_request`` which does the per-request work
(policy, send, forward response).
"""

from __future__ import annotations

import asyncio
import traceback
from asyncio import StreamReader
from typing import TYPE_CHECKING, Optional

from ._common import logger, ProxyConfig, DEFAULT_CONFIG
from ._io import ManagedConnection

if TYPE_CHECKING:
    from .session import SessionProxy


class Http1Handler:
    """Forwards HTTP/1.x traffic between the browser and target.

    Handles keep-alive connection reuse, chunked transfer encoding,
    WebSocket upgrades (101 Switching Protocols), and response capture
    for the interception API.
    """

    __slots__ = ("config", "_proxy")

    def __init__(self, proxy: SessionProxy, config: ProxyConfig = DEFAULT_CONFIG):
        # Strong reference.  See _ProxyHandler.__init__ in session.py for
        # the lifetime contract: SessionProxy.stop() awaits every handler
        # task (registered in SessionProxy._tasks) before clearing
        # ``self._handler``, so handler code can rely on ``self._proxy``
        # being alive for the entire duration of its task.
        self._proxy = proxy
        self.config = config

    async def handle(
        self,
        client: ManagedConnection,
        target: ManagedConnection,
        target_host: str,
        is_https: bool = True,
    ) -> None:
        """Enter the HTTP/1.x keep-alive loop.

        Reads requests from *client*, forwards them to *target*, then
        streams responses back.  Loops until either side closes the
        connection, the idle timeout fires, or an upgrade occurs.
        """
        scheme = "https" if is_https else "http"
        request_count = 0

        try:
            while not client.closed and not target.closed:
                request = await self._read_request(client)
                if not request:
                    break

                method, path, version, headers, body = request
                request_count += 1
                client.touch()

                keep_alive, is_upgrade = await self._forward_one_request(
                    client, target, target_host, scheme,
                    method, path, version, headers, body,
                )

                if is_upgrade:
                    await self._bidirectional_pipe(client, target)
                    break
                if not keep_alive:
                    break

        except asyncio.TimeoutError:
            logger.debug(
                "[HTTP/1.1 %s] Timeout after %d reqs", target_host, request_count
            )
        except (ConnectionResetError, BrokenPipeError) as e:
            logger.debug("[HTTP/1.1 %s] Connection closed: %s", target_host, e)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(
                "[HTTP/1.1 %s] Error: %s\n%s",
                target_host,
                e,
                traceback.format_exc(),
            )

    async def handle_with_buffered(
        self,
        client: ManagedConnection,
        target: ManagedConnection,
        target_host: str,
        method: str,
        path: str,
        version: str,
        headers: list[tuple[str, str]],
        body: bytes,
        is_https: bool = True,
    ) -> None:
        """Forward a pre-read first request, then enter the keep-alive loop.

        Used when the proxy handler has already consumed the first
        request line + headers (e.g. to determine the target host for a
        plain-HTTP request).
        """
        scheme = "https" if is_https else "http"

        try:
            keep_alive, is_upgrade = await self._forward_one_request(
                client, target, target_host, scheme,
                method, path, version, headers, body,
            )
            if is_upgrade:
                await self._bidirectional_pipe(client, target)
                return
            if keep_alive:
                await self.handle(client, target, target_host, is_https)

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(
                "[HTTP/1.1 %s] Buffered handler error: %s", target_host, e
            )

    async def _forward_one_request(
        self,
        client: ManagedConnection,
        target: ManagedConnection,
        target_host: str,
        scheme: str,
        method: str,
        path: str,
        version: str,
        headers: list[tuple[str, str]],
        body: bytes,
    ) -> tuple[bool, bool]:
        """Apply policy, send one request to *target*, forward the response.

        Returns ``(keep_alive, is_upgrade)`` from the forwarded response.
        Used by both ``handle()`` (per loop iteration) and
        ``handle_with_buffered()`` (one-shot for an already-read request).
        """
        url = f"{scheme}://{target_host}{path}"
        socks = self._proxy.socks_proxy
        logger.trace("[REQ] %s %s via %s", method, url, socks or "direct")

        modified = self._proxy.policy.transform_request_headers(
            url, headers, is_h2=False
        )
        # Synthesize Host if the request didn't carry one (rare; clients
        # always send Host in HTTP/1.1, but defend against malformed input).
        if not any(k.lower() == "host" for k, _ in modified):
            modified.append(("Host", target_host))

        await self._send_request(target, method, path, version, modified, body)
        target.touch()

        keep_alive, is_upgrade = await self._forward_response(target, client, url)
        client.touch()
        return keep_alive, is_upgrade

    # -- internal ----------------------------------------------------------

    async def _read_request(
        self, conn: ManagedConnection
    ) -> Optional[tuple[str, str, str, list[tuple[str, str]], bytes]]:
        """Read a complete HTTP/1.x request (line + headers + body).

        Returns ``None`` on EOF, timeout, or malformed input.
        """
        try:
            async with asyncio.timeout(self.config.idle_timeout):
                line = await conn.reader.readline()
                if not line:
                    return None
                request_line = line.decode("utf-8", errors="replace").strip()
                if not request_line:
                    return None
                parts = request_line.split(" ", 2)
                if len(parts) < 3:
                    return None
                method, path, version = parts

            async with asyncio.timeout(self.config.request_timeout):
                headers: list[tuple[str, str]] = []
                content_length = 0
                chunked = False

                while True:
                    line = await conn.reader.readline()
                    if not line or line == b"\r\n":
                        break
                    decoded = line.decode("utf-8", errors="replace").strip()
                    if ":" in decoded:
                        k, v = decoded.split(":", 1)
                        k, v = k.strip(), v.strip()
                        headers.append((k, v))
                        kl = k.lower()
                        if kl == "content-length":
                            try:
                                content_length = int(v)
                            except ValueError:
                                logger.debug(
                                    "Malformed Content-Length %r; treating as 0", v,
                                )
                                content_length = 0
                        elif (
                            kl == "transfer-encoding" and "chunked" in v.lower()
                        ):
                            chunked = True

                body = b""
                if chunked:
                    body = await self._read_chunked(conn.reader)
                elif content_length > 0:
                    body = await conn.reader.readexactly(content_length)

            return method, path, version, headers, body

        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            return None

    async def _read_chunked(self, reader: StreamReader) -> bytes:
        """Read a chunked-encoded body, returning the reassembled bytes."""
        body = bytearray()
        while True:
            size_line = await reader.readline()
            size = int(size_line.strip(), 16)
            if size == 0:
                await reader.readline()  # trailing CRLF
                break
            body.extend(await reader.readexactly(size))
            await reader.readline()  # chunk-terminating CRLF
        return bytes(body)

    async def _send_request(
        self,
        conn: ManagedConnection,
        method: str,
        path: str,
        version: str,
        headers: list[tuple[str, str]],
        body: bytes,
    ) -> None:
        """Serialise and send an HTTP/1.x request."""
        conn.writer.write(f"{method} {path} {version}\r\n".encode())
        for n, v in headers:
            conn.writer.write(f"{n}: {v}\r\n".encode())
        conn.writer.write(b"\r\n")
        if body:
            conn.writer.write(body)
        await conn.writer.drain()

    async def _forward_response(
        self,
        source: ManagedConnection,
        dest: ManagedConnection,
        url: str,
    ) -> tuple[bool, bool]:
        """Forward a complete HTTP/1.x response from *source* to *dest*.

        Returns ``(keep_alive, is_upgrade)``.

        If the response URL matches an active ``RequestInterceptor``,
        the body is also buffered into a ``_ResponseCapture`` and
        delivered on completion.

        ``Alt-Svc`` response headers are filtered to remove HTTP/3
        (QUIC) entries while preserving h2 alternatives, preventing the
        browser from upgrading to a protocol we cannot intercept.

        Handles three body framing modes:
        1. ``Transfer-Encoding: chunked``
        2. ``Content-Length: N``
        3. **Close-delimited** — read until EOF (no length, not chunked)
        """
        capture = self._proxy.policy.open_capture(url)
        delivered = False
        try:
            async with asyncio.timeout(self.config.request_timeout):
                # -- status line --
                status_line = await source.reader.readline()
                if not status_line:
                    return False, False
                dest.writer.write(status_line)

                status_parts = status_line.decode("utf-8", errors="replace").split(
                    " ", 2
                )
                try:
                    status_code = (
                        int(status_parts[1]) if len(status_parts) >= 2 else 0
                    )
                except ValueError:
                    logger.debug(
                        "Malformed status line %r", status_line[:80],
                    )
                    status_code = 0
                version = status_parts[0].lower() if status_parts else ""
                default_ka = "http/1.1" in version

                if capture:
                    capture.status_code = status_code

            # -- headers --
            content_length = -1
            chunked = False
            keep_alive = default_ka
            is_upgrade = status_code == 101

            while True:
                line = await source.reader.readline()
                if line == b"\r\n":
                    dest.writer.write(line)
                    break

                header_raw = line.decode("utf-8", errors="replace").strip()
                header_lower = header_raw.lower()

                # -- Policy-driven header transformation --
                # The default policy strips h3 entries from Alt-Svc.
                # A custom policy can drop or rewrite any header.
                policy_result = self._proxy.policy.filter_response_header_line(
                    header_raw
                )
                if policy_result is None:
                    # Policy dropped the header entirely
                    continue
                if policy_result != header_raw:
                    # Policy rewrote the header — re-encode the line
                    line = f"{policy_result}\r\n".encode()
                    header_raw = policy_result
                    # header_lower is intentionally NOT recomputed: it's
                    # only used below for the well-known framing headers
                    # (Content-Length, Transfer-Encoding, Connection),
                    # which the policy must never rewrite — doing so would
                    # desync request/response framing.

                dest.writer.write(line)

                if capture and ":" in header_raw:
                    hk, hv = header_raw.split(":", 1)
                    capture.headers.append((hk.strip(), hv.strip()))

                if header_lower.startswith("content-length:"):
                    try:
                        content_length = int(header_lower.split(":", 1)[1].strip())
                    except ValueError:
                        logger.debug(
                            "Malformed response Content-Length %r; treating as 0",
                            header_lower[:64],
                        )
                        content_length = 0
                elif header_lower.startswith("transfer-encoding:") and "chunked" in header_lower:
                    chunked = True
                elif header_lower.startswith("connection:"):
                    keep_alive = "keep-alive" in header_lower

            # -- 101 Switching Protocols (WebSocket etc.) --
            if is_upgrade:
                await dest.writer.drain()
                if capture:
                    self._proxy.policy.deliver_capture(capture)
                    delivered = True
                return False, True

            # -- body: chunked transfer encoding --
            if chunked:
                while True:
                    size_line = await source.reader.readline()
                    dest.writer.write(size_line)
                    try:
                        # Strip chunk extensions (after ';') before parsing
                        hex_part = size_line.strip().split(b";", 1)[0]
                        size = int(hex_part, 16)
                    except (ValueError, IndexError):
                        logger.warning(
                            "Malformed response chunk size %r; closing connection",
                            size_line[:64],
                        )
                        # Don't keep this connection alive — framing is corrupt
                        return False, False
                    if size == 0:
                        trailer = await source.reader.readline()
                        dest.writer.write(trailer)
                        break
                    chunk = await source.reader.readexactly(size)
                    dest.writer.write(chunk)
                    if capture:
                        capture.body.extend(chunk)
                    crlf = await source.reader.readline()
                    dest.writer.write(crlf)

            # -- body: fixed Content-Length --
            elif content_length > 0:
                remaining = content_length
                while remaining > 0:
                    chunk = await source.reader.read(
                        min(remaining, self.config.read_buffer_size)
                    )
                    if not chunk:
                        break
                    dest.writer.write(chunk)
                    if capture:
                        capture.body.extend(chunk)
                    remaining -= len(chunk)

            # -- body: close-delimited (no length, not chunked) --
            # FIX: Previously the body was silently dropped for responses
            # that signal end-of-body by closing the connection (HTTP/1.0
            # default, or HTTP/1.1 without Content-Length or chunked TE).
            elif content_length == -1 and not keep_alive:
                while True:
                    chunk = await source.reader.read(
                        self.config.read_buffer_size
                    )
                    if not chunk:
                        break
                    dest.writer.write(chunk)
                    if capture:
                        capture.body.extend(chunk)

            await dest.writer.drain()

            if capture:
                self._proxy.policy.deliver_capture(capture)
                delivered = True

            return keep_alive, False
        finally:
            # If we exited via exception (or any early return path) and the
            # capture was created but never delivered, deliver whatever we
            # have so the interceptor isn't left hanging until its timeout.
            # We only deliver if status_code is set (i.e., we got at least a
            # status line) — empty captures don't help anyone.
            if capture and not delivered and capture.status_code:
                try:
                    self._proxy.policy.deliver_capture(capture)
                except Exception as e:
                    logger.trace("partial-capture delivery failed: %s", e)

    async def _bidirectional_pipe(
        self, client: ManagedConnection, target: ManagedConnection
    ) -> None:
        """Full-duplex byte pipe for upgraded connections (WebSocket, etc.)."""

        async def pipe(src: ManagedConnection, dst: ManagedConnection) -> None:
            try:
                while not src.closed and not dst.closed:
                    try:
                        async with asyncio.timeout(self.config.idle_timeout):
                            data = await src.reader.read(
                                self.config.read_buffer_size
                            )
                    except asyncio.TimeoutError:
                        break
                    if not data:
                        break
                    src.touch()
                    dst.writer.write(data)
                    await dst.writer.drain()
                    dst.touch()
            except asyncio.CancelledError:
                raise
            except (ConnectionResetError, BrokenPipeError):
                pass
            except Exception as e:
                logger.trace("pipe worker error: %s", e)

        t1 = asyncio.create_task(pipe(client, target))
        t2 = asyncio.create_task(pipe(target, client))
        try:
            _, pending = await asyncio.wait(
                [t1, t2], return_when=asyncio.FIRST_COMPLETED
            )
            for t in pending:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass
        except asyncio.CancelledError:
            t1.cancel()
            t2.cancel()
            raise
