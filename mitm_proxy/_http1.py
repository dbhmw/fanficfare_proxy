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
from ._policy import RequestHeaders, ResponseHeaders


def _b(s: bytes | str) -> bytes:
    """Coerce a header name/value to bytes (latin1)."""
    return s if isinstance(s, bytes) else s.encode("latin1")

if TYPE_CHECKING:
    from .session import SessionProxy
    from ._interceptor import _ResponseCapture


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
        headers: list[tuple[bytes, bytes]],
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
        headers: list[tuple[bytes, bytes]],
        body: bytes,
    ) -> tuple[bool, bool]:
        """Apply policy, send one request to *target*, forward the response.

        Returns ``(keep_alive, is_upgrade)`` from the forwarded response.
        Used by both ``handle()`` (per loop iteration) and
        ``handle_with_buffered()`` (one-shot for an already-read request).
        """
        url = f"{scheme}://{target_host}{path}"
        socks = self._proxy.socks_proxy.get_proxy()
        logger.trace("[REQ] %s %s via %s", method, url, socks or "direct")

        # Build the protocol-agnostic request view.  h1 carries method/path
        # in the request line and has no :scheme/:authority on the wire, but
        # we seed all four pseudo-fields so the policy sees a uniform view;
        # we read .method/.path back out below for the request line and
        # ignore .scheme/.authority (h1 expresses authority via Host).
        view = RequestHeaders(
            [(b":method", method.encode("latin1")),
             (b":scheme", scheme.encode("latin1")),
             (b":authority", target_host.encode("latin1")),
             (b":path", path.encode("latin1"))]
            + [(_b(k), _b(v)) for k, v in headers],
        )
        view = self._proxy.policy.transform_request_headers(url, view)

        out_method = view.method or method
        out_path = view.path or path
        regular = view.items()  # regular headers only (pseudo are fields)
        # Synthesize Host if the request didn't carry one (rare; clients
        # always send Host in HTTP/1.1, but defend against malformed input).
        if not any(k.lower() == b"host" for k, _ in regular):
            regular.append((b"Host", target_host.encode("latin1")))

        # Normalise request body framing.  ``_read_request`` always hands us
        # a fully-buffered, de-chunked ``body``, so forwarding the client's
        # original ``Transfer-Encoding: chunked`` header would desync the
        # target — it would try to parse our flat body as chunk-framed and
        # fail (or hang waiting for a terminating 0-size chunk that never
        # comes).  Re-frame to Content-Length: drop any Transfer-Encoding /
        # Content-Length and set a Content-Length matching the body we hold.
        # (Plain Content-Length requests already match ``len(body)``, so we
        # only rewrite when the client used chunked TE — leaving the common
        # case byte-identical.)  A fully streaming, framing-preserving
        # forward would be more fingerprint-faithful for the rare chunked
        # upload, but correctness wins here.
        if any(
            k.lower() == b"transfer-encoding" and b"chunked" in v.lower()
            for k, v in regular
        ):
            regular = [
                (k, v) for k, v in regular
                if k.lower() not in (b"transfer-encoding", b"content-length")
            ]
            regular.append((b"Content-Length", str(len(body)).encode("latin1")))

        await self._send_request(target, out_method, out_path, version, regular, body)
        target.touch()

        keep_alive, is_upgrade = await self._forward_response(
            target, client, url, out_method
        )
        client.touch()
        return keep_alive, is_upgrade

    # -- internal ----------------------------------------------------------

    async def _read_request(
        self, conn: ManagedConnection
    ) -> Optional[tuple[str, str, str, list[tuple[bytes, bytes]], bytes]]:
        """Read a complete HTTP/1.x request (line + headers + body).

        Returns ``(method, path, version, headers, body)`` or ``None`` on
        EOF, timeout, or malformed input.

        Header names/values are returned as **raw bytes** exactly as they
        arrived on the wire — they are *not* decoded.  The request line is
        decoded with latin1, which is a total, lossless byte<->str mapping
        for the ASCII method/path/version tokens (and never raises like a
        utf-8 decode can), so a path carrying non-utf-8 percent-unencoded
        bytes survives intact.  This matches the response path, which also
        preserves wire bytes, and is what keeps the forwarded request
        byte-faithful for fingerprinting.
        """
        try:
            async with asyncio.timeout(self.config.idle_timeout):
                line = await conn.reader.readline()
                if not line:
                    return None
                request_line = line.decode("latin1").strip()
                if not request_line:
                    return None
                parts = request_line.split(" ", 2)
                if len(parts) < 3:
                    return None
                method, path, version = parts

            async with asyncio.timeout(self.config.request_timeout):
                headers: list[tuple[bytes, bytes]] = []
                content_length = -1
                chunked = False
                saw_content_length = False

                while True:
                    line = await conn.reader.readline()
                    if not line or line == b"\r\n":
                        break
                    raw = line.strip()
                    if b":" not in raw:
                        continue
                    hk, hv = raw.split(b":", 1)
                    hk, hv = hk.strip(), hv.strip()
                    headers.append((hk, hv))
                    kl = hk.lower()
                    if kl == b"content-length":
                        saw_content_length = True
                        try:
                            content_length = int(hv)
                        except ValueError:
                            logger.debug(
                                "Malformed Content-Length %r; treating as 0",
                                hv[:64],
                            )
                            content_length = 0
                    elif kl == b"transfer-encoding" and b"chunked" in hv.lower():
                        chunked = True

                # RFC 9112 §6.1 / §6.3.3: a message with both Transfer-
                # Encoding and Content-Length is a framing ambiguity and a
                # classic request-smuggling vector.  Don't guess — reject it.
                if chunked and saw_content_length:
                    logger.warning(
                        "Request has both Transfer-Encoding and Content-Length; "
                        "rejecting (smuggling guard)"
                    )
                    return None

                body = b""
                if chunked:
                    body = await self._read_chunked(conn.reader)
                    if body is None:
                        return None
                elif content_length > 0:
                    body = await conn.reader.readexactly(content_length)

            return method, path, version, headers, body

        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            return None

    async def _read_chunked(self, reader: StreamReader) -> Optional[bytes]:
        """Read a chunked-encoded body, returning the reassembled bytes.

        Returns ``None`` if the framing is malformed (bad chunk size) or the
        accumulated body exceeds ``read_buffer_size``-bounded sanity limit,
        so the caller can abort cleanly instead of letting a ``ValueError``
        escape or buffering an unbounded body into memory.
        """
        body = bytearray()
        # Cap the buffered request body to guard against a malicious or
        # broken client streaming an unbounded chunked body into memory.
        max_body = max(self.config.read_buffer_size * 1024, 64 * 1024 * 1024)
        while True:
            size_line = await reader.readline()
            if not size_line:
                return None  # EOF mid-body
            # Strip chunk extensions (everything after ';') before parsing.
            hex_part = size_line.strip().split(b";", 1)[0]
            try:
                size = int(hex_part, 16)
            except ValueError:
                logger.warning(
                    "Malformed request chunk size %r; aborting", size_line[:64],
                )
                return None
            if size == 0:
                await reader.readline()  # trailing CRLF (and any trailers line)
                break
            if len(body) + size > max_body:
                logger.warning(
                    "Chunked request body exceeded %d bytes; aborting", max_body,
                )
                return None
            body.extend(await reader.readexactly(size))
            await reader.readline()  # chunk-terminating CRLF
        return bytes(body)

    async def _send_request(
        self,
        conn: ManagedConnection,
        method: str,
        path: str,
        version: str,
        headers: list[tuple[bytes, bytes]],
        body: bytes,
    ) -> None:
        """Serialise and send an HTTP/1.x request (header bytes are raw)."""
        conn.writer.write(f"{method} {path} {version}\r\n".encode("latin1"))
        for n, v in headers:
            conn.writer.write(n + b": " + v + b"\r\n")
        conn.writer.write(b"\r\n")
        if body:
            conn.writer.write(body)
        await conn.writer.drain()

    async def _read_status_and_headers(
        self, source: ManagedConnection
    ) -> Optional[
        tuple[bytes, str, int, bool, list[tuple[bytes, bytes]], int, bool, bool]
    ]:
        """Read one response status line + header block from *source*.

        Returns ``(status_line, version_token, status_code, default_ka,
        resp_pairs, content_length, chunked, keep_alive)`` or ``None`` on
        EOF.  Header names/values are kept as raw wire bytes; only the
        framing-control headers are decoded locally (latin1, ASCII-safe)
        for the framing decision.  Body framing is derived from the
        ORIGINAL upstream headers because the proxy must read the body
        exactly as the target framed it, regardless of any policy rewrite.

        Wrapped in ``request_timeout`` — the same budget the original code
        applied to status-line + header reading.
        """
        async with asyncio.timeout(self.config.request_timeout):
            status_line = await source.reader.readline()
            if not status_line:
                return None

            # latin1 is lossless for the status line; we only use the
            # version token and numeric status, never the reason phrase.
            status_parts = status_line.decode("latin1").split(" ", 2)
            version_token = status_parts[0] if status_parts else "HTTP/1.1"
            try:
                status_code = int(status_parts[1]) if len(status_parts) >= 2 else 0
            except ValueError:
                logger.debug("Malformed status line %r", status_line[:80])
                status_code = 0
            default_ka = "http/1.1" in version_token.lower()

            resp_pairs: list[tuple[bytes, bytes]] = []
            content_length = -1
            chunked = False
            keep_alive = default_ka

            while True:
                line = await source.reader.readline()
                if not line or line == b"\r\n":
                    break
                raw = line.strip()
                if b":" not in raw:
                    continue
                hk, hv = raw.split(b":", 1)
                hk, hv = hk.strip(), hv.strip()
                resp_pairs.append((hk, hv))

                kl = hk.lower()
                if kl == b"content-length":
                    try:
                        content_length = int(hv)
                    except ValueError:
                        logger.debug(
                            "Malformed response Content-Length %r; treating as 0",
                            hv[:64],
                        )
                        content_length = 0
                elif kl == b"transfer-encoding" and b"chunked" in hv.lower():
                    chunked = True
                elif kl == b"connection":
                    keep_alive = b"keep-alive" in hv.lower()

        return (
            status_line, version_token, status_code, default_ka,
            resp_pairs, content_length, chunked, keep_alive,
        )

    def _transform_and_write_head(
        self,
        dest: ManagedConnection,
        *,
        status_line: bytes,
        version_token: str,
        status_code: int,
        resp_pairs: list[tuple[bytes, bytes]],
        url: str,
        capture: "Optional[_ResponseCapture]",
    ) -> None:
        """Run the response-header policy hook and write the status line +
        header block to *dest*.

        Shared by interim (1xx) and final responses so the policy sees both
        uniformly (mirroring the h2 path, where 1xx goes through the same
        ``transform_response_headers`` hook).  If the policy left the status
        unchanged we write the original status line byte-for-byte (preserving
        its reason phrase); if it changed, we synthesise a line with an empty
        reason phrase (RFC 9112 §4 permits this) — the proxy never invents a
        reason phrase on a policy's behalf.  When *capture* is provided, the
        original (pre-policy) status/headers are recorded on it, so an
        interceptor sees the unmodified upstream response.
        """
        headers = ResponseHeaders(resp_pairs, status=status_code)
        headers = self._proxy.policy.transform_response_headers(url, headers)
        out_status = headers.status
        forward_pairs = headers.items()  # regular headers only

        if out_status is None or out_status == status_code:
            dest.writer.write(status_line)  # byte-for-byte original
        else:
            dest.writer.write(
                version_token.encode("latin1")
                + b" "
                + str(out_status).encode("latin1")
                + b"\r\n"
            )
        for hk, hv in forward_pairs:
            dest.writer.write(hk + b": " + hv + b"\r\n")
        dest.writer.write(b"\r\n")

        if capture is not None:
            # Record the ORIGINAL wire response (pre-policy): an interceptor
            # should see what the server actually sent, not the browser-facing
            # version produced by transform_response_headers.  resp_pairs and
            # status_code are the untransformed values — ResponseHeaders copies
            # its input on construction, so the transform above mutated its own
            # internal list, never resp_pairs.
            capture.status_code = status_code
            capture.headers = list(resp_pairs)

    async def _forward_response(
        self,
        source: ManagedConnection,
        dest: ManagedConnection,
        url: str,
        method: str,
    ) -> tuple[bool, bool]:
        """Forward a complete HTTP/1.x response from *source* to *dest*.

        Returns ``(keep_alive, is_upgrade)``.  *method* is the request
        method as sent to the target; it's needed because a response to a
        ``HEAD`` request carries no message body even when it advertises a
        ``Content-Length`` (RFC 9112 §6.3).

        Status and headers are buffered (not streamed line-by-line) so the
        policy's ``transform_response_headers`` hook can rewrite the block
        as a unit before anything reaches the browser, exactly as the
        request side does.  Body framing is computed from the *original*
        upstream headers and is unaffected by any rewrite.

        Interim responses
        ~~~~~~~~~~~~~~~~~~
        A server may emit zero or more 1xx interim responses (100 Continue,
        103 Early Hints, …) before the final one, on the same connection.
        Each is forwarded to the browser (through the policy) and we keep
        reading until the final (>= 200) response.  Without this the proxy
        would mistake the interim for the final response and then try to
        read a fresh *request* from the browser while the server is still
        sending the real response — desyncing the keep-alive connection.

        No-body responses
        ~~~~~~~~~~~~~~~~~~
        Responses to ``HEAD`` and all ``204`` / ``304`` responses have no
        message body regardless of framing headers.  The framing headers
        are still forwarded (the browser applies the same rule), but the
        proxy must NOT attempt to read a body — doing so blocks forever on
        bytes that never arrive (the bug that stalled ``HEAD`` and
        ``304``-with-Content-Length until the connection was torn down).

        If the response URL matches an active ``RequestInterceptor``, the
        body is also buffered into a ``_ResponseCapture`` and delivered on
        completion; the capture reflects the original (pre-policy) headers.

        Handles three body framing modes:
        1. ``Transfer-Encoding: chunked``
        2. ``Content-Length: N``
        3. **Close-delimited** — read until EOF (no length, not chunked)
        """
        capture = self._proxy.policy.open_capture(url)
        delivered = False
        req_method = method.upper()
        try:
            # -- read past any interim 1xx responses, forwarding each --
            while True:
                parsed = await self._read_status_and_headers(source)
                if parsed is None:
                    return False, False
                (
                    status_line, version_token, status_code, default_ka,
                    resp_pairs, content_length, chunked, keep_alive,
                ) = parsed

                # Record the latest status so a mid-body death can still
                # deliver a partial capture for the final response.
                if capture:
                    capture.status_code = status_code

                # 101 is terminal (handled as an upgrade below); other 1xx
                # are interim — forward and keep reading.
                if 100 <= status_code < 200 and status_code != 101:
                    self._transform_and_write_head(
                        dest,
                        status_line=status_line,
                        version_token=version_token,
                        status_code=status_code,
                        resp_pairs=resp_pairs,
                        url=url,
                        capture=None,  # interim — never the captured response
                    )
                    await dest.writer.drain()
                    continue
                break  # final response (or 101 upgrade)

            is_upgrade = status_code == 101

            # -- write final status line + headers (policy transform) --
            self._transform_and_write_head(
                dest,
                status_line=status_line,
                version_token=version_token,
                status_code=status_code,
                resp_pairs=resp_pairs,
                url=url,
                capture=capture,
            )

            # -- 101 Switching Protocols (WebSocket etc.) --
            if is_upgrade:
                await dest.writer.drain()
                if capture:
                    self._proxy.policy.deliver_capture(capture)
                    delivered = True
                return False, True

            # -- no-body responses (RFC 9112 §6.3): HEAD, 204, 304 --
            # (1xx was already consumed above.)  Forward the head, do NOT
            # read a body, and let the connection stay keep-alive.
            if req_method == "HEAD" or status_code in (204, 304):
                await dest.writer.drain()
                if capture:
                    self._proxy.policy.deliver_capture(capture)
                    delivered = True
                return keep_alive, False

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
