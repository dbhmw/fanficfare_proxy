from __future__ import annotations
import uvloop
uvloop.install()
import asyncio
import fnmatch
import gzip
import logging
import random
import ssl
import struct
import threading
import time
import traceback
import zlib
from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Optional
from urllib.parse import urlparse

try:
    import brotli as _brotli

    def _decompress_brotli(data: bytes) -> bytes:
        return _brotli.decompress(data)
except ImportError:
    def _decompress_brotli(data: bytes) -> bytes:
        raise RuntimeError(
            "Brotli-compressed response received but 'brotli' package is not installed. "
            "Install it with: pip install brotli"
        )


import h2.config
import h2.connection
import h2.events
import h2.exceptions


# ============================================================================
# Configuration
# ============================================================================


@dataclass(frozen=True)
class ProxyConfig:
    """Proxy configuration with sensible defaults"""

    max_streams_per_connection: int = 100

    # Timeouts (seconds)
    connect_timeout: float = 120.0
    idle_timeout: float = 70.0
    request_timeout: float = 120.0
    stream_timeout: float = 120.0

    # Buffer sizes
    read_buffer_size: int = 65536


DEFAULT_CONFIG = ProxyConfig()


# ============================================================================
# Data Classes
# ============================================================================


@dataclass(frozen=True)
class Rule:
    """Intercept rule for modifying outgoing request headers"""

    urls: frozenset[str]
    headers: tuple[tuple[str, str], ...]

    @classmethod
    def create(cls, urls: set[str], headers: list[tuple[str, str]]) -> Rule:
        return cls(frozenset(urls), tuple((k, v) for k, v in headers))


class Protocol(Enum):
    HTTP1 = "http/1.1"
    HTTP2 = "h2"


@dataclass
class InterceptedResponse:
    """A captured HTTP response with auto-decompressed body."""

    url: str
    status_code: int
    headers: list[tuple[str, str]]
    body: bytes
    content_type: str
    content_encoding: str
    timestamp: float = field(default_factory=time.monotonic)


def _decompress_body(data: bytes, encoding: str) -> bytes:
    """Decompress response body based on Content-Encoding header."""
    if not data or not encoding:
        return data

    encoding = encoding.lower().strip()

    try:
        if encoding == "gzip" or encoding == "x-gzip":
            return gzip.decompress(data)
        elif encoding == "deflate":
            # Try raw deflate first, fall back to zlib-wrapped
            try:
                return zlib.decompress(data, -zlib.MAX_WBITS)
            except zlib.error:
                return zlib.decompress(data)
        elif encoding == "br":
            return _decompress_brotli(data)
        elif encoding == "zstd":
            try:
                import zstandard
                return zstandard.ZstdDecompressor().decompress(data)
            except ImportError:
                raise RuntimeError(
                    "Zstandard-compressed response received but 'zstandard' package "
                    "is not installed. Install it with: pip install zstandard"
                )
        elif encoding == "identity":
            return data
        else:
            logger.warning("Unknown Content-Encoding: %s, returning raw body", encoding)
            return data
    except Exception as e:
        logger.warning("Failed to decompress %s response (%s), returning raw body", encoding, e)
        return data


@dataclass
class _ResponseCapture:
    """Internal buffer for response capture in progress"""

    url: str
    status_code: int = 0
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytearray = field(default_factory=bytearray)

    def finalise(self) -> InterceptedResponse:
        content_type = ""
        content_encoding = ""
        for k, v in self.headers:
            kl = k.lower()
            if kl == "content-type":
                content_type = v
            elif kl == "content-encoding":
                content_encoding = v

        raw = bytes(self.body)
        body = _decompress_body(raw, content_encoding)

        return InterceptedResponse(
            url=self.url,
            status_code=self.status_code,
            headers=list(self.headers),
            body=body,
            content_type=content_type,
            content_encoding=content_encoding,
        )


# ============================================================================
# Request Interception API
# ============================================================================


class RequestInterceptor:
    """Captures HTTP responses flowing through the proxy for registered URLs.

    Thread-safe: the ``async with`` block runs on the caller's event loop,
    while the proxy delivers responses from its own loop/thread.  Delivery
    crosses threads via ``loop.call_soon_threadsafe``.

    Supports three consumption patterns:

        # 1. Wait for a specific URL
        async with proxy.intercept(["https://a.com/x", "https://b.com/y"]) as cap:
            driver.get(page)
            resp = await cap.get("https://a.com/x", timeout=30)

        # 2. Wait for all registered URLs
        async with proxy.intercept(urls) as cap:
            driver.get(page)
            responses = await cap.all(timeout=30)

        # 3. Async-iterate as responses arrive
        async with proxy.intercept(urls) as cap:
            driver.get(page)
            async for resp in cap:
                print(resp.url, resp.status_code)

    URL matching:
        - Exact string match by default.
        - Patterns containing ``*`` or ``?`` use fnmatch-style globbing,
          e.g. ``"https://api.example.com/v1/*"`` matches any sub-path.
    """

    __slots__ = (
        "_patterns",
        "_exact_urls",
        "_glob_patterns",
        "_futures",
        "_queue",
        "_remaining",
        "_proxy",
        "_caller_loop",
        "_entered",
    )

    def __init__(self, patterns: list[str], proxy: SessionProxy) -> None:
        self._patterns = list(patterns)
        self._proxy = proxy
        self._entered = False
        self._caller_loop: Optional[asyncio.AbstractEventLoop] = None

        # Split into exact and glob patterns for fast matching
        self._exact_urls: set[str] = set()
        self._glob_patterns: list[str] = []
        for p in patterns:
            if "*" in p or "?" in p:
                self._glob_patterns.append(p)
            else:
                self._exact_urls.add(p)

        self._futures: dict[str, asyncio.Future[InterceptedResponse]] = {}
        self._queue: asyncio.Queue[InterceptedResponse] = asyncio.Queue()
        self._remaining = len(patterns)

    # -- matching ----------------------------------------------------------

    def matches(self, url: str) -> Optional[str]:
        """Return the pattern that matched *url*, or None."""
        if url in self._exact_urls:
            return url
        for pat in self._glob_patterns:
            if fnmatch.fnmatch(url, pat):
                return pat
        return None

    # -- delivery (called from proxy thread) -------------------------------

    def _deliver_threadsafe(self, pattern: str, response: InterceptedResponse) -> None:
        """Deliver a response from the proxy thread to the caller's loop.

        Called synchronously from the proxy's event loop thread.  Uses
        ``call_soon_threadsafe`` to resolve the future and enqueue the
        response on the caller's loop.
        """
        loop = self._caller_loop
        if loop is None or loop.is_closed():
            return

        fut = self._futures.get(pattern)

        def _resolve() -> None:
            if fut and not fut.done():
                fut.set_result(response)
            self._queue.put_nowait(response)

        loop.call_soon_threadsafe(_resolve)

    # -- public consumption API --------------------------------------------

    async def get(self, url_or_pattern: str, *, timeout: float = 30.0) -> InterceptedResponse:
        """Wait for a response matching *url_or_pattern*."""
        if url_or_pattern not in self._futures:
            raise KeyError(
                f"{url_or_pattern!r} was not registered with this interceptor"
            )
        return await asyncio.wait_for(self._futures[url_or_pattern], timeout)

    async def all(self, *, timeout: float = 60.0) -> list[InterceptedResponse]:
        """Wait until every registered pattern has been seen at least once."""
        return await asyncio.wait_for(
            asyncio.gather(*self._futures.values()), timeout
        )

    async def __aiter__(self) -> AsyncIterator[InterceptedResponse]:
        """Yield responses as they arrive; stops when all patterns fulfilled."""
        delivered = 0
        while delivered < self._remaining:
            resp = await self._queue.get()
            delivered += 1
            yield resp

    # -- context manager ---------------------------------------------------

    async def __aenter__(self) -> RequestInterceptor:
        self._caller_loop = asyncio.get_running_loop()
        for p in self._patterns:
            self._futures[p] = self._caller_loop.create_future()
        self._proxy._register_interceptor(self)
        self._entered = True
        return self

    async def __aexit__(self, *exc: object) -> None:
        self._proxy._unregister_interceptor(self)
        for fut in self._futures.values():
            if not fut.done():
                fut.cancel()
        self._entered = False
        self._caller_loop = None


# ============================================================================
# Header Modification
# ============================================================================


class HeaderModifier:
    """Shared header modification logic"""

    STRIP_HEADERS: frozenset[str] = frozenset(
        {"rtt", "ect", "downlink", "device-memory", "viewport-width", "dpr"}
    )

    STRIP_PREFIXES: tuple[str, ...] = ("sec-ch-", "proxy-")

    FORBIDDEN_H2_HEADERS: frozenset[str] = frozenset(
        {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"}
    )

    @classmethod
    def should_strip(cls, name: str, value: str = "", is_h2: bool = False) -> bool:
        lower = name.lower()
        if lower in cls.STRIP_HEADERS:
            return True
        if is_h2 and lower in cls.FORBIDDEN_H2_HEADERS:
            return True
        if lower == "te" and value.lower() != "trailers":
            return True
        return any(lower.startswith(p) for p in cls.STRIP_PREFIXES)

    @classmethod
    def apply_rules(
        cls,
        headers: list[tuple[str, str]],
        url: str,
        rule: Optional[Rule],
        is_h2: bool = True,
    ) -> list[tuple[str, str]]:
        pseudo: list[tuple[str, str]] = []
        regular: list[tuple[str, str]] = []

        for k, v in headers:
            lower = k.lower()
            if cls.should_strip(lower, v, is_h2):
                continue
            if lower.startswith(":"):
                pseudo.append((lower, v))
            else:
                regular.append((lower, v))

        if rule and url in rule.urls:
            logger.debug("[Intercept] Applying header rules for: %s", url)
            hmap = dict(regular)
            for name, value in rule.headers:
                nl = name.lower()
                if nl.startswith(":"):
                    continue
                if is_h2 and nl in cls.FORBIDDEN_H2_HEADERS:
                    continue
                if nl in cls.STRIP_HEADERS:
                    continue
                hmap[nl] = value
            regular = list(hmap.items())

        return pseudo + regular


# ============================================================================
# Connection Wrapper
# ============================================================================


class ManagedConnection:
    __slots__ = ("reader", "writer", "last_activity", "_closed")

    def __init__(self, reader: StreamReader, writer: StreamWriter):
        self.reader = reader
        self.writer = writer
        self.last_activity = time.monotonic()
        self._closed = False

    def touch(self) -> None:
        self.last_activity = time.monotonic()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if not self.writer.is_closing():
                self.writer.close()
                await asyncio.wait_for(self.writer.wait_closed(), timeout=2.0)
        except Exception as e:
            logger.trace(e)

    @property
    def closed(self) -> bool:
        return self._closed or self.writer.is_closing()


# ============================================================================
# SOCKS5 Client
# ============================================================================


class Socks5Client:
    @staticmethod
    async def connect(
        proxy: str, target_host: str, target_port: int, timeout: float = 30.0
    ) -> tuple[StreamReader, StreamWriter]:
        proxy_host, proxy_port = proxy, 1080
        if ":" in proxy:
            proxy_host, port_str = proxy.rsplit(":", 1)
            proxy_port = int(port_str)
        if "@" in proxy_host:
            proxy_host = proxy_host.split("@")[-1]

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port), timeout=timeout
        )

        try:
            async with asyncio.timeout(timeout):
                writer.write(b"\x05\x01\x00")
                await writer.drain()

                resp = await reader.readexactly(2)
                if resp[0] != 0x05 or resp[1] == 0xFF:
                    raise ConnectionError("SOCKS5 handshake failed")

                domain = target_host.encode("utf-8")
                request = (
                    b"\x05\x01\x00\x03"
                    + bytes([len(domain)])
                    + domain
                    + struct.pack(">H", target_port)
                )
                writer.write(request)
                await writer.drain()

                resp = await reader.readexactly(4)
                if resp[1] != 0x00:
                    errors = {
                        1: "General failure",
                        2: "Not allowed",
                        3: "Network unreachable",
                        4: "Host unreachable",
                        5: "Connection refused",
                        6: "TTL expired",
                    }
                    raise ConnectionError(
                        f"SOCKS5: {errors.get(resp[1], 'Unknown error')}"
                    )

                atyp = resp[3]
                if atyp == 0x01:
                    await reader.readexactly(6)
                elif atyp == 0x03:
                    length = (await reader.readexactly(1))[0]
                    await reader.readexactly(length + 2)
                elif atyp == 0x04:
                    await reader.readexactly(18)

            return reader, writer
        except Exception:
            writer.close()
            await writer.wait_closed()
            raise


class SocksProxyPool:
    """Shared SOCKS5 proxy pool — loaded once, used by many SessionProxy instances."""

    __slots__ = ("proxy_file", "proxies")

    def __init__(self, proxy_file: str):
        self.proxy_file = proxy_file
        self.proxies: tuple[str, ...] = ()
        self._load_proxies()

    def _load_proxies(self) -> None:
        try:
            with open(self.proxy_file, "r", encoding="utf-8") as f:
                self.proxies = tuple(line.strip() for line in f if line.strip())
            logger.info("Loaded %d SOCKS5 proxies from %s", len(self.proxies), self.proxy_file)
        except FileNotFoundError:
            logger.warning("SOCKS5 proxy file not found: %s", self.proxy_file)
        except Exception as e:
            logger.error("Error loading SOCKS5 proxies: %s", e)

    def assign(self) -> Optional[str]:
        """Pick a random proxy from the pool."""
        if not self.proxies:
            return None
        return random.choice(self.proxies)

    def rotate(self, current: Optional[str]) -> Optional[str]:
        """Pick a different proxy than *current*. Falls back to any if only one exists."""
        if not self.proxies:
            return None
        if current and len(self.proxies) > 1:
            available = [p for p in self.proxies if p != current]
            return random.choice(available)
        return random.choice(self.proxies)

    def reload(self) -> None:
        """Re-read the proxy file from disk."""
        self._load_proxies()

    def __len__(self) -> int:
        return len(self.proxies)


# ============================================================================
# TLS Interceptor
# ============================================================================


class TLSInterceptor:
    __slots__ = ("ca_cert_path", "ca_key_path", "_server_ctx_cache")

    def __init__(self, ca_cert_path: str, ca_key_path: str):
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self._server_ctx_cache: dict[tuple[str, ...], ssl.SSLContext] = {}

    def get_server_context(self, alpn: tuple[str, ...]) -> ssl.SSLContext:
        if alpn not in self._server_ctx_cache:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.ca_cert_path, self.ca_key_path)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if alpn:
                ctx.set_alpn_protocols(list(alpn))
            self._server_ctx_cache[alpn] = ctx
        return self._server_ctx_cache[alpn]

    def create_client_context(self, alpn: list[str] | None = None) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if alpn:
            ctx.set_alpn_protocols(alpn)
        return ctx


# ============================================================================
# HTTP/2 Stream Tracking
# ============================================================================


class Http2Stream:
    __slots__ = ("client_id", "target_id", "authority", "path", "scheme", "created_at", "url")

    def __init__(
        self,
        client_id: int,
        target_id: int,
        authority: str,
        path: str,
        scheme: str,
        created_at: float,
    ):
        self.client_id = client_id
        self.target_id = target_id
        self.authority = authority
        self.path = path
        self.scheme = scheme
        self.created_at = created_at
        self.url = f"{scheme}://{authority}{path}"


# ============================================================================
# Buffered Request Types
# ============================================================================


@dataclass
class BufferedH1Request:
    method: str
    path: str
    version: str
    headers: list[tuple[str, str]]
    body: bytes


class _TargetGoaway(Exception):
    """Raised when the target server sends an HTTP/2 GOAWAY frame."""

    __slots__ = ("last_stream_id", "error_code", "additional_data")

    def __init__(self, last_stream_id: int | None, error_code: int, additional_data: bytes):
        self.last_stream_id = last_stream_id
        self.error_code = error_code
        self.additional_data = additional_data
        super().__init__(f"Target GOAWAY (last_stream={last_stream_id}, error={error_code})")


class _ClientGoaway(Exception):
    """Raised when the client sends an HTTP/2 GOAWAY frame."""

    __slots__ = ("last_stream_id", "error_code", "additional_data")

    def __init__(self, last_stream_id: int | None, error_code: int, additional_data: bytes):
        self.last_stream_id = last_stream_id
        self.error_code = error_code
        self.additional_data = additional_data
        super().__init__(f"Client GOAWAY (last_stream={last_stream_id}, error={error_code})")


# ============================================================================
# HTTP/1.1 Handler
# ============================================================================


class Http1Handler:
    __slots__ = ("config", "_proxy")

    def __init__(self, proxy: SessionProxy, config: ProxyConfig = DEFAULT_CONFIG):
        self._proxy = proxy
        self.config = config

    async def handle(
        self,
        client: ManagedConnection,
        target: ManagedConnection,
        target_host: str,
        is_https: bool = True,
    ) -> None:
        """Handle HTTP/1.1 keep-alive loop."""
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

                url = f"{scheme}://{target_host}{path}"
                socks = self._proxy.socks_proxy
                logger.trace("[REQ] %s %s via %s", method, url, socks or "direct")
                rule = self._proxy.rule
                modified = HeaderModifier.apply_rules(headers, url, rule, is_h2=False)

                if not any(k.lower() == "host" for k, _ in modified):
                    modified.append(("Host", target_host))

                await self._send_request(target, method, path, version, modified, body)
                target.touch()

                keep_alive, is_upgrade = await self._forward_response(
                    target, client, url
                )
                client.touch()

                if is_upgrade:
                    await self._bidirectional_pipe(client, target)
                    break
                if not keep_alive:
                    break

        except asyncio.TimeoutError:
            logger.debug("[HTTP/1.1 %s] Timeout after %d reqs", target_host, request_count)
        except (ConnectionResetError, BrokenPipeError) as e:
            logger.debug("[HTTP/1.1 %s] Connection closed: %s", target_host, e)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("[HTTP/1.1 %s] Error: %s\n%s", target_host, e, traceback.format_exc())

    async def handle_with_buffered(
        self,
        client: ManagedConnection,
        target: ManagedConnection,
        target_host: str,
        buffered: BufferedH1Request,
        is_https: bool = True,
    ) -> None:
        """Forward a pre-read first request, then enter keep-alive loop."""
        scheme = "https" if is_https else "http"

        try:
            url = f"{scheme}://{target_host}{buffered.path}"
            socks = self._proxy.socks_proxy
            logger.trace("[REQ] %s %s via %s", buffered.method, url, socks or "direct")
            rule = self._proxy.rule
            modified = HeaderModifier.apply_rules(buffered.headers, url, rule, is_h2=False)

            if not any(k.lower() == "host" for k, _ in modified):
                modified.append(("Host", target_host))

            await self._send_request(
                target, buffered.method, buffered.path, buffered.version, modified, buffered.body
            )
            target.touch()

            keep_alive, is_upgrade = await self._forward_response(target, client, url)
            client.touch()

            if is_upgrade:
                await self._bidirectional_pipe(client, target)
                return
            if keep_alive:
                await self.handle(client, target, target_host, is_https)

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("[HTTP/1.1 %s] Buffered handler error: %s", target_host, e)

    # -- internal ----------------------------------------------------------

    async def _read_request(
        self, conn: ManagedConnection
    ) -> Optional[tuple[str, str, str, list[tuple[str, str]], bytes]]:
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
                            content_length = int(v)
                        elif kl == "transfer-encoding" and "chunked" in v.lower():
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
        body = bytearray()
        while True:
            size_line = await reader.readline()
            size = int(size_line.strip(), 16)
            if size == 0:
                await reader.readline()
                break
            body.extend(await reader.readexactly(size))
            await reader.readline()
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
        """Forward response; capture it if the URL is being intercepted."""
        capture = self._proxy._start_capture(url)

        async with asyncio.timeout(self.config.request_timeout):
            status_line = await source.reader.readline()
            if not status_line:
                return False, False
            dest.writer.write(status_line)

            status_parts = status_line.decode("utf-8", errors="replace").split(" ", 2)
            status_code = int(status_parts[1]) if len(status_parts) >= 2 else 0
            version = status_parts[0].lower() if status_parts else ""
            default_ka = "http/1.1" in version

            if capture:
                capture.status_code = status_code

            content_length = -1
            chunked = False
            keep_alive = default_ka
            is_upgrade = status_code == 101

            while True:
                line = await source.reader.readline()
                dest.writer.write(line)
                if line == b"\r\n":
                    break

                header_raw = line.decode("utf-8", errors="replace").strip()
                if capture and ":" in header_raw:
                    hk, hv = header_raw.split(":", 1)
                    capture.headers.append((hk.strip(), hv.strip()))

                hl = header_raw.lower()
                if hl.startswith("content-length:"):
                    content_length = int(hl.split(":", 1)[1].strip())
                elif hl.startswith("transfer-encoding:") and "chunked" in hl:
                    chunked = True
                elif hl.startswith("connection:"):
                    keep_alive = "keep-alive" in hl

            if is_upgrade:
                await dest.writer.drain()
                if capture:
                    self._proxy._deliver_capture(capture)
                return False, True

            if chunked:
                while True:
                    size_line = await source.reader.readline()
                    dest.writer.write(size_line)
                    size = int(size_line.strip(), 16)
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

            await dest.writer.drain()

            if capture:
                self._proxy._deliver_capture(capture)

            return keep_alive, False

    async def _bidirectional_pipe(
        self, client: ManagedConnection, target: ManagedConnection
    ) -> None:
        async def pipe(src: ManagedConnection, dst: ManagedConnection) -> None:
            try:
                while not src.closed and not dst.closed:
                    try:
                        async with asyncio.timeout(self.config.idle_timeout):
                            data = await src.reader.read(self.config.read_buffer_size)
                    except asyncio.TimeoutError:
                        break
                    if not data:
                        break
                    src.touch()
                    dst.writer.write(data)
                    await dst.writer.drain()
                    dst.touch()
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                pass

        t1 = asyncio.create_task(pipe(client, target))
        t2 = asyncio.create_task(pipe(target, client))
        try:
            done, pending = await asyncio.wait(
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


# ============================================================================
# HTTP/2 Handler
# ============================================================================


class Http2Handler:
    __slots__ = ("config", "_proxy")

    def __init__(self, proxy: SessionProxy, config: ProxyConfig = DEFAULT_CONFIG):
        self._proxy = proxy
        self.config = config

    async def handle(
        self,
        client: ManagedConnection,
        target: ManagedConnection,
        target_host: str,
        client_conn: h2.connection.H2Connection,
        target_conn: h2.connection.H2Connection,
        streams: dict[int, Http2Stream],
        captures: dict[int, _ResponseCapture],
    ) -> None:
        logger.debug("[HTTP/2 %s] Handler started", target_host)
        timeout_task: Optional[asyncio.Task] = None

        try:
            client_task = asyncio.create_task(
                self._handle_client(
                    client, target, client_conn, target_conn, streams, captures, target_host
                )
            )
            target_task = asyncio.create_task(
                self._handle_target(
                    client, target, client_conn, target_conn, streams, captures
                )
            )
            timeout_task = asyncio.create_task(
                self._check_stream_timeouts(
                    streams, client_conn, target_conn, client, target
                )
            )

            done, pending = await asyncio.wait(
                [client_task, target_task], return_when=asyncio.FIRST_COMPLETED
            )

            goaway = False
            for t in done:
                exc = t.exception()
                if isinstance(exc, (_TargetGoaway, _ClientGoaway)):
                    goaway = True
                    logger.info(
                        "[HTTP/2 %s] GOAWAY teardown: %s", target_host, exc,
                    )
                elif exc:
                    logger.debug("[HTTP/2 %s] Task exc: %s", target_host, exc)

            for t in pending:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass

            # Flush any pending GOAWAY / RST_STREAM frames to both sides
            if goaway:
                await self._flush_both(client, target, client_conn, target_conn)
                await client.close()
                await target.close()
                logger.info("[HTTP/2 %s] Handler destroyed after GOAWAY", target_host)

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("[HTTP/2 %s] Error: %s\n%s", target_host, e, traceback.format_exc())
        finally:
            if timeout_task:
                timeout_task.cancel()
                try:
                    await timeout_task
                except asyncio.CancelledError:
                    pass
            logger.debug("[HTTP/2 %s] Handler stopped", target_host)
            streams.clear()
            captures.clear()

    async def start_session(self, client: ManagedConnection, target: ManagedConnection, target_host: str) -> None:
        """Set up HTTP/2 connections on both sides and enter the handler loop."""
        client_config = h2.config.H2Configuration(client_side=False)
        client_conn = h2.connection.H2Connection(config=client_config)
        client_conn.initiate_connection()
        client.writer.write(client_conn.data_to_send())
        await client.writer.drain()

        target_config = h2.config.H2Configuration(client_side=True)
        target_conn = h2.connection.H2Connection(config=target_config)
        target_conn.initiate_connection()

        streams: dict[int, Http2Stream] = {}
        captures: dict[int, _ResponseCapture] = {}

        self._proxy._track_h2_state(client_conn, target_conn, client, target)
        try:
            target.writer.write(target_conn.data_to_send())
            await target.writer.drain()

            async with asyncio.timeout(5.0):
                data = await target.reader.read(self.config.read_buffer_size)
                if data:
                    target_conn.receive_data(data)
                    ack = target_conn.data_to_send()
                    if ack:
                        target.writer.write(ack)
                        await target.writer.drain()

            await self.handle(
                client, target, target_host, client_conn, target_conn, streams, captures
            )

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(
                "[HTTP/2 %s] Session error: %s\n%s",
                target_host,
                e,
                traceback.format_exc(),
            )
        finally:
            self._proxy._untrack_h2_state(client_conn, target_conn, client, target)
            streams.clear()
            captures.clear()

    # -- internal ----------------------------------------------------------

    async def _check_stream_timeouts(
        self,
        streams: dict[int, Http2Stream],
        client_conn: h2.connection.H2Connection,
        target_conn: h2.connection.H2Connection,
        client: ManagedConnection,
        target: ManagedConnection,
    ) -> None:
        try:
            while True:
                await asyncio.sleep(30)
                now = time.monotonic()
                timed_out = [
                    s for s in streams.values()
                    if now - s.created_at > self.config.stream_timeout
                ]
                for s in timed_out:
                    try:
                        client_conn.reset_stream(s.client_id, error_code=8)
                        target_conn.reset_stream(s.target_id, error_code=8)
                    except Exception:
                        pass
                    streams.pop(s.client_id, None)
                if timed_out:
                    await self._flush_both(client, target, client_conn, target_conn)
        except asyncio.CancelledError:
            pass

    async def _handle_client(
        self,
        client: ManagedConnection,
        target: ManagedConnection,
        client_conn: h2.connection.H2Connection,
        target_conn: h2.connection.H2Connection,
        streams: dict[int, Http2Stream],
        captures: dict[int, _ResponseCapture],
        target_host: str,
    ) -> None:
        while not client.closed:
            try:
                async with asyncio.timeout(self.config.idle_timeout):
                    data = await client.reader.read(self.config.read_buffer_size)
            except asyncio.TimeoutError:
                break
            if not data:
                break
            client.touch()

            try:
                events = client_conn.receive_data(data)
            except h2.exceptions.ProtocolError as e:
                logger.warning("H2 protocol error (client): %s", e)
                break

            for event in events:
                await self._process_client_event(
                    event, client_conn, target_conn, streams, captures, target_host
                )

            await self._flush_both(client, target, client_conn, target_conn)

    async def _handle_target(
        self,
        client: ManagedConnection,
        target: ManagedConnection,
        client_conn: h2.connection.H2Connection,
        target_conn: h2.connection.H2Connection,
        streams: dict[int, Http2Stream],
        captures: dict[int, _ResponseCapture],
    ) -> None:
        while not target.closed:
            try:
                async with asyncio.timeout(self.config.idle_timeout):
                    data = await target.reader.read(self.config.read_buffer_size)
            except asyncio.TimeoutError:
                break
            if not data:
                break
            target.touch()

            try:
                events = target_conn.receive_data(data)
            except h2.exceptions.ProtocolError as e:
                logger.warning("H2 protocol error (target): %s", e)
                break

            for event in events:
                await self._process_target_event(
                    event, client_conn, target_conn, streams, captures
                )

            await self._flush_both(client, target, client_conn, target_conn)

    async def _flush_both(
        self,
        client: ManagedConnection,
        target: ManagedConnection,
        client_conn: h2.connection.H2Connection,
        target_conn: h2.connection.H2Connection,
    ) -> None:
        cd = client_conn.data_to_send()
        td = target_conn.data_to_send()
        if cd and not client.closed:
            client.writer.write(cd)
        if td and not target.closed:
            target.writer.write(td)
        coros = []
        if cd and not client.closed:
            coros.append(client.writer.drain())
        if td and not target.closed:
            coros.append(target.writer.drain())
        if coros:
            await asyncio.gather(*coros, return_exceptions=True)

    async def _process_client_event(
        self,
        event: h2.events.Event,
        client_conn: h2.connection.H2Connection,
        target_conn: h2.connection.H2Connection,
        streams: dict[int, Http2Stream],
        captures: dict[int, _ResponseCapture],
        target_host: str,
    ) -> None:
        if isinstance(event, h2.events.RequestReceived):
            cid = event.stream_id

            if len(streams) >= self.config.max_streams_per_connection:
                client_conn.reset_stream(cid, error_code=7)
                return

            headers: list[tuple[str, str]] = []
            for k, v in event.headers:
                key = k.decode("utf-8") if isinstance(k, bytes) else k
                val = v.decode("utf-8") if isinstance(v, bytes) else v
                headers.append((key, val))

            hd = {k.lower(): v for k, v in headers}
            path = hd.get(":path", "/")
            authority = hd.get(":authority", target_host)
            scheme = hd.get(":scheme", "https")
            method = hd.get(":method")

            if not method:
                client_conn.reset_stream(cid, error_code=1)
                return

            url = f"{scheme}://{authority}{path}"
            socks = self._proxy.socks_proxy
            logger.trace("[REQ] %s %s via %s (h2 stream %d)", method, url, socks or "direct", cid)
            rule = self._proxy.rule
            modified = HeaderModifier.apply_rules(headers, url, rule, is_h2=True)

            tid = target_conn.get_next_available_stream_id()
            stream = Http2Stream(
                client_id=cid,
                target_id=tid,
                authority=authority,
                path=path,
                scheme=scheme,
                created_at=time.monotonic(),
            )
            streams[cid] = stream

            # Start capture if URL is being intercepted
            cap = self._proxy._start_capture(url)
            if cap:
                captures[cid] = cap

            end_stream = event.stream_ended is not None
            target_conn.send_headers(tid, modified, end_stream=end_stream)

        elif isinstance(event, h2.events.DataReceived):
            stream = streams.get(event.stream_id)
            if stream:
                client_conn.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
                target_conn.send_data(
                    stream.target_id,
                    event.data,
                    end_stream=event.stream_ended is not None,
                )

        elif isinstance(event, h2.events.StreamReset):
            stream = streams.pop(event.stream_id, None)
            captures.pop(event.stream_id, None)
            if stream:
                try:
                    target_conn.reset_stream(stream.target_id, event.error_code)
                except Exception:
                    pass

        elif isinstance(event, h2.events.ConnectionTerminated):
            last_id = getattr(event, "last_stream_id", None)
            error_code = getattr(event, "error_code", 0)
            additional = getattr(event, "additional_data", b"")
            logger.info(
                "[GOAWAY] Client sent GOAWAY (last_stream=%s, error=%s, data=%s) — "
                "tearing down handler (%d active streams)",
                last_id, error_code, additional, len(streams),
            )

            # Deliver any in-flight captures before cleanup
            for cid, cap in list(captures.items()):
                if cap.status_code:
                    self._proxy._deliver_capture(cap)
            captures.clear()

            # Reset all active streams on the target side
            for stream in list(streams.values()):
                try:
                    target_conn.reset_stream(stream.target_id, error_code=2)
                except Exception:
                    pass
            streams.clear()

            # Forward GOAWAY to the target
            try:
                target_conn.close_connection(error_code=0)
            except Exception:
                pass

            raise _ClientGoaway(last_id, error_code, additional)

    async def _process_target_event(
        self,
        event: h2.events.Event,
        client_conn: h2.connection.H2Connection,
        target_conn: h2.connection.H2Connection,
        streams: dict[int, Http2Stream],
        captures: dict[int, _ResponseCapture],
    ) -> None:
        def find_stream(target_id: int) -> Optional[Http2Stream]:
            for s in streams.values():
                if s.target_id == target_id:
                    return s
            return None

        if isinstance(event, h2.events.ResponseReceived):
            stream = find_stream(event.stream_id)
            if stream:
                client_conn.send_headers(
                    stream.client_id,
                    event.headers,
                    end_stream=event.stream_ended is not None,
                )
                cap = captures.get(stream.client_id)
                if cap:
                    for k, v in event.headers:
                        key = k.decode("utf-8") if isinstance(k, bytes) else k
                        val = v.decode("utf-8") if isinstance(v, bytes) else v
                        if key == ":status":
                            cap.status_code = int(val)
                        else:
                            cap.headers.append((key, val))

        # elif isinstance(event, h2.events.DataReceived):
        #     stream = find_stream(event.stream_id)
        #     if stream:
        #         target_conn.acknowledge_received_data(
        #             event.flow_controlled_length, event.stream_id
        #         )
        #         client_conn.send_data(
        #             stream.client_id,
        #             event.data,
        #             end_stream=event.stream_ended is not None,
        #         )
        #         cap = captures.get(stream.client_id)
        #         if cap:
        #             cap.body.extend(event.data)
        elif isinstance(event, h2.events.DataReceived):
            stream = find_stream(event.stream_id)
            if stream:
                target_conn.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
                end = event.stream_ended is not None
                client_conn.send_data(stream.client_id, event.data, end_stream=end)
                cap = captures.get(stream.client_id)
                if cap:
                    cap.body.extend(event.data)
                if end:
                    cap = captures.pop(stream.client_id, None)
                    if cap:
                        self._proxy._deliver_capture(cap)
                    streams.pop(stream.client_id, None)
        
        elif isinstance(event, h2.events.StreamEnded):
            stream = find_stream(event.stream_id)
            if stream:
                try:
                    client_conn.end_stream(stream.client_id)
                except Exception:
                    pass
                cap = captures.pop(stream.client_id, None)
                if cap:
                    self._proxy._deliver_capture(cap)
                streams.pop(stream.client_id, None)

        elif isinstance(event, h2.events.StreamReset):
            stream = find_stream(event.stream_id)
            if stream:
                try:
                    client_conn.reset_stream(stream.client_id, event.error_code)
                except Exception:
                    pass
                captures.pop(stream.client_id, None)
                streams.pop(stream.client_id, None)

        elif isinstance(event, h2.events.TrailersReceived):
            stream = find_stream(event.stream_id)
            if stream:
                client_conn.send_headers(stream.client_id, event.headers, end_stream=True)
                cap = captures.pop(stream.client_id, None)
                if cap:
                    self._proxy._deliver_capture(cap)

        elif isinstance(event, h2.events.ConnectionTerminated):
            last_id = getattr(event, "last_stream_id", None)
            error_code = getattr(event, "error_code", 0)
            additional = getattr(event, "additional_data", b"")
            logger.info(
                "[GOAWAY] Target sent GOAWAY (last_stream=%s, error=%s, data=%s) — "
                "tearing down handler (%d active streams)",
                last_id, error_code, additional, len(streams),
            )

            # Deliver any in-flight captures before cleanup
            for cid, cap in list(captures.items()):
                if cap.status_code:
                    self._proxy._deliver_capture(cap)
            captures.clear()

            # Reset all active streams on the client side
            for stream in list(streams.values()):
                try:
                    client_conn.reset_stream(stream.client_id, error_code=2)
                except Exception:
                    pass
            streams.clear()

            # Forward GOAWAY to the client so it knows to reconnect
            try:
                client_conn.close_connection(error_code=0)
            except Exception:
                pass

            raise _TargetGoaway(last_id, error_code, additional)


# ============================================================================
# Core Proxy Handler (single-session, no multiplexing)
# ============================================================================


class _ProxyHandler:
    """Handles connections for a single SessionProxy instance."""

    __slots__ = ("_proxy", "tls", "http1", "http2", "config")

    def __init__(self, proxy: SessionProxy, tls: TLSInterceptor, config: ProxyConfig):
        self._proxy = proxy
        self.tls = tls
        self.config = config
        self.http1 = Http1Handler(proxy, config)
        self.http2 = Http2Handler(proxy, config)

    async def handle_client(self, reader: StreamReader, writer: StreamWriter) -> None:
        client = ManagedConnection(reader, writer)
        self._proxy._track_connection(client)

        try:
            async with asyncio.timeout(self.config.request_timeout):
                line = await reader.readline()
                if not line:
                    return

                request_line = line.decode("utf-8", errors="replace").strip()
                parts = request_line.split(" ", 2)
                if len(parts) < 3:
                    return

                method, target_url, version = parts

                headers: dict[str, str] = {}
                raw_headers: list[tuple[str, str]] = []
                content_length = 0
                chunked = False

                while True:
                    hl = await reader.readline()
                    if not hl or hl == b"\r\n":
                        break
                    decoded = hl.decode("utf-8", errors="replace").strip()
                    if ":" in decoded:
                        k, v = decoded.split(":", 1)
                        ks, vs = k.strip(), v.strip()
                        headers[ks.lower()] = vs
                        raw_headers.append((ks, vs))
                        kl = ks.lower()
                        if kl == "content-length":
                            content_length = int(vs)
                        elif kl == "transfer-encoding" and "chunked" in vs.lower():
                            chunked = True

            if method == "CONNECT":
                await self._handle_connect(client, target_url)
            else:
                body = b""
                if chunked:
                    body = await self._read_chunked_body(reader)
                elif content_length > 0:
                    body = await reader.readexactly(content_length)
                await self._handle_plain_http(
                    client, method, target_url, version, raw_headers, body, headers
                )

        except asyncio.TimeoutError:
            pass
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
                    port = int(port_str)
                else:
                    host, port = host_header, 80
                path = target_url

            if not host:
                client.writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await client.writer.drain()
                return

            target = await self._connect_to_target(host, port)
            display_host = f"{host}:{port}" if port != 80 else host

            socks = self._proxy.socks_proxy
            logger.trace("[REQ] %s http://%s%s via %s", method, display_host, path, socks or "direct")

            buffered = BufferedH1Request(
                method=method, path=path, version=version,
                headers=raw_headers, body=body,
            )
            await self.http1.handle_with_buffered(
                client, target, display_host, buffered, is_https=False
            )

        except asyncio.TimeoutError:
            self._try_error(client, b"HTTP/1.1 504 Gateway Timeout\r\n\r\n")
        except (ConnectionRefusedError, ConnectionError):
            self._try_error(client, b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except Exception as e:
            logger.error("[HTTP] Error: %s", e)
            self._try_error(client, b"HTTP/1.1 500 Internal Server Error\r\n\r\n")
        finally:
            if target:
                await target.close()

    # -- CONNECT -----------------------------------------------------------

    async def _handle_connect(self, client: ManagedConnection, target_url: str) -> None:
        if ":" in target_url:
            host, port_str = target_url.rsplit(":", 1)
            port = int(port_str)
        else:
            host, port = target_url, 443

        target: Optional[ManagedConnection] = None
        client_tls: Optional[ManagedConnection] = None
        target_tls: Optional[ManagedConnection] = None

        try:
            client.writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client.writer.drain()

            protocol, client_tls = await self._negotiate_client_tls(client, host)
            self._proxy._track_connection(client_tls)

            target = await self._connect_to_target(host, port)
            self._proxy._track_connection(target)

            target_tls = await self._negotiate_target_tls(target, host, protocol)
            self._proxy._track_connection(target_tls)

            if protocol == Protocol.HTTP2:
                await self.http2.start_session(client_tls, target_tls, host)
            else:
                await self.http1.handle(client_tls, target_tls, host, is_https=True)

        except asyncio.TimeoutError:
            logger.warning("[%s:%d] Timeout", host, port)
        except (ConnectionRefusedError, ConnectionError, OSError) as e:
            logger.warning("[%s:%d] Connection error: %s", host, port, e)
        except Exception as e:
            logger.error("[%s:%d] Error: %s\n%s", host, port, e, traceback.format_exc())
        finally:
            for conn in (target_tls, client_tls, target):
                if conn:
                    self._proxy._untrack_connection(conn)
                    await conn.close()

    # -- TLS ---------------------------------------------------------------

    async def _negotiate_client_tls(
        self, client: ManagedConnection, hostname: str
    ) -> tuple[Protocol, ManagedConnection]:
        loop = asyncio.get_event_loop()
        ctx = self.tls.get_server_context(("h2", "http/1.1"))

        transport = client.writer.transport
        proto_obj = transport.get_protocol()

        async with asyncio.timeout(self.config.connect_timeout):
            ssl_transport = await loop.start_tls(
                transport, proto_obj, ctx, server_side=True
            )

        if ssl_transport is None:
            raise ConnectionError("Client TLS handshake failed")

        ssl_obj = ssl_transport.get_extra_info("ssl_object")
        alpn = ssl_obj.selected_alpn_protocol() if ssl_obj else None
        protocol = Protocol.HTTP2 if alpn == "h2" else Protocol.HTTP1

        tls_reader = StreamReader()
        tls_proto = asyncio.StreamReaderProtocol(tls_reader)
        ssl_transport.set_protocol(tls_proto)
        tls_proto.connection_made(ssl_transport)
        tls_writer = StreamWriter(ssl_transport, tls_proto, tls_reader, loop)

        return protocol, ManagedConnection(tls_reader, tls_writer)

    async def _negotiate_target_tls(
        self, target: ManagedConnection, hostname: str, protocol: Protocol
    ) -> ManagedConnection:
        loop = asyncio.get_event_loop()
        ctx = self.tls.create_client_context(alpn=[protocol.value])

        transport = target.writer.transport
        proto_obj = transport.get_protocol()

        async with asyncio.timeout(self.config.connect_timeout):
            ssl_transport = await loop.start_tls(
                transport, proto_obj, ctx,
                server_side=False, server_hostname=hostname,
            )

        if ssl_transport is None:
            raise ConnectionError("Target TLS handshake failed")

        tls_reader = StreamReader()
        tls_proto = asyncio.StreamReaderProtocol(tls_reader)
        ssl_transport.set_protocol(tls_proto)
        tls_proto.connection_made(ssl_transport)
        tls_writer = StreamWriter(ssl_transport, tls_proto, tls_reader, loop)

        return ManagedConnection(tls_reader, tls_writer)

    # -- target connection -------------------------------------------------

    async def _connect_to_target(self, host: str, port: int) -> ManagedConnection:
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

    async def _read_chunked_body(self, reader: StreamReader) -> bytes:
        body = bytearray()
        while True:
            size_line = await reader.readline()
            size = int(size_line.strip(), 16)
            if size == 0:
                await reader.readline()
                break
            body.extend(await reader.readexactly(size))
            await reader.readline()
        return bytes(body)

    @staticmethod
    def _try_error(client: ManagedConnection, msg: bytes) -> None:
        try:
            if not client.closed:
                client.writer.write(msg)
        except Exception:
            pass


# ============================================================================
# SessionProxy — one instance per browser session
# ============================================================================


class SessionProxy:
    """A per-session proxy server with response interception.

    Usage::

        pool = SocksProxyPool("proxies.txt")

        proxy = SessionProxy(
            ca_cert="certs/ca.pem",
            ca_key="certs/ca.key",
            socks_pool=pool,               # shared pool, auto-assigns one
        )
        port = await proxy.start()          # OS-assigned port

        # configure browser: --proxy-server=127.0.0.1:{port}

        # intercept responses
        async with proxy.intercept(["https://api.example.com/v1/data"]) as cap:
            driver.get("https://example.com")
            resp = await cap.get("https://api.example.com/v1/data", timeout=30)
            print(resp.status_code, len(resp.body))

        # rotate exit IP
        new_proxy = proxy.rotate_proxy()
        print(f"Now using: {new_proxy}")

        # modify outgoing headers
        proxy.set_rule(
            urls={"https://cdn.example.com/bundle.js"},
            headers=[("Authorization", "Bearer tok")],
        )

        await proxy.stop()
    """

    def __init__(
        self,
        ca_cert: str,
        ca_key: str,
        socks_pool: Optional[SocksProxyPool] = None,
        socks_proxy: Optional[str] = None,
        host: str = "127.0.0.1",
        port: int = 0,
        config: ProxyConfig = DEFAULT_CONFIG,
    ):
        self.host = host
        self.port = port
        self.config = config
        self.rule: Optional[Rule] = None

        self._socks_pool = socks_pool
        # Explicit proxy takes precedence; otherwise auto-assign from pool
        if socks_proxy:
            self.socks_proxy: Optional[str] = socks_proxy
        elif socks_pool:
            self.socks_proxy = socks_pool.assign()
        else:
            self.socks_proxy = None

        self._tls = TLSInterceptor(ca_cert, ca_key)
        self._handler: Optional[_ProxyHandler] = None
        self._server: Optional[asyncio.Server] = None
        self._interceptors: list[RequestInterceptor] = []
        self._interceptor_lock = threading.Lock()
        self._active_connections: set[ManagedConnection] = set()
        self._active_h2_states: list[tuple[
            h2.connection.H2Connection,  # client h2 conn
            h2.connection.H2Connection,  # target h2 conn
            ManagedConnection,           # client
            ManagedConnection,           # target
        ]] = []

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> int:
        """Start listening. Returns the bound port number."""
        self._handler = _ProxyHandler(self, self._tls, self.config)
        self._server = await asyncio.start_server(
            self._handler.handle_client,
            self.host,
            self.port,
            reuse_address=True,
        )
        # Resolve actual port (useful when port=0)
        sock = self._server.sockets[0]
        self.port = sock.getsockname()[1]
        logger.info("SessionProxy listening on %s:%d (socks: %s)", self.host, self.port, self.socks_proxy or "direct")
        return self.port

    async def stop(self) -> None:
        """Stop accepting and close everything."""
        if self._server:
            if self._server.is_serving():
                self._server.close()
                await self._server.wait_closed()
            self._server = None
        await self.close_all_handlers()
        self._handler = None
        self.rule = None
        self.socks_proxy = None
        logger.info("SessionProxy stopped (was :%d)", self.port)

    # -- SOCKS proxy management --------------------------------------------

    def rotate_proxy(self) -> Optional[str]:
        """Switch to a different SOCKS proxy from the pool. Returns the new proxy or None."""
        if not self._socks_pool:
            logger.warning("No SOCKS pool configured, cannot rotate")
            return None
        new_proxy = self._socks_pool.rotate(self.socks_proxy)
        old = self.socks_proxy
        self.socks_proxy = new_proxy
        logger.info("Rotated SOCKS proxy: %s -> %s", old, new_proxy)
        return new_proxy

    def get_proxy(self) -> Optional[str]:
        """Return the currently assigned SOCKS proxy."""
        return self.socks_proxy

    # -- header rules ------------------------------------------------------

    def set_rule(self, urls: set[str], headers: list[tuple[str, str]]) -> None:
        """Set a header-modification rule (replaces any previous rule)."""
        self.rule = Rule.create(urls, headers)

    def clear_rule(self) -> None:
        self.rule = None

    # -- interception API --------------------------------------------------

    def intercept(self, urls: list[str]) -> RequestInterceptor:
        """Create a :class:`RequestInterceptor` for the given URL patterns.

        Must be used as an ``async with`` context manager.
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
        """Deliver a completed capture to all matching interceptors.

        Synchronous — safe to call from the proxy thread.  Actual future
        resolution and queue insertion happen on the caller's loop via
        ``call_soon_threadsafe``.
        """
        response = capture.finalise()
        with self._interceptor_lock:
            for ic in self._interceptors:
                pattern = ic.matches(response.url)
                if pattern is not None:
                    ic._deliver_threadsafe(pattern, response)

    # -- Connections tracker --------------------------------------------------

    async def close_all_handlers(self) -> None:
        """Forcefully close all active connections with clean HTTP/2 teardown.
        Does NOT stop the server — new connections can still be accepted."""
        h2_states = list(self._active_h2_states)
        self._active_h2_states.clear()
        for client_h2, target_h2, client_mc, target_mc in h2_states:
            try:
                client_h2.close_connection(error_code=0)
                data = client_h2.data_to_send()
                if data and not client_mc.closed:
                    client_mc.writer.write(data)
                    await asyncio.wait_for(client_mc.writer.drain(), timeout=2.0)
            except Exception:
                pass
            try:
                target_h2.close_connection(error_code=0)
                data = target_h2.data_to_send()
                if data and not target_mc.closed:
                    target_mc.writer.write(data)
                    await asyncio.wait_for(target_mc.writer.drain(), timeout=2.0)
            except Exception:
                pass

        connections = list(self._active_connections)
        self._active_connections.clear()
        if connections:
            logger.info("Force-closing %d active connection(s)", len(connections))
            await asyncio.wait_for(
                asyncio.gather(
                    *(conn.close() for conn in connections),
                    return_exceptions=True,
                ),
                timeout=5.0,
            )

    def _track_connection(self, conn: ManagedConnection) -> None:
        self._active_connections.add(conn)

    def _untrack_connection(self, conn: ManagedConnection) -> None:
        self._active_connections.discard(conn)

    def _track_h2_state(self, client_conn, target_conn, client, target):
        self._active_h2_states.append((client_conn, target_conn, client, target))

    def _untrack_h2_state(self, client_conn, target_conn, client, target):
        try:
            self._active_h2_states.remove((client_conn, target_conn, client, target))
        except ValueError:
            pass


# ============================================================================
# Logging
# ============================================================================


class CustomLogger(logging.Logger):
    def trace(self, message: object, *args: Any, stacklevel: int = 1, **kwargs: Any) -> None:
        if self.isEnabledFor(5):
            self._log(5, message, args, **kwargs, stacklevel=stacklevel + 1)


logging.setLoggerClass(CustomLogger)
logging.addLevelName(5, "TRACE")


class ColoredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        colors = {
            5: "\033[0;37m",
            logging.DEBUG: "\033[0m",
            logging.INFO: "\033[34m",
            logging.WARNING: "\033[1;33m",
            logging.ERROR: "\033[1;31m",
            logging.CRITICAL: "\033[1;37;41m",
        }
        c = colors.get(record.levelno, "\033[0m")
        record.elapsed = f"{record.relativeCreated / 1000.0:8.3f}"  # type: ignore[attr-defined]
        record.msg = f"{c}{record.msg}\033[0m"
        record.levelname = f"{c}{record.levelname:<8}\033[0m"
        return super().format(record)


logger: CustomLogger = logging.getLogger(__name__)  # type: ignore[assignment]
logger.setLevel(logging.DEBUG)

_handler = logging.StreamHandler()
_handler.setLevel(logging.DEBUG)
_handler.setFormatter(
    ColoredFormatter(
        "%(elapsed)s | %(levelname)-8s | %(filename)s | %(funcName)s[%(lineno)d] | %(message)s"
    )
)
logger.addHandler(_handler)