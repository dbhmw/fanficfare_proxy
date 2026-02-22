"""
proxy.py — Per-session MITM proxy with HTTP/1.1 and HTTP/2 support.

Architecture
------------
Each ``SessionProxy`` instance binds a local TCP port that a browser
(or any HTTP client) can use as its HTTP/HTTPS proxy.  For HTTPS the
proxy performs a TLS man-in-the-middle using a custom CA certificate so
it can inspect, modify, and capture request/response traffic.

Key components:

* **SessionProxy** — owns the ``asyncio.Server``, SOCKS pool assignment,
  header-modification rules, and response-interception registry.
* **_ProxyHandler** — accepts individual browser connections; dispatches
  plain-HTTP vs CONNECT tunnels.
* **Http1Handler / Http2Handler** — protocol-specific bidirectional
  forwarding with keep-alive, interception, and capture support.
* **RequestInterceptor** — async context manager that lets callers
  ``await`` specific response URLs flowing through the proxy.
* **TLSInterceptor** — creates the per-ALPN ``ssl.SSLContext`` pairs
  for the browser-side and target-side TLS handshakes.
* **SidecarManager** (external) — optional Go subprocess that provides
  Chrome-fingerprinted TLS for the target connection, avoiding Python's
  easily-detectable ``ssl`` module fingerprint.

Threading model
~~~~~~~~~~~~~~~
Everything runs on a single asyncio event loop **except** the caller of
``RequestInterceptor``, which may live on a different thread/loop.
Cross-thread delivery uses ``loop.call_soon_threadsafe`` and a short
``threading.Lock`` to protect the interceptor registry.
"""

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
import h2.config
import h2.connection
import h2.events
import h2.exceptions
from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Optional, Sequence
from urllib.parse import urlparse
from utls_bridge.sidecar import SidecarManager

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


# ============================================================================
# Configuration
# ============================================================================


@dataclass(frozen=True)
class ProxyConfig:
    """Tunable knobs for the proxy.

    All timeouts are in seconds.  Buffer sizes are in bytes.

    Attributes
    ----------
    max_streams_per_connection:
        HTTP/2 concurrent stream cap per origin connection.  Exceeding
        this causes the proxy to RST_STREAM with REFUSED_STREAM (0x7).
    verify_ssl:
        Whether to verify the *target* server's TLS certificate.  Set
        ``False`` for development/testing only.
    connect_timeout:
        Maximum time allowed for TCP + optional SOCKS + TLS handshake
        when establishing a new target connection.
    idle_timeout:
        How long a keep-alive connection may sit idle before the proxy
        tears it down.  Should be shorter than the browser's own idle
        timeout to avoid races.
    request_timeout:
        Maximum wall-clock time for reading a single HTTP request
        (headers + body) or response (headers + body) from either side.
    stream_timeout:
        Per-stream deadline for HTTP/2.  Streams older than this are
        RST_STREAM'd with CANCEL (0x8) on both sides.
    read_buffer_size:
        Size of the ``asyncio`` read buffer passed to ``reader.read()``.
    """

    max_streams_per_connection: int = 100
    verify_ssl: bool = True

    connect_timeout: float = 120.0
    idle_timeout: float = 70.0
    request_timeout: float = 120.0
    stream_timeout: float = 120.0

    read_buffer_size: int = 65536


DEFAULT_CONFIG = ProxyConfig()


# ============================================================================
# Data Classes
# ============================================================================


@dataclass(frozen=True)
class Rule:
    """An immutable header-modification rule bound to a set of URLs.

    When the proxy sees an outgoing request whose URL is in ``urls``,
    the headers in ``headers`` are merged into (or replace) the
    request's existing headers.
    """

    urls: frozenset[str]
    headers: tuple[tuple[str, str], ...]

    @classmethod
    def create(cls, urls: set[str], headers: list[tuple[str, str]]) -> Rule:
        return cls(frozenset(urls), tuple((k, v) for k, v in headers))


class Protocol(Enum):
    """ALPN-negotiated protocol for the target connection."""

    HTTP1 = "http/1.1"
    HTTP2 = "h2"


@dataclass
class InterceptedResponse:
    """A captured HTTP response with an auto-decompressed body.

    The ``body`` field is *always* decompressed (gzip, br, deflate,
    zstd).  The original ``content_encoding`` is preserved for
    informational purposes.
    """

    url: str
    status_code: int
    headers: list[tuple[str, str]]
    body: bytes
    content_type: str
    content_encoding: str
    timestamp: float = field(default_factory=time.monotonic)


def _decompress_body(data: bytes, encoding: str) -> bytes:
    """Decompress *data* according to the ``Content-Encoding`` value.

    Falls back to returning *data* unchanged if decompression fails or
    the encoding is unrecognised.
    """
    if not data or not encoding:
        return data

    encoding = encoding.lower().strip()

    try:
        if encoding in ("gzip", "x-gzip"):
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
            logger.warning(
                "Unknown Content-Encoding: %s, returning raw body", encoding
            )
            return data
    except Exception as e:
        logger.warning(
            "Failed to decompress %s response (%s), returning raw body", encoding, e
        )
        return data


@dataclass
class _ResponseCapture:
    """Internal accumulator for a response that is being intercepted.

    Collects status, headers, and body chunks as they arrive.  Call
    ``finalise()`` to produce the public ``InterceptedResponse`` (with
    decompressed body).
    """

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

    **Thread-safe:** the ``async with`` block runs on the caller's event
    loop, while the proxy delivers responses from its own loop/thread.
    Delivery crosses threads via ``loop.call_soon_threadsafe``.

    Supports three consumption patterns::

        # 1. Wait for a specific URL
        async with proxy.intercept(["https://a.com/x"]) as cap:
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

    URL matching
    ~~~~~~~~~~~~
    Exact string match by default.  Patterns containing ``*`` or ``?``
    use :func:`fnmatch.fnmatch`-style globbing, e.g.
    ``"https://api.example.com/v1/*"`` matches any sub-path.
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
        """Return the pattern that matched *url*, or ``None``."""
        if url in self._exact_urls:
            return url
        for pat in self._glob_patterns:
            if fnmatch.fnmatch(url, pat):
                return pat
        return None

    # -- delivery (called from proxy thread) -------------------------------

    def _deliver_threadsafe(self, pattern: str, response: InterceptedResponse) -> None:
        """Deliver a response from the proxy thread to the caller's loop.

        Called synchronously from the proxy's event loop.  Uses
        ``call_soon_threadsafe`` to resolve the future and enqueue the
        response on the *caller's* loop, which may be a different thread.
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

    async def get(
        self, url_or_pattern: str, *, timeout: float = 30.0
    ) -> InterceptedResponse:
        """Wait for a response matching *url_or_pattern*.

        Raises
        ------
        KeyError
            If *url_or_pattern* was not registered with this interceptor.
        asyncio.TimeoutError
            If no matching response arrives within *timeout* seconds.
        """
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
    """Shared logic for stripping, filtering, and modifying HTTP headers.

    **Request headers:** Removes browser-injected client-hints and proxy
    headers that would leak information or violate HTTP/2 constraints.

    **Response headers:** Filters ``Alt-Svc`` to remove HTTP/3 (QUIC)
    entries while preserving legitimate h2 alternatives.  This prevents
    the browser from upgrading to HTTP/3, which the proxy cannot MITM
    because QUIC bundles its own crypto transport.
    """

    # Headers that reveal client-hint / network data
    STRIP_HEADERS: frozenset[str] = frozenset(
        {"rtt", "ect", "downlink", "device-memory", "viewport-width", "dpr"}
    )

    # Prefix-based stripping (sec-ch-ua-*, proxy-*)
    STRIP_PREFIXES: tuple[str, ...] = ("sec-ch-", "proxy-")

    # HTTP/2 forbids connection-level headers (RFC 9113 §8.2.2)
    FORBIDDEN_H2_HEADERS: frozenset[str] = frozenset(
        {
            "connection",
            "keep-alive",
            "proxy-connection",
            "transfer-encoding",
            "upgrade",
        }
    )

    @classmethod
    def should_strip(cls, name: str, value: str = "", is_h2: bool = False) -> bool:
        """Return ``True`` if the header should be removed."""
        lower = name.lower()
        if lower in cls.STRIP_HEADERS:
            return True
        if is_h2 and lower in cls.FORBIDDEN_H2_HEADERS:
            return True
        if lower == "te" and value.lower() != "trailers":
            return True
        return any(lower.startswith(p) for p in cls.STRIP_PREFIXES)

    # ── Response-header filtering ──
    #
    # HTTP/3 runs over QUIC (UDP) which we cannot MITM.  Browsers
    # discover HTTP/3 via the `Alt-Svc` response header:
    #
    #   Alt-Svc: h2="alt.example.com:443", h3=":443"; ma=86400
    #
    # If we strip the header wholesale we also lose legitimate h1→h2
    # upgrades and cross-host alternatives.  Instead we parse the
    # comma-separated entries and remove only those whose protocol-id
    # starts with "h3" (covers h3, h3-29, h3-Q050, etc.).
    #
    # The special token "clear" (RFC 7838 §3) means "forget all
    # alternatives" and is always preserved.

    # Protocol-id prefixes that indicate QUIC/HTTP-3
    _H3_PREFIXES: tuple[str, ...] = ("h3",)

    @classmethod
    def filter_alt_svc(cls, value: str) -> Optional[str]:
        """Remove HTTP/3 entries from an ``Alt-Svc`` header value.

        Returns the filtered value string, or ``None`` if no entries
        remain (meaning the header should be dropped entirely).

        Examples::

            >>> HeaderModifier.filter_alt_svc('h3=":443"; ma=86400')
            None
            >>> HeaderModifier.filter_alt_svc('h2="alt:443", h3=":443"')
            'h2="alt:443"'
            >>> HeaderModifier.filter_alt_svc('clear')
            'clear'
        """
        stripped = value.strip()
        if not stripped:
            return None

        # "clear" is a special standalone token — always pass through
        if stripped.lower() == "clear":
            return stripped

        kept: list[str] = []
        for entry in stripped.split(","):
            entry = entry.strip()
            if not entry:
                continue

            # Extract the protocol-id: everything before '='
            # e.g. 'h3=":443"; ma=86400' → 'h3'
            #      'h2="alt.example.com:443"' → 'h2'
            eq_pos = entry.find("=")
            if eq_pos == -1:
                # Malformed entry or bare token — keep it to be safe
                kept.append(entry)
                continue

            proto_id = entry[:eq_pos].strip().lower()

            # Drop if the protocol-id is h3, h3-29, h3-Q050, etc.
            if any(proto_id.startswith(p) for p in cls._H3_PREFIXES):
                continue

            kept.append(entry)

        if not kept:
            return None

        return ", ".join(kept)

    @classmethod
    def filter_response_headers(
        cls,
        headers: Sequence[tuple[bytes | str, bytes | str]],
    ) -> list[tuple[bytes | str, bytes | str]]:
        """Filter a response header list, removing HTTP/3 ``Alt-Svc`` entries.

        Designed for HTTP/2 where headers arrive as a list of
        ``(name, value)`` tuples (possibly bytes).  Accepts ``Sequence``
        rather than ``list`` because h2's ``Header`` namedtuple is a
        subtype of ``tuple`` — and ``list`` is invariant in its type
        parameter.  Returns a new list with ``alt-svc`` entries filtered
        or removed.
        """
        result: list[tuple[bytes | str, bytes | str]] = []
        for k, v in headers:
            key_str = k.decode("utf-8") if isinstance(k, bytes) else k
            if key_str.lower() != "alt-svc":
                result.append((k, v))
                continue

            # Filter the value
            val_str = v.decode("utf-8") if isinstance(v, bytes) else v
            filtered = cls.filter_alt_svc(val_str)
            if filtered is not None:
                # Preserve original type (bytes vs str) for h2 compat
                if isinstance(v, bytes):
                    result.append((k, filtered.encode("utf-8")))
                else:
                    result.append((k, filtered))
            # else: drop the header entirely — all entries were h3

        return result

    @classmethod
    def apply_rules(
        cls,
        headers: list[tuple[str, str]],
        url: str,
        rule: Optional[Rule],
        is_h2: bool = True,
    ) -> list[tuple[str, str]]:
        """Strip unwanted headers, apply *rule* overrides, return clean list.

        Pseudo-headers (``:method``, ``:path``, etc.) are preserved at
        the front of the list for HTTP/2 compliance.
        """
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

            # Build a lookup of rule headers that are eligible for
            # this connection type, keyed by lowered name.
            rule_overrides: dict[str, str] = {}
            for name, value in rule.headers:
                nl = name.lower()
                if nl.startswith(":"):
                    continue
                if is_h2 and nl in cls.FORBIDDEN_H2_HEADERS:
                    continue
                if nl in cls.STRIP_HEADERS:
                    continue
                rule_overrides[nl] = value

            # Pass 1: walk regular headers in order, replacing values
            # where the rule provides an override.  Track which rule
            # keys were consumed so we know what to append.
            applied: set[str] = set()
            updated: list[tuple[str, str]] = []
            for k, v in regular:
                kl = k.lower()
                if kl in rule_overrides and kl not in applied:
                    # Replace value at the same position (first
                    # occurrence wins — preserves order for duplicates)
                    updated.append((kl, rule_overrides[kl]))
                    applied.add(kl)
                else:
                    updated.append((k, v))

            # Pass 2: append any rule headers that weren't already
            # present in the original list (new additions go at end).
            for nl, value in rule_overrides.items():
                if nl not in applied:
                    updated.append((nl, value))

            regular = updated

        return pseudo + regular


# ============================================================================
# Connection Wrapper
# ============================================================================


class ManagedConnection:
    """Thin wrapper around an ``(StreamReader, StreamWriter)`` pair.

    Tracks last-activity time for idle-timeout enforcement and provides
    a safe ``close()`` that handles SSL edge-cases without spamming the
    asyncio exception handler.
    """

    __slots__ = ("reader", "writer", "last_activity", "_closed")

    def __init__(self, reader: StreamReader, writer: StreamWriter):
        self.reader = reader
        self.writer = writer
        self.last_activity = time.monotonic()
        self._closed = False

    def touch(self) -> None:
        """Update the last-activity timestamp (call on every successful I/O)."""
        self.last_activity = time.monotonic()

    async def close(self, force: bool = False) -> None:
        """Close the underlying transport.

        Parameters
        ----------
        force:
            If ``True``, abort the transport immediately without
            attempting a graceful TLS ``close_notify`` shutdown.  Use
            this during bulk teardown (e.g. ``close_all_handlers``)
            where the peer may already be gone and a graceful close
            would just hang until the timeout fires.

        When *force* is ``False`` (the default), the method handles the
        common case where an SSL transport's underlying TCP connection
        has already been reset by the peer — in that scenario
        ``writer.close()`` would trigger an ``SSLError`` that asyncio
        routes through its exception handler, producing noisy log lines.
        We detect this and ``abort()`` directly instead.
        """
        if self._closed:
            return
        self._closed = True
        try:
            transport = self.writer.transport
            if force:
                transport.abort()
            if transport is None or transport.is_closing():
                return
            ssl_obj = transport.get_extra_info("ssl_object")
            if ssl_obj is not None:
                try:
                    ssl_obj.version()
                except Exception:
                    # SSL session is dead — skip graceful close
                    transport.abort()
                    return
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), timeout=2.0)
        except TimeoutError:
            try:
                transport = self.writer.transport
                if transport and not transport.is_closing():
                    transport.abort()
            except Exception as e:
                logger.debug(e)
            logger.trace("Connection close timed out, aborted")
        except Exception as e:
            logger.debug("Connection close error: %s", e)

    @property
    def closed(self) -> bool:
        return self._closed or self.writer.is_closing()


# ============================================================================
# SOCKS5 Client
# ============================================================================


class Socks5Client:
    """Async SOCKS5 CONNECT client (no-auth method only)."""

    @staticmethod
    async def connect(
        proxy: str, target_host: str, target_port: int, timeout: float = 30.0
    ) -> tuple[StreamReader, StreamWriter]:
        """Open a SOCKS5 tunnel to ``target_host:target_port`` via *proxy*.

        Parameters
        ----------
        proxy:
            ``host:port`` of the SOCKS5 proxy.  ``user@host:port`` is
            accepted but the user part is stripped (no auth sent).
        target_host:
            The hostname the SOCKS5 proxy should connect to.
        target_port:
            The port the SOCKS5 proxy should connect to.
        timeout:
            Overall timeout for the SOCKS5 handshake + CONNECT.
        """
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
                # Greeting: version 5, 1 method (no-auth)
                writer.write(b"\x05\x01\x00")
                await writer.drain()

                resp = await reader.readexactly(2)
                if resp[0] != 0x05 or resp[1] == 0xFF:
                    raise ConnectionError("SOCKS5 handshake failed")

                # CONNECT request: domain-name address type (0x03)
                domain = target_host.encode("utf-8")
                request = (
                    b"\x05\x01\x00\x03"
                    + bytes([len(domain)])
                    + domain
                    + struct.pack(">H", target_port)
                )
                writer.write(request)
                await writer.drain()

                # CONNECT response
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

                # Drain the bound address so the socket is ready for data
                atyp = resp[3]
                if atyp == 0x01:  # IPv4 + port
                    await reader.readexactly(6)
                elif atyp == 0x03:  # Domain + port
                    length = (await reader.readexactly(1))[0]
                    await reader.readexactly(length + 2)
                elif atyp == 0x04:  # IPv6 + port
                    await reader.readexactly(18)

            return reader, writer
        except Exception:
            writer.close()
            await writer.wait_closed()
            raise


class SocksProxyPool:
    """Shared SOCKS5 proxy pool — loaded once, used by many ``SessionProxy`` instances.

    Proxies are loaded from a newline-delimited text file.  Each line
    should be ``host:port``.

    Thread-safe for read access (the tuple is immutable); call
    ``reload()`` to re-read the file.
    """

    __slots__ = ("proxy_file", "proxies")

    def __init__(self, proxy_file: str):
        self.proxy_file = proxy_file
        self.proxies: tuple[str, ...] = ()
        self._load_proxies()

    def _load_proxies(self) -> None:
        try:
            with open(self.proxy_file, "r", encoding="utf-8") as f:
                self.proxies = tuple(line.strip() for line in f if line.strip())
            logger.info(
                "Loaded %d SOCKS5 proxies from %s",
                len(self.proxies),
                self.proxy_file,
            )
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
        """Pick a different proxy than *current*.

        Falls back to any proxy if the pool only has one entry.
        """
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
    """Creates ``ssl.SSLContext`` objects for both sides of the MITM.

    The *server* context (presented to the browser) uses the custom CA
    certificate so the browser trusts the intercepted connection.  The
    *client* context (used toward the target) is a standard outgoing
    context with optional certificate verification.

    Server contexts are cached by ALPN tuple so we don't re-create them
    on every connection.
    """

    __slots__ = ("ca_cert_path", "ca_key_path", "_server_ctx_cache")

    def __init__(self, ca_cert_path: str, ca_key_path: str):
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self._server_ctx_cache: dict[tuple[str, ...], ssl.SSLContext] = {}

    def get_server_context(self, alpn: tuple[str, ...]) -> ssl.SSLContext:
        """Return a cached server-side ``SSLContext`` for the given ALPN list."""
        if alpn not in self._server_ctx_cache:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.ca_cert_path, self.ca_key_path)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if alpn:
                ctx.set_alpn_protocols(list(alpn))
            self._server_ctx_cache[alpn] = ctx
        return self._server_ctx_cache[alpn]

    def create_client_context(
        self, alpn: list[str] | None = None, verify: bool = True
    ) -> ssl.SSLContext:
        """Create a fresh client-side ``SSLContext`` for the target connection."""
        if verify:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if alpn:
            ctx.set_alpn_protocols(alpn)
        return ctx


# ============================================================================
# HTTP/2 Stream Tracking
# ============================================================================


class Http2Stream:
    """Maps a single HTTP/2 stream between the client and target sides.

    The proxy assigns its own stream IDs on the target connection
    (``target_id``) which differ from the browser's stream IDs
    (``client_id``).  This object tracks the mapping plus metadata
    needed for logging and interception.
    """

    __slots__ = (
        "client_id",
        "target_id",
        "authority",
        "path",
        "scheme",
        "created_at",
        "url",
    )

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
# HTTP/2 Stream Map — O(1) bidirectional lookup
# ============================================================================


class _StreamMap:
    """Bidirectional mapping between client stream IDs and ``Http2Stream`` objects.

    The proxy needs to look up streams by *client* ID (when the browser
    sends data) **and** by *target* ID (when the origin responds).  A
    naive ``dict[client_id, stream]`` requires an O(n) scan for the
    target→client direction on every event — a hot path under load.

    This class maintains two dicts for O(1) both ways, with a single
    ``len()`` and ``clear()``.
    """

    __slots__ = ("_by_client", "_by_target")

    def __init__(self) -> None:
        self._by_client: dict[int, Http2Stream] = {}
        self._by_target: dict[int, Http2Stream] = {}

    # -- mutators --

    def add(self, stream: Http2Stream) -> None:
        self._by_client[stream.client_id] = stream
        self._by_target[stream.target_id] = stream

    def remove_by_client(self, client_id: int) -> Optional[Http2Stream]:
        stream = self._by_client.pop(client_id, None)
        if stream is not None:
            self._by_target.pop(stream.target_id, None)
        return stream

    def remove_by_target(self, target_id: int) -> Optional[Http2Stream]:
        stream = self._by_target.pop(target_id, None)
        if stream is not None:
            self._by_client.pop(stream.client_id, None)
        return stream

    def clear(self) -> None:
        self._by_client.clear()
        self._by_target.clear()

    # -- lookups --

    def get_by_client(self, client_id: int) -> Optional[Http2Stream]:
        return self._by_client.get(client_id)

    def get_by_target(self, target_id: int) -> Optional[Http2Stream]:
        return self._by_target.get(target_id)

    # -- iteration --

    def values(self) -> list[Http2Stream]:
        """Return all streams (by client-side view)."""
        return list(self._by_client.values())

    def __len__(self) -> int:
        return len(self._by_client)


# ============================================================================
# Buffered Request Types
# ============================================================================


@dataclass
class BufferedH1Request:
    """A fully-read HTTP/1.x request, ready to be forwarded."""

    method: str
    path: str
    version: str
    headers: list[tuple[str, str]]
    body: bytes


class _TargetGoaway(Exception):
    """Raised when the target server sends an HTTP/2 GOAWAY frame."""

    __slots__ = ("last_stream_id", "error_code", "additional_data")

    def __init__(
        self, last_stream_id: int | None, error_code: int, additional_data: bytes
    ):
        self.last_stream_id = last_stream_id
        self.error_code = error_code
        self.additional_data = additional_data
        super().__init__(
            f"Target GOAWAY (last_stream={last_stream_id}, error={error_code})"
        )


class _ClientGoaway(Exception):
    """Raised when the browser sends an HTTP/2 GOAWAY frame."""

    __slots__ = ("last_stream_id", "error_code", "additional_data")

    def __init__(
        self, last_stream_id: int | None, error_code: int, additional_data: bytes
    ):
        self.last_stream_id = last_stream_id
        self.error_code = error_code
        self.additional_data = additional_data
        super().__init__(
            f"Client GOAWAY (last_stream={last_stream_id}, error={error_code})"
        )


# ============================================================================
# HTTP/1.1 Handler
# ============================================================================


class Http1Handler:
    """Forwards HTTP/1.x traffic between the browser and target.

    Handles keep-alive connection reuse, chunked transfer encoding,
    WebSocket upgrades (101 Switching Protocols), and response capture
    for the interception API.
    """

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

                url = f"{scheme}://{target_host}{path}"
                socks = self._proxy.socks_proxy
                logger.trace(
                    "[REQ] %s %s via %s", method, url, socks or "direct"
                )
                rule = self._proxy.rule
                modified = HeaderModifier.apply_rules(
                    headers, url, rule, is_h2=False
                )

                if not any(k.lower() == "host" for k, _ in modified):
                    modified.append(("Host", target_host))

                await self._send_request(
                    target, method, path, version, modified, body
                )
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
        buffered: BufferedH1Request,
        is_https: bool = True,
    ) -> None:
        """Forward a pre-read first request, then enter the keep-alive loop.

        Used when the proxy handler has already consumed the first
        request line + headers (e.g. to determine the target host for a
        plain-HTTP request).
        """
        scheme = "https" if is_https else "http"

        try:
            url = f"{scheme}://{target_host}{buffered.path}"
            socks = self._proxy.socks_proxy
            logger.trace(
                "[REQ] %s %s via %s", buffered.method, url, socks or "direct"
            )
            rule = self._proxy.rule
            modified = HeaderModifier.apply_rules(
                buffered.headers, url, rule, is_h2=False
            )

            if not any(k.lower() == "host" for k, _ in modified):
                modified.append(("Host", target_host))

            await self._send_request(
                target,
                buffered.method,
                buffered.path,
                buffered.version,
                modified,
                buffered.body,
            )
            target.touch()

            keep_alive, is_upgrade = await self._forward_response(
                target, client, url
            )
            client.touch()

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
                            content_length = int(v)
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
        capture = self._proxy._start_capture(url)

        async with asyncio.timeout(self.config.request_timeout):
            # -- status line --
            status_line = await source.reader.readline()
            if not status_line:
                return False, False
            dest.writer.write(status_line)

            status_parts = status_line.decode("utf-8", errors="replace").split(
                " ", 2
            )
            status_code = (
                int(status_parts[1]) if len(status_parts) >= 2 else 0
            )
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

                # -- Filter Alt-Svc: remove h3/QUIC entries --
                # We inspect the header *before* writing so we can
                # modify or suppress it.  Other headers are forwarded
                # verbatim.
                hl = header_raw.lower()
                if hl.startswith("alt-svc:"):
                    raw_val = header_raw.split(":", 1)[1].strip()
                    filtered = HeaderModifier.filter_alt_svc(raw_val)
                    if filtered is None:
                        # All entries were h3 — drop the header
                        continue
                    if filtered != raw_val:
                        # Rewrite the header with h3 entries removed
                        hdr_name = header_raw.split(":", 1)[0]
                        line = f"{hdr_name}: {filtered}\r\n".encode()

                dest.writer.write(line)

                if capture and ":" in header_raw:
                    hk, hv = header_raw.split(":", 1)
                    capture.headers.append((hk.strip(), hv.strip()))

                if hl.startswith("content-length:"):
                    content_length = int(hl.split(":", 1)[1].strip())
                elif hl.startswith("transfer-encoding:") and "chunked" in hl:
                    chunked = True
                elif hl.startswith("connection:"):
                    keep_alive = "keep-alive" in hl

            # -- 101 Switching Protocols (WebSocket etc.) --
            if is_upgrade:
                await dest.writer.drain()
                if capture:
                    self._proxy._deliver_capture(capture)
                return False, True

            # -- body: chunked transfer encoding --
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
                self._proxy._deliver_capture(capture)

            return keep_alive, False

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
            except (
                ConnectionResetError,
                BrokenPipeError,
                asyncio.CancelledError,
            ):
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
    """Bidirectional HTTP/2 multiplexing proxy.

    Sits between the browser's HTTP/2 connection and the target's
    HTTP/2 connection, forwarding frames in both directions.  Stream IDs
    are re-mapped because each side assigns its own IDs independently.

    Uses ``_StreamMap`` for O(1) bidirectional stream lookup (the
    previous implementation used an O(n) linear scan for target→client
    lookups on every event — a significant overhead with many concurrent
    streams).
    """

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
        streams: _StreamMap,
        captures: dict[int, _ResponseCapture],
    ) -> None:
        """Main HTTP/2 forwarding loop.

        Spawns two tasks (client→target, target→client) plus a
        stream-timeout reaper.  Runs until one side disconnects or
        sends GOAWAY.
        """
        logger.debug("[HTTP/2 %s] Handler started", target_host)
        timeout_task: Optional[asyncio.Task] = None

        try:
            client_task = asyncio.create_task(
                self._handle_client(
                    client,
                    target,
                    client_conn,
                    target_conn,
                    streams,
                    captures,
                    target_host,
                )
            )
            target_task = asyncio.create_task(
                self._handle_target(
                    client,
                    target,
                    client_conn,
                    target_conn,
                    streams,
                    captures,
                )
            )
            timeout_task = asyncio.create_task(
                self._check_stream_timeouts(
                    streams, client_conn, target_conn, client, target
                )
            )

            done, pending = await asyncio.wait(
                [client_task, target_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            goaway = False
            for t in done:
                exc = t.exception()
                if isinstance(exc, (_TargetGoaway, _ClientGoaway)):
                    goaway = True
                    logger.info(
                        "[HTTP/2 %s] GOAWAY teardown: %s",
                        target_host,
                        exc,
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
                await self._flush_both(
                    client, target, client_conn, target_conn
                )
                await client.close()
                await target.close()
                logger.info(
                    "[HTTP/2 %s] Handler destroyed after GOAWAY", target_host
                )

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(
                "[HTTP/2 %s] Error: %s\n%s",
                target_host,
                e,
                traceback.format_exc(),
            )
        finally:
            if timeout_task:
                timeout_task.cancel()
                try:
                    await timeout_task
                except asyncio.CancelledError:
                    pass
            logger.debug("[HTTP/2 %s] Handler stopped", target_host)

            # FIX: Deliver partial captures for in-flight streams so that
            # interceptors blocked on cap.get() are unblocked immediately
            # instead of hanging until their timeout.
            for cid, cap in list(captures.items()):
                if cap.status_code:
                    self._proxy._deliver_capture(cap)
            captures.clear()
            streams.clear()

    async def start_session(
        self,
        client: ManagedConnection,
        target: ManagedConnection,
        target_host: str,
    ) -> None:
        """Set up HTTP/2 connections on both sides and enter the handler loop.

        Performs the HTTP/2 connection preface exchange with both the
        browser and the target, then delegates to ``handle()``.
        """
        # validate_inbound_headers=False: some origins send non-standard
        # header values that h2 would otherwise reject.
        client_config = h2.config.H2Configuration(
            client_side=False, validate_inbound_headers=False
        )
        client_conn = h2.connection.H2Connection(config=client_config)
        client_conn.initiate_connection()
        client.writer.write(client_conn.data_to_send())
        await client.writer.drain()

        target_config = h2.config.H2Configuration(
            client_side=True, validate_inbound_headers=False
        )
        target_conn = h2.connection.H2Connection(config=target_config)
        target_conn.initiate_connection()

        streams = _StreamMap()
        captures: dict[int, _ResponseCapture] = {}

        self._proxy._track_h2_state(client_conn, target_conn, client, target)
        try:
            target.writer.write(target_conn.data_to_send())
            await target.writer.drain()

            # Read target's SETTINGS frame (connection preface)
            async with asyncio.timeout(5.0):
                data = await target.reader.read(self.config.read_buffer_size)
                if data:
                    target_conn.receive_data(data)
                    ack = target_conn.data_to_send()
                    if ack:
                        target.writer.write(ack)
                        await target.writer.drain()

            await self.handle(
                client,
                target,
                target_host,
                client_conn,
                target_conn,
                streams,
                captures,
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
            self._proxy._untrack_h2_state(
                client_conn, target_conn, client, target
            )
            streams.clear()
            captures.clear()

    # -- internal ----------------------------------------------------------

    async def _check_stream_timeouts(
        self,
        streams: _StreamMap,
        client_conn: h2.connection.H2Connection,
        target_conn: h2.connection.H2Connection,
        client: ManagedConnection,
        target: ManagedConnection,
    ) -> None:
        """Periodically RST_STREAM any streams that have exceeded the timeout."""
        try:
            while True:
                await asyncio.sleep(30)
                now = time.monotonic()
                timed_out = [
                    s
                    for s in streams.values()
                    if now - s.created_at > self.config.stream_timeout
                ]
                for s in timed_out:
                    try:
                        client_conn.reset_stream(s.client_id, error_code=8)
                        target_conn.reset_stream(s.target_id, error_code=8)
                    except Exception:
                        pass
                    streams.remove_by_client(s.client_id)
                if timed_out:
                    await self._flush_both(
                        client, target, client_conn, target_conn
                    )
        except asyncio.CancelledError:
            pass

    async def _handle_client(
        self,
        client: ManagedConnection,
        target: ManagedConnection,
        client_conn: h2.connection.H2Connection,
        target_conn: h2.connection.H2Connection,
        streams: _StreamMap,
        captures: dict[int, _ResponseCapture],
        target_host: str,
    ) -> None:
        """Read loop for the browser side: forwards requests to the target."""
        while not client.closed:
            try:
                async with asyncio.timeout(self.config.idle_timeout):
                    data = await client.reader.read(
                        self.config.read_buffer_size
                    )
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
                    event,
                    client_conn,
                    target_conn,
                    streams,
                    captures,
                    target_host,
                )

            await self._flush_both(client, target, client_conn, target_conn)

    async def _handle_target(
        self,
        client: ManagedConnection,
        target: ManagedConnection,
        client_conn: h2.connection.H2Connection,
        target_conn: h2.connection.H2Connection,
        streams: _StreamMap,
        captures: dict[int, _ResponseCapture],
    ) -> None:
        """Read loop for the target side: forwards responses to the browser."""
        while not target.closed:
            try:
                async with asyncio.timeout(self.config.idle_timeout):
                    data = await target.reader.read(
                        self.config.read_buffer_size
                    )
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
                    event,
                    client_conn,
                    target_conn,
                    streams,
                    captures,
                )

            await self._flush_both(client, target, client_conn, target_conn)

    async def _flush_both(
        self,
        client: ManagedConnection,
        target: ManagedConnection,
        client_conn: h2.connection.H2Connection,
        target_conn: h2.connection.H2Connection,
    ) -> None:
        """Send any pending h2 frame data to both sides."""
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
        streams: _StreamMap,
        captures: dict[int, _ResponseCapture],
        target_host: str,
    ) -> None:
        """Handle a single h2 event from the browser side."""

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
            logger.trace(
                "[REQ] %s %s via %s (h2 stream %d)",
                method,
                url,
                socks or "direct",
                cid,
            )
            rule = self._proxy.rule
            modified = HeaderModifier.apply_rules(
                headers, url, rule, is_h2=True
            )

            tid = target_conn.get_next_available_stream_id()
            stream = Http2Stream(
                client_id=cid,
                target_id=tid,
                authority=authority,
                path=path,
                scheme=scheme,
                created_at=time.monotonic(),
            )
            streams.add(stream)

            # Start capture if URL is being intercepted
            cap = self._proxy._start_capture(url)
            if cap:
                captures[cid] = cap

            end_stream = event.stream_ended is not None
            target_conn.send_headers(tid, modified, end_stream=end_stream)

        elif isinstance(event, h2.events.DataReceived):
            stream = streams.get_by_client(event.stream_id)
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
            stream = streams.remove_by_client(event.stream_id)
            captures.pop(event.stream_id, None)
            if stream:
                try:
                    target_conn.reset_stream(
                        stream.target_id, event.error_code
                    )
                except Exception:
                    pass

        elif isinstance(event, h2.events.ConnectionTerminated):
            last_id = getattr(event, "last_stream_id", None)
            error_code = getattr(event, "error_code", 0)
            additional = getattr(event, "additional_data", b"")
            logger.info(
                "[GOAWAY] Client sent GOAWAY (last_stream=%s, error=%s, data=%s) — "
                "tearing down handler (%d active streams)",
                last_id,
                error_code,
                additional,
                len(streams),
            )

            # Deliver any in-flight captures before cleanup
            for cid, cap in list(captures.items()):
                if cap.status_code:
                    self._proxy._deliver_capture(cap)
            captures.clear()

            # Reset all active streams on the target side
            for stream in streams.values():
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
        streams: _StreamMap,
        captures: dict[int, _ResponseCapture],
    ) -> None:
        """Handle a single h2 event from the target side.

        Uses ``streams.get_by_target()`` for O(1) lookup instead of the
        previous O(n) linear scan.
        """

        if isinstance(event, h2.events.ResponseReceived):
            stream = streams.get_by_target(event.stream_id)
            if stream:
                # Filter h3/QUIC entries from Alt-Svc headers so the
                # browser never discovers HTTP/3 (which we can't MITM).
                filtered_headers = HeaderModifier.filter_response_headers(
                    event.headers
                )
                client_conn.send_headers(
                    stream.client_id,
                    filtered_headers,
                    end_stream=event.stream_ended is not None,
                )
                cap = captures.get(stream.client_id)
                if cap:
                    for k, v in filtered_headers:
                        key = (
                            k.decode("utf-8") if isinstance(k, bytes) else k
                        )
                        val = (
                            v.decode("utf-8") if isinstance(v, bytes) else v
                        )
                        if key == ":status":
                            cap.status_code = int(val)
                        else:
                            cap.headers.append((key, val))

        elif isinstance(event, h2.events.DataReceived):
            stream = streams.get_by_target(event.stream_id)
            if stream:
                target_conn.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
                end = event.stream_ended is not None
                client_conn.send_data(
                    stream.client_id, event.data, end_stream=end
                )
                cap = captures.get(stream.client_id)
                if cap:
                    cap.body.extend(event.data)
                if end:
                    cap = captures.pop(stream.client_id, None)
                    if cap:
                        self._proxy._deliver_capture(cap)
                    streams.remove_by_client(stream.client_id)

        elif isinstance(event, h2.events.StreamEnded):
            stream = streams.get_by_target(event.stream_id)
            if stream:
                try:
                    client_conn.end_stream(stream.client_id)
                except Exception:
                    pass
                cap = captures.pop(stream.client_id, None)
                if cap:
                    self._proxy._deliver_capture(cap)
                streams.remove_by_client(stream.client_id)

        elif isinstance(event, h2.events.StreamReset):
            stream = streams.get_by_target(event.stream_id)
            if stream:
                try:
                    client_conn.reset_stream(
                        stream.client_id, event.error_code
                    )
                except Exception:
                    pass
                captures.pop(stream.client_id, None)
                streams.remove_by_client(stream.client_id)

        elif isinstance(event, h2.events.TrailersReceived):
            stream = streams.get_by_target(event.stream_id)
            if stream:
                client_conn.send_headers(
                    stream.client_id, event.headers, end_stream=True
                )
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
                last_id,
                error_code,
                additional,
                len(streams),
            )

            # Deliver any in-flight captures before cleanup
            for cid, cap in list(captures.items()):
                if cap.status_code:
                    self._proxy._deliver_capture(cap)
            captures.clear()

            # Reset all active streams on the client side
            for stream in streams.values():
                try:
                    client_conn.reset_stream(stream.client_id, error_code=2)
                except Exception:
                    pass
            streams.clear()

            # Forward GOAWAY to the browser
            try:
                client_conn.close_connection(error_code=0)
            except Exception:
                pass

            raise _TargetGoaway(last_id, error_code, additional)


# ============================================================================
# Core Proxy Handler (single-session, no multiplexing)
# ============================================================================


class _ProxyHandler:
    """Accepts individual browser connections and dispatches them.

    Plain HTTP requests are forwarded directly.  CONNECT tunnels are
    intercepted with a MITM TLS handshake so traffic can be inspected.
    """

    __slots__ = ("_proxy", "tls", "http1", "http2", "config")

    def __init__(
        self, proxy: SessionProxy, tls: TLSInterceptor, config: ProxyConfig
    ):
        self._proxy = proxy
        self.tls = tls
        self.config = config
        self.http1 = Http1Handler(proxy, config)
        self.http2 = Http2Handler(proxy, config)

    async def handle_client(
        self, reader: StreamReader, writer: StreamWriter
    ) -> None:
        """Entry point for each new browser connection (called by ``asyncio.Server``)."""
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
                        elif (
                            kl == "transfer-encoding"
                            and "chunked" in vs.lower()
                        ):
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
                    client,
                    method,
                    target_url,
                    version,
                    raw_headers,
                    body,
                    headers,
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
            logger.trace(
                "[REQ] %s http://%s%s via %s",
                method,
                display_host,
                path,
                socks or "direct",
            )

            buffered = BufferedH1Request(
                method=method,
                path=path,
                version=version,
                headers=raw_headers,
                body=body,
            )
            await self.http1.handle_with_buffered(
                client, target, display_host, buffered, is_https=False
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
            port = int(port_str)
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
            client.writer.transport.pause_reading()

            # Step 2: Connect to target, learn its protocol
            if self._proxy.sidecar:
                target_tls, target_protocol = (
                    await self._connect_via_sidecar(host, port)
                )
                self._proxy._track_connection(target_tls)
            else:
                target = await self._connect_to_target(host, port)
                self._proxy._track_connection(target)

                target_tls, target_protocol = (
                    await self._negotiate_target_tls(target, host)
                )
                self._proxy._track_connection(target_tls)

            # Step 3: Browser MITM TLS with matching protocol
            if target_protocol == Protocol.HTTP2:
                browser_alpn = ("h2", "http/1.1")
            else:
                browser_alpn = ("http/1.1",)

            protocol, client_tls = await self._negotiate_client_tls(
                client, host, alpn=browser_alpn
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

        sc_host, sc_port_str = sidecar_addr.rsplit(":", 1)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(sc_host, int(sc_port_str)),
            timeout=5.0,
        )

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
                await writer.wait_closed()
            except Exception:
                pass
            raise

    # -- TLS ---------------------------------------------------------------

    async def _negotiate_client_tls(
        self,
        client: ManagedConnection,
        hostname: str,
        alpn: tuple[str, ...] = ("h2", "http/1.1"),
    ) -> tuple[Protocol, ManagedConnection]:
        """Perform the browser-side MITM TLS handshake.

        Uses ``loop.start_tls()`` to upgrade the existing plaintext
        transport to TLS.  The ALPN offered to the browser is restricted
        to what the target actually supports (determined beforehand).
        """
        loop = asyncio.get_event_loop()
        ctx = self.tls.get_server_context(alpn)

        transport = client.writer.transport
        proto_obj = transport.get_protocol()

        async with asyncio.timeout(self.config.connect_timeout):
            ssl_transport = await loop.start_tls(
                transport, proto_obj, ctx, server_side=True
            )

        if ssl_transport is None:
            raise ConnectionError("Client TLS handshake failed")

        ssl_obj = ssl_transport.get_extra_info("ssl_object")
        negotiated_alpn = (
            ssl_obj.selected_alpn_protocol() if ssl_obj else None
        )
        protocol = (
            Protocol.HTTP2 if negotiated_alpn == "h2" else Protocol.HTTP1
        )

        tls_reader = StreamReader()
        tls_proto = asyncio.StreamReaderProtocol(tls_reader)
        ssl_transport.set_protocol(tls_proto)
        tls_proto.connection_made(ssl_transport)
        tls_writer = StreamWriter(ssl_transport, tls_proto, tls_reader, loop)

        return protocol, ManagedConnection(tls_reader, tls_writer)

    async def _negotiate_target_tls(
        self,
        target: ManagedConnection,
        hostname: str,
    ) -> tuple[ManagedConnection, Protocol]:
        """TLS handshake with the target, offering both h2 and http/1.1.

        Returns the wrapped connection and whichever protocol the server
        actually negotiated.
        """
        loop = asyncio.get_event_loop()
        ctx = self.tls.create_client_context(
            alpn=["h2", "http/1.1"], verify=self.config.verify_ssl
        )

        transport = target.writer.transport
        proto_obj = transport.get_protocol()

        async with asyncio.timeout(self.config.connect_timeout):
            ssl_transport = await loop.start_tls(
                transport,
                proto_obj,
                ctx,
                server_side=False,
                server_hostname=hostname,
            )

        if ssl_transport is None:
            raise ConnectionError("Target TLS handshake failed")

        ssl_obj = ssl_transport.get_extra_info("ssl_object")
        negotiated = (
            ssl_obj.selected_alpn_protocol() if ssl_obj else None
        )
        target_protocol = (
            Protocol.HTTP2 if negotiated == "h2" else Protocol.HTTP1
        )

        tls_reader = StreamReader()
        tls_proto = asyncio.StreamReaderProtocol(tls_reader)
        ssl_transport.set_protocol(tls_proto)
        tls_proto.connection_made(ssl_transport)
        tls_writer = StreamWriter(ssl_transport, tls_proto, tls_reader, loop)

        return ManagedConnection(tls_reader, tls_writer), target_protocol

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

    async def _read_chunked_body(self, reader: StreamReader) -> bytes:
        """Read a chunked-encoded request body."""
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
    * Header modification rules
    * Async response interception for specific URLs

    Usage::

        pool = SocksProxyPool("proxies.txt")

        proxy = SessionProxy(
            ca_cert="certs/ca.pem",
            ca_key="certs/ca.key",
            socks_pool=pool,
        )
        port = await proxy.start()

        # configure browser: --proxy-server=127.0.0.1:{port}

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
        socks_proxy: Optional[str] = None,
        host: str = "127.0.0.1",
        port: int = 0,
        config: ProxyConfig = DEFAULT_CONFIG,
        sidecar: Optional[SidecarManager] = None,
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
        self._active_h2_states: list[
            tuple[
                h2.connection.H2Connection,  # client h2 conn
                h2.connection.H2Connection,  # target h2 conn
                ManagedConnection,  # client
                ManagedConnection,  # target
            ]
        ] = []

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> int:
        """Start listening.  Returns the bound port number."""
        self._handler = _ProxyHandler(self, self._tls, self.config)
        self._server = await asyncio.start_server(
            self._handler.handle_client,
            self.host,
            self.port,
            reuse_address=True,
        )
        # Suppress noisy asyncio SSL exceptions that occur when the browser
        # resets a connection before the TLS shutdown completes.
        loop = asyncio.get_running_loop()
        _default_handler = loop.get_exception_handler()

        def _quiet_exception_handler(
            loop: asyncio.AbstractEventLoop, context: dict
        ) -> None:
            msg = context.get("message", "")
            exc = context.get("exception")

            if exc and "SSL" in type(exc).__name__:
                logger.debug("asyncio SSL exception (suppressed): %s", exc)
                return
            if isinstance(msg, str) and "ssl" in msg.lower():
                logger.debug("asyncio SSL message (suppressed): %s", msg)
                return

            if _default_handler:
                _default_handler(loop, context)
            else:
                loop.default_exception_handler(context)

        loop.set_exception_handler(_quiet_exception_handler)

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
        """Stop accepting new connections and close all active ones."""
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

    def get_proxy(self) -> Optional[str]:
        """Return the currently assigned SOCKS proxy address."""
        return self.socks_proxy

    # -- header rules ------------------------------------------------------

    def set_rule(self, urls: set[str], headers: list[tuple[str, str]]) -> None:
        """Set a header-modification rule (replaces any previous rule).

        When a request URL matches one of *urls*, the given *headers*
        are merged into the outgoing request headers.
        """
        self.rule = Rule.create(urls, headers)

    def clear_rule(self) -> None:
        """Remove any active header-modification rule."""
        self.rule = None

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
        for client_h2, target_h2, client_mc, target_mc in h2_states:
            try:
                client_h2.close_connection(error_code=0)
                data = client_h2.data_to_send()
                if data and not client_mc.closed:
                    client_mc.writer.write(data)
                    await asyncio.wait_for(
                        client_mc.writer.drain(), timeout=2.0
                    )
            except Exception:
                pass
            try:
                target_h2.close_connection(error_code=0)
                data = target_h2.data_to_send()
                if data and not target_mc.closed:
                    target_mc.writer.write(data)
                    await asyncio.wait_for(
                        target_mc.writer.drain(), timeout=2.0
                    )
            except Exception:
                pass

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

    def _track_h2_state(self, client_conn, target_conn, client, target):
        self._active_h2_states.append(
            (client_conn, target_conn, client, target)
        )

    def _untrack_h2_state(self, client_conn, target_conn, client, target):
        try:
            self._active_h2_states.remove(
                (client_conn, target_conn, client, target)
            )
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
