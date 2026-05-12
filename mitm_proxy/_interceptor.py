"""Response interception API: capture HTTP responses for URLs of interest.

The user-facing surface is :class:`RequestInterceptor`, returned from
``SessionProxy.intercept(urls)`` and used as an async context manager.
While the context is active, the proxy's policy layer calls
``open_capture(url)`` on each request and ``deliver_capture(capture)``
when the response completes; if any registered interceptor's pattern
matches, the response is queued and any awaiting ``get()``/``all()``/
``async for`` resumes.

The capture pipeline:

* :class:`_ResponseCapture` — internal mutable accumulator threaded
  through the protocol handlers as headers/body bytes arrive.
* :func:`_decompress_body` — gzip/br/deflate/zstd handling, called
  once at finalise time.
* :class:`InterceptedResponse` — the immutable, decompressed snapshot
  delivered to the caller.

Cross-thread delivery
~~~~~~~~~~~~~~~~~~~~~
The proxy may run on a different event loop than the caller of
``intercept()``.  Delivery uses ``call_soon_threadsafe`` to resolve
the future and enqueue the response on the *caller's* loop.
"""

from __future__ import annotations

import asyncio
import fnmatch
import gzip
import time
import weakref
import zlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, AsyncIterator, Optional

from ._common import logger

if TYPE_CHECKING:
    from .session import SessionProxy


# -- optional decompression backends -----------------------------------------

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
            except ImportError:
                raise RuntimeError(
                    "Zstandard-compressed response received but 'zstandard' "
                    "package is not installed. Install it with: pip install zstandard"
                )
            reader = zstandard.ZstdDecompressor().stream_reader(data)
            chunks = []
            while True:
                chunk = reader.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
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
        "_proxy_ref",
        "_caller_loop",
        "_entered",
    )

    def __init__(self, patterns: list[str], proxy: SessionProxy) -> None:
        self._patterns = list(patterns)
        # weakref.ref: while we're registered the proxy holds a strong
        # reference to us via ``proxy._interceptors``, so the proxy
        # outlives us during the ``async with`` block.  After unregister,
        # the user may keep the interceptor object around; we don't
        # need (and shouldn't) keep the proxy alive on their behalf.
        # ``weakref.ref`` (rather than ``weakref.proxy``) makes the
        # dereference explicit — every callable site checks for None
        # instead of catching ReferenceError after the fact.
        self._proxy_ref: weakref.ref[SessionProxy] = weakref.ref(proxy)
        self._entered = False
        self._caller_loop: Optional[asyncio.AbstractEventLoop] = None

        # Split into exact and glob patterns for fast matching
        self._exact_urls: set[str] = set()
        self._glob_patterns: list[str] = []
        for p in patterns:
            if "*" in p:# or "?" in p:
                self._glob_patterns.append(p)
            else:
                self._exact_urls.add(p)

        self._futures: dict[str, asyncio.Future[InterceptedResponse]] = {}
        # Bounded queue for the async-iter consumption pattern.  If the
        # consumer never iterates (uses get()/all() only), responses
        # would otherwise pile up forever on long-running sessions with
        # permissive glob patterns matching many URLs.  When full, we
        # drop the *oldest* response to bound memory.
        self._queue: asyncio.Queue[InterceptedResponse] = asyncio.Queue(
            maxsize=1024
        )
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
            try:
                self._queue.put_nowait(response)
            except asyncio.QueueFull:
                # Drop the oldest response to make room for the newest.
                # This keeps memory bounded if the consumer never iterates.
                try:
                    self._queue.get_nowait()
                    self._queue.put_nowait(response)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass

        try:
            loop.call_soon_threadsafe(_resolve)
        except RuntimeError:
            # Loop closed between our is_closed() check above and now.
            # Race is benign: the caller is no longer waiting.
            pass

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
        proxy = self._proxy_ref()
        if proxy is None:
            raise RuntimeError(
                "SessionProxy was destroyed before interceptor entry"
            )
        self._caller_loop = asyncio.get_running_loop()
        for p in self._patterns:
            self._futures[p] = self._caller_loop.create_future()
        proxy._register_interceptor(self)
        self._entered = True
        return self

    async def __aexit__(self, *exc: object) -> None:
        # If the SessionProxy was destroyed before us (unusual but
        # possible if the user dropped their proxy reference before
        # exiting the ``async with`` block), the weakref returns None.
        # That's fine — the proxy is gone, so unregistering is a no-op
        # anyway.
        proxy = self._proxy_ref()
        if proxy is not None:
            proxy._unregister_interceptor(self)
        for fut in self._futures.values():
            if not fut.done():
                fut.cancel()
        self._entered = False
        self._caller_loop = None
