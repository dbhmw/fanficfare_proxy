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
import socket
import time
import weakref
import zlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, AsyncIterator, ClassVar, Optional

from ._common import logger

if TYPE_CHECKING:
    from ._policy import ResponseHeaders
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


# Sentinel pushed onto a RequestInterceptor's queue when its context
# manager exits, so a blocked ``async for`` terminates cleanly instead of
# hanging.  A module-level unique object (never a real InterceptedResponse).
_ITER_DONE: object = object()


@dataclass(frozen=True)
class ProxyError:
    """Reason a proxy-synthesised response was delivered instead of a real one.

    Populated on :attr:`InterceptedResponse.error` only when the proxy
    *synthesised* the response in place of a real upstream reply —
    currently CONNECT-time failures (unreachable target, timeout, refused
    connection, DNS failure, SOCKS5/sidecar problem).  Real upstream
    responses have ``error=None``, **including real upstream 502s**:
    status code alone can't tell you whether a 502 came from the target
    or from this proxy; ``error is not None`` is the signal.

    The ``code`` is a short stable identifier — match against the class
    constants for type-safe branching::

        if resp.error and resp.error.code == ProxyError.TIMED_OUT:
            schedule_retry()
        elif resp.error and resp.error.code == ProxyError.NAME_NOT_RESOLVED:
            give_up()

    The ``message`` field is the full original exception text, useful for
    logging.  The same text is also embedded in ``raw_body`` so HTTP
    clients reading the synthetic response body see it too.

    Classification
    ~~~~~~~~~~~~~~
    :meth:`from_exception` classifies first by exception type
    (``TimeoutError``, ``ConnectionRefusedError``, ``socket.gaierror``)
    and falls back to message-substring matching for sidecar-wrapped
    errors — the SOCKS5 sidecar flattens real network errors into
    ``OSError`` with the original cause embedded in the message string,
    so the type alone isn't enough.
    """

    # Stable identifiers; match with ``resp.error.code == ProxyError.X``.
    TIMED_OUT: ClassVar[str] = "TIMED_OUT"
    CONNECTION_REFUSED: ClassVar[str] = "CONNECTION_REFUSED"
    NAME_NOT_RESOLVED: ClassVar[str] = "NAME_NOT_RESOLVED"
    PROXY_UNREACHABLE: ClassVar[str] = "PROXY_UNREACHABLE"
    TUNNEL_FAILED: ClassVar[str] = "TUNNEL_FAILED"
    TTL_EXPIRED: ClassVar[str] = "TTL_EXPIRED"

    code: str
    message: str

    @classmethod
    def from_exception(cls, exc: BaseException) -> ProxyError:
        """Build a ProxyError from *exc*, classifying its code.

        ``message`` captures ``str(exc)`` verbatim (or the exception's
        class name when ``str(exc)`` is empty, e.g. bare ``TimeoutError``).
        """
        return cls(
            code=cls._classify(exc),
            message=str(exc) or exc.__class__.__name__,
        )

    @staticmethod
    def _classify(exc: BaseException) -> str:
        # Type-based classification first — reliable, no string parsing.
        # ``asyncio.TimeoutError`` aliases ``TimeoutError`` on 3.11+, so
        # the single isinstance check catches both.
        if isinstance(exc, TimeoutError):
            return ProxyError.TIMED_OUT
        if isinstance(exc, ConnectionRefusedError):
            return ProxyError.CONNECTION_REFUSED
        if isinstance(exc, socket.gaierror):
            return ProxyError.NAME_NOT_RESOLVED

        # Fall back to message-substring matching.  The SOCKS5 sidecar
        # returns "socks5 connect read: ... i/o timeout" as a plain
        # OSError — the underlying TimeoutError never reaches us — so
        # we have to read the message to recover the cause.  Order
        # matters: check the most specific tokens first.
        logger.debug(type(exc))
        msg = str(exc).lower()
        if "ttl expired" in msg:
            return ProxyError.TTL_EXPIRED
        if "timeout" in msg or "timed out" in msg:
            return ProxyError.TIMED_OUT
        if "refused" in msg:
            return ProxyError.CONNECTION_REFUSED
        if (
            "no such host" in msg
            or "name resolution" in msg
            or "name or service not known" in msg
        ):
            return ProxyError.NAME_NOT_RESOLVED
        if "socks" in msg or "sidecar" in msg or "proxy" in msg:
            return ProxyError.PROXY_UNREACHABLE

        return ProxyError.TUNNEL_FAILED


@dataclass
class InterceptedResponse:
    """A captured HTTP response whose body is decompressed on access.

    ``body`` returns the decompressed payload (gzip, br, deflate, zstd);
    ``content_encoding`` preserves the original encoding for reference.

    Lazy decompression
    ~~~~~~~~~~~~~~~~~~~
    The bytes are stored compressed and decompressed on *first access to
    ``body``*, then cached.  This matters because captures are finalised
    on the proxy's event-loop thread, but ``body`` is read by the
    consumer on *their* thread — so decompressing a large (multi-MB)
    response no longer stalls the proxy loop (and every other connection
    on it) for the duration.  Reading ``status_code``/``headers`` never
    triggers decompression.

    ``raw_body`` exposes the undecoded bytes if a caller needs them.

    Byte-faithful headers
    ~~~~~~~~~~~~~~~~~~~~~
    ``headers`` is a :class:`ResponseHeaders` view over the raw ``(name,
    value)`` **byte** pairs exactly as seen on the wire (h2 names are
    lowercase per spec; h1 names keep their original casing).  The same
    class the policy layer uses, so a consumer gets ergonomic access
    without re-decoding every header in a loop::

        # Case-insensitive lookup, bytes or str:
        loc = resp.headers.get("location")          # -> bytes | None
        if "location" in resp.headers:
            ...
        cookies = resp.headers.get_all("set-cookie")  # multi-value safe

        # Iteration still yields raw byte pairs (regular headers only;
        # status is on resp.status_code / resp.headers.status):
        for name, value in resp.headers:
            print(name.decode("latin1"), value.decode("latin1"))

    The view reflects the **original** wire response (a snapshot taken
    before any policy ``transform_response_headers`` runs), and is an
    independent instance from the one the policy receives, so a policy
    rewrite never bleeds into capture.

    Proxy-synthesised failures
    ~~~~~~~~~~~~~~~~~~~~~~~~~~
    If the proxy could not deliver a real upstream response (CONNECT
    timed out, target refused, DNS failed, etc.) it synthesises a 502
    with the failure detail on :attr:`error` — a :class:`ProxyError`
    carrying a stable code (``ProxyError.TIMED_OUT`` etc.) and the full
    original exception message.  For every real upstream response,
    ``error`` is ``None`` — including real upstream 502s, so checking
    ``error is not None`` distinguishes "proxy couldn't reach the target"
    from "the target returned a 502".
    """

    url: str
    status_code: int
    headers: ResponseHeaders
    raw_body: bytes = field(repr=False)
    content_type: str
    content_encoding: str
    error: Optional[ProxyError] = None
    timestamp: float = field(default_factory=time.monotonic)
    _decoded: Optional[bytes] = field(
        default=None, init=False, repr=False, compare=False
    )

    @property
    def body(self) -> bytes:
        """Decompressed body. Decoded lazily on first access and cached.

        Runs on the calling thread, not the proxy loop. Idempotent: a
        concurrent double-decode (two threads racing first access) is
        harmless — both produce identical bytes, last write wins.
        """
        if self._decoded is None:
            self._decoded = _decompress_body(self.raw_body, self.content_encoding)
        return self._decoded


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
    headers: list[tuple[bytes, bytes]] = field(default_factory=list)
    body: bytearray = field(default_factory=bytearray)

    def finalise(self) -> InterceptedResponse:
        # Runtime import (not module-level) to break the import cycle
        # with _policy, which imports _ResponseCapture from us.  Python
        # caches the module after the first call, so this is effectively
        # free on subsequent finalises.
        from ._policy import ResponseHeaders

        # Build a fresh ResponseHeaders view over the accumulated raw
        # pairs.  This is an independent instance — the policy receives
        # its own ResponseHeaders elsewhere, and the two never share
        # state, so a policy rewrite that runs after capture started
        # cannot reach in here.
        #
        # ``status_code`` was set by the handler from the wire (h1 status
        # line / h2 :status); we mirror it onto the view's typed field
        # so consumers can read either ``resp.status_code`` or
        # ``resp.headers.status``.
        headers = ResponseHeaders(self.headers, status=self.status_code or None)

        # Two headers we read locally: content-type is echoed on the
        # public object, content-encoding drives body decompression.
        # Decode with latin1 — lossless and ASCII-safe for header tokens.
        ct = headers.get(b"content-type")
        ce = headers.get(b"content-encoding")
        content_type = ct.decode("latin1") if ct else ""
        content_encoding = ce.decode("latin1") if ce else ""

        # Store the raw (still-compressed) bytes; decompression is
        # deferred to InterceptedResponse.body so it runs on the
        # consumer's thread, not the proxy loop.  finalise() itself runs
        # on the loop, so it must stay cheap.
        return InterceptedResponse(
            url=self.url,
            status_code=self.status_code,
            headers=headers,
            raw_body=bytes(self.body),
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

        # 3. Async-iterate as responses arrive (runs until the `async with`
        #    block exits, so break when you have what you need)
        async with proxy.intercept(urls) as cap:
            driver.get(page)
            async for resp in cap:
                print(resp.url, resp.status_code)
                if resp.url == last_one:
                    break

    URL matching
    ~~~~~~~~~~~~
    Exact string match by default.  Patterns containing ``*`` use
    :func:`fnmatch.fnmatch`-style globbing, e.g.
    ``"https://api.example.com/v1/*"`` matches any sub-path.  ``?`` is
    *not* treated as a wildcard here (unlike plain ``fnmatch``) because
    it occurs literally in query strings; only ``*`` switches a pattern
    into glob mode.
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
        "_closed",
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
        # drop the *oldest* response to bound memory.  Holds either an
        # InterceptedResponse or the ``_ITER_DONE`` sentinel that wakes a
        # blocked iterator when the context manager exits.
        self._queue: asyncio.Queue[object] = asyncio.Queue(maxsize=1024)
        self._remaining = len(patterns)
        # Set in __aexit__ so a blocked ``async for`` terminates instead of
        # hanging, and so late deliveries after the context exits are dropped.
        self._closed = False

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
            # The context manager may have exited between the cross-thread
            # schedule and now; drop late deliveries rather than resolving
            # a stale future or pushing onto a queue no one is reading.
            if self._closed:
                return
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
        """Yield captured responses as they arrive.

        Runs until the interceptor's ``async with`` block exits (which
        pushes a close sentinel that ends the loop) or the consumer
        ``break``s.  Every response that matches *any* registered pattern
        is yielded — including repeated matches of a glob pattern — so a
        single ``"https://api/*"`` pattern surfaces every matching URL.

        (The previous implementation stopped after ``len(patterns)`` items,
        which under-counted when a glob matched many URLs and hung forever
        when a pattern never matched.)
        """
        while True:
            item = await self._queue.get()
            if item is _ITER_DONE:
                return
            yield item  # type: ignore[misc]  # never the sentinel here

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
        # Mark closed first so any in-flight cross-thread delivery is
        # dropped rather than racing the teardown below.
        self._closed = True
        for fut in self._futures.values():
            if not fut.done():
                fut.cancel()
        # Wake an iterator blocked on the queue so ``async for`` ends
        # instead of hanging.  Runs on the caller loop (same loop the
        # queue lives on), so put_nowait is safe here.
        try:
            self._queue.put_nowait(_ITER_DONE)
        except asyncio.QueueFull:
            try:
                self._queue.get_nowait()
                self._queue.put_nowait(_ITER_DONE)
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass
        self._entered = False
        self._caller_loop = None
