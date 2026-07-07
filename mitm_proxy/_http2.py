"""HTTP/2 bidirectional forwarding handler.

Sits between the browser's HTTP/2 connection and the target's
HTTP/2 connection, multiplexing streams in both directions.  Stream
IDs are translated because each side assigns its own IDs.

Major pieces:

* Module-level h2 patch (``_relax_h2_goaway_state``) — applied at
  import time, lets the proxy keep streams alive after a GOAWAY as
  RFC 9113 §6.8 permits but the ``h2`` library does not by default.
* ``Http2Stream`` / ``_StreamMap`` — bidirectional ID mapping with
  O(1) lookup either way.
* ``Http2Handler`` — the main handler.  Spawns three concurrent
  tasks (client-side pump, target-side pump, stream-timeout reaper)
  and translates events between the two sides.

The handler depends on ``_io`` (transport), ``_interceptor`` (capture
buffers), and ``_policy`` (header transformation, capture lifecycle).
It does not depend on ``_http1``.
"""

from __future__ import annotations

import asyncio
import time
import traceback
from typing import TYPE_CHECKING, Optional

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions
import h2.settings
from hyperframe.frame import Frame as _HF_Frame
from hyperframe.exceptions import UnknownFrameError as _HF_UnknownFrameError

from ._common import logger, ProxyConfig, DEFAULT_CONFIG
from ._interceptor import _ResponseCapture
from ._io import ManagedConnection
from ._policy import RequestHeaders, ResponseHeaders

if TYPE_CHECKING:
    from .session import SessionProxy


# ── Patch h2 to allow streams below last_stream_id to continue after GOAWAY.
# RFC 9113 §6.8 explicitly permits this; h2's state machine does not
# (https://github.com/python-hyper/h2/issues/1181, open since 2019).
# Without this patch, servers that send GOAWAY before their final response
# frames trigger ProtocolError mid-response.
from h2.connection import (
    H2ConnectionStateMachine,
    ConnectionState,
    ConnectionInputs,
)


def _relax_h2_goaway_state() -> None:
    transitions = H2ConnectionStateMachine._transitions
    for open_state in (ConnectionState.CLIENT_OPEN, ConnectionState.SERVER_OPEN):
        for input_ in (ConnectionInputs.RECV_GOAWAY, ConnectionInputs.SEND_GOAWAY):
            key = (open_state, input_)
            if key in transitions:
                func, _old_target = transitions[key]
                transitions[key] = (func, open_state)  # stay open instead of CLOSED


_relax_h2_goaway_state()


# ── Tuning constants ────────────────────────────────────────────────────────

# Chrome bumps the HTTP/2 connection-level receive window to 15 MiB right
# after the preface (the spec default is 65535).  We advertise the same
# increment on the browser-facing connection so our flow-control posture
# matches Chrome's and large downloads aren't throttled by a tiny window.
# 15 MiB total − 65535 default = 15663105.
_BROWSER_FACING_RECV_WINDOW_INCREMENT = 15 * 1024 * 1024 - 65535  # 15663105

# h2 reports a sentinel of 2**32+1 for MAX_CONCURRENT_STREAMS when the peer
# never advertised one.  Treat any value below this threshold as a genuine
# per-peer limit (and mirror it as-is); at or above it, assume "unset" and
# fall back to Chrome's customary advertised value.  2**31 sits safely above
# any realistic real limit and well below the sentinel.
_H2_UNSET_CONCURRENT_STREAMS_THRESHOLD = 1 << 31
# Chrome advertises MAX_CONCURRENT_STREAMS=100; use the same when the target
# didn't specify a limit of its own.
_DEFAULT_MAX_CONCURRENT_STREAMS = 100


def _b2(value: object) -> bytes:
    """Coerce an h2 header name/value to ``bytes`` (latin1 for str).

    h2 yields bytes on the wire, but a policy could hand back str; this
    keeps the Headers views uniformly byte-backed without assuming type.
    """
    if isinstance(value, bytes):
        return value
    return value.encode("latin1")  # type: ignore[union-attr]


# Connection-level headers HTTP/2 forbids in a HEADERS frame (RFC 9113
# §8.2.2).  Enforced by the handler at serialise time — a framing rule, not
# policy hygiene.  Bytes, since h2 header names are bytes on the wire.
_H2_FORBIDDEN: frozenset[bytes] = frozenset(
    {b"connection", b"keep-alive", b"proxy-connection", b"transfer-encoding", b"upgrade"}
)


class _Direction:
    """Per-direction flow-control + backpressure state for one stream.

    A proxied stream carries DATA both ways, and each way needs its own
    bookkeeping.  ``Http2Stream`` holds two of these: ``to_target``
    (browser → origin) and ``to_client`` (origin → browser).  Bundling
    the three fields here lets the backpressure helpers take a single
    ``_Direction`` argument instead of a buffer plus four getter/setter
    callables threaded through as per-event lambdas.

    Fields
    ------
    pending:
        Bytes received from the sender that the receiver's flow-control
        window couldn't accommodate yet.  Drained by
        ``_drain_pending_with_backpressure`` when a WINDOW_UPDATE for
        this stream arrives.
    pending_end:
        Whether END_STREAM was set on the queued tail.  The flag rides
        out on the final drained frame rather than being sent early.
    deferred_ack:
        Bytes received from the sender but not yet ACKed (via
        WINDOW_UPDATE) because we haven't forwarded them onward.
        Deferring the ACK is what produces end-to-end backpressure — the
        sender doesn't refill until we've actually moved its bytes
        through.
    """

    __slots__ = ("pending", "pending_end", "deferred_ack")

    def __init__(self) -> None:
        self.pending: bytearray = bytearray()
        self.pending_end: bool = False
        self.deferred_ack: int = 0


class Http2Stream:
    """Maps a single HTTP/2 stream between the client and target sides.

    The proxy assigns its own stream IDs on the target connection
    (``target_stream_id``) which differ from the browser's stream IDs
    (``client_stream_id``).  This object tracks the mapping plus metadata
    needed for logging and interception.
    """

    __slots__ = (
        "client_stream_id",
        "target_stream_id",
        "authority",
        "path",
        "scheme",
        "created_at",
        "last_activity",
        "url",
        # Per-direction flow-control + backpressure state.  When we
        # receive DATA on one side but the OTHER side's outgoing window
        # won't accommodate it, we buffer in the relevant _Direction and
        # defer the WINDOW_UPDATE ACK to the sender.  The sender then
        # naturally backpressures because we're not telling them they
        # have more window until we've actually moved their bytes
        # through.
        #
        # ``to_target`` carries browser → origin data; ``to_client``
        # carries origin → browser data.  See
        # ``Http2Handler._forward_data_with_backpressure`` for the full
        # protocol — this is where the actual flow control gets plumbed
        # end-to-end across the two h2 connections.
        "to_target",
        "to_client",
        # Active idle-timeout TimerHandle (loop.call_later) for this
        # stream, owned by _StreamReaper.  None when no timer is armed
        # (before arm(), after a reap, or after disarm()).
        "_reap_handle",
        # Set to True when this stream's RequestReceived had inline PRIORITY
        # (event.priority_updated was not None) and we already forwarded it
        # via send_headers with priority params.  Cleared immediately when the
        # subsequent PriorityUpdated event for the same stream fires, so that
        # prioritize() is NOT called — preventing a redundant standalone PRIORITY
        # frame that corrupts the Akamai H2 fingerprint.
        "_had_inline_priority",
    )

    def __init__(
        self,
        client_stream_id: int,
        target_stream_id: int,
        authority: str,
        path: str,
        scheme: str,
        created_at: float,
    ):
        self.client_stream_id = client_stream_id
        self.target_stream_id = target_stream_id
        self.authority = authority
        self.path = path
        self.scheme = scheme
        self.created_at = created_at
        # Wall-clock of the last frame on this stream in either direction.
        # Used by ``_StreamReaper`` so long-lived streams
        # (server-sent events, large downloads on slow links, gRPC server
        # streaming) aren't reaped just because they've been alive longer
        # than ``stream_timeout`` — what matters is whether they're still
        # making progress.  Bumped by ``_touch_stream`` on any DataReceived
        # / WindowUpdated / HeadersReceived event for the stream.
        self.last_activity = created_at
        self.url = f"{scheme}://{authority}{path}"
        # browser → origin and origin → browser flow-control state.
        self.to_target = _Direction()
        self.to_client = _Direction()
        self._reap_handle: Optional[asyncio.TimerHandle] = None
        self._had_inline_priority: bool = False


# ============================================================================
# HTTP/2 Stream Map — O(1) bidirectional lookup
# ============================================================================


class _StreamMap:
    """Bidirectional mapping between client stream IDs and ``Http2Stream`` objects.

    The proxy needs to look up streams by *client* ID (when the browser
    sends data) **and** by *target* ID (when the origin responds).  A
    naive ``dict[client_stream_id, stream]`` requires an O(n) scan for the
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
        self._by_client[stream.client_stream_id] = stream
        self._by_target[stream.target_stream_id] = stream

    def remove_by_client(self, client_stream_id: int) -> Optional[Http2Stream]:
        stream = self._by_client.pop(client_stream_id, None)
        if stream is not None:
            self._by_target.pop(stream.target_stream_id, None)
        return stream

    def remove_by_target(self, target_stream_id: int) -> Optional[Http2Stream]:
        stream = self._by_target.pop(target_stream_id, None)
        if stream is not None:
            self._by_client.pop(stream.client_stream_id, None)
        return stream

    def clear(self) -> None:
        self._by_client.clear()
        self._by_target.clear()

    # -- lookups --

    def get_by_client(self, client_stream_id: int) -> Optional[Http2Stream]:
        return self._by_client.get(client_stream_id)

    def get_by_target(self, target_stream_id: int) -> Optional[Http2Stream]:
        return self._by_target.get(target_stream_id)

    # -- iteration --

    def values(self) -> list[Http2Stream]:
        """Return all streams (by client-side view)."""
        return list(self._by_client.values())

    def __len__(self) -> int:
        return len(self._by_client)


# ============================================================================
# HTTP/2 idle-stream reaper — event-driven (timer per stream)
# ============================================================================


class _StreamReaper:
    """Event-driven idle-stream reaper for a single HTTP/2 session.

    Replaces the former fixed-interval polling loop
    (``_check_stream_timeouts``, which woke every ``min(30, timeout/2)``
    seconds and scanned every stream).  Each stream gets a timer scheduled
    for ``last_activity + stream_timeout``.  When it fires we re-check the
    deadline: if activity has pushed it out since the timer was armed we
    lazily re-arm to the new deadline, otherwise we reap (RST both sides +
    deliver any partial capture).  Net effect:

    * A stream is reaped within ``stream_timeout`` of its final frame —
      the old up-to-30 s tick overshoot is gone.
    * No periodic O(streams) scan; work happens only when a deadline
      actually elapses.
    * :meth:`touch` is O(1) and deliberately does **not** reschedule the
      timer.  Re-arming a ``TimerHandle`` on every DATA frame would
      dominate a hot stream's per-frame cost; instead we eat at most one
      extra re-arm per idle gap when the timer fires early.

    Clock
    ~~~~~
    Timers are scheduled via ``loop.call_later`` (``call_at`` in the loop
    clock under the hood) using delays derived from ``time.monotonic()`` —
    the same clock ``last_activity``/``created_at`` are stamped with — so
    we never have to assume ``loop.time()`` and ``time.monotonic()`` share
    an epoch (they happen to on CPython/uvloop, but that is not contract).

    Flush
    ~~~~~
    A ``call_later`` callback is synchronous and cannot ``await`` the
    socket drain, so a reap only buffers RST frames into the h2 state
    machines and then sets an ``asyncio.Event``.  The :meth:`run` task
    (one per session, mostly parked on ``event.wait()``) performs the
    actual ``_flush_both``.  This keeps the reaper purely event-driven:
    no task wakes unless a stream genuinely expires.
    """

    __slots__ = (
        "_loop", "_timeout", "_handler",
        "_client_h2", "_target_h2", "_client_io", "_target_io",
        "_streams", "_captures", "_flush_evt", "_closed",
    )

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        timeout: float,
        handler: "Http2Handler",
        client_h2: h2.connection.H2Connection,
        target_h2: h2.connection.H2Connection,
        client_io: ManagedConnection,
        target_io: ManagedConnection,
        streams: _StreamMap,
        captures: dict[int, _ResponseCapture],
    ) -> None:
        self._loop = loop
        self._timeout = timeout
        self._handler = handler
        self._client_h2 = client_h2
        self._target_h2 = target_h2
        self._client_io = client_io
        self._target_io = target_io
        self._streams = streams
        self._captures = captures
        self._flush_evt = asyncio.Event()
        self._closed = False

    # -- timer management --------------------------------------------------

    def arm(self, stream: "Http2Stream") -> None:
        """Schedule the first reap timer for *stream*.  Called at creation."""
        if self._closed:
            return
        delay = max(
            0.0, stream.last_activity + self._timeout - time.monotonic()
        )
        stream._reap_handle = self._loop.call_later(
            delay, self._fire, stream.client_stream_id
        )

    @staticmethod
    def touch(stream: "Http2Stream") -> None:
        """Record activity. O(1); does NOT reschedule (see class docstring)."""
        stream.last_activity = time.monotonic()

    @staticmethod
    def disarm(stream: "Http2Stream") -> None:
        """Cancel a stream's reap timer (idempotent). Called from _finish_stream."""
        if stream._reap_handle is not None:
            stream._reap_handle.cancel()
            stream._reap_handle = None

    def close(self) -> None:
        """Cancel all outstanding timers and release the flush task."""
        self._closed = True
        for s in self._streams.values():
            self.disarm(s)
        self._flush_evt.set()

    # -- firing ------------------------------------------------------------

    def _fire(self, client_stream_id: int) -> None:
        stream = self._streams.get_by_client(client_stream_id)
        if stream is None:
            return
        stream._reap_handle = None

        remaining = stream.last_activity + self._timeout - time.monotonic()
        if remaining > 1e-3:
            # Activity arrived after the timer was armed (lazy touch never
            # rescheduled).  Re-arm to the fresh deadline instead of reaping.
            stream._reap_handle = self._loop.call_later(
                remaining, self._fire, client_stream_id
            )
            return

        now = time.monotonic()
        logger.info(
            "[HTTP/2] stream-timeout: RST stream c=%d t=%d url=%s "
            "idle=%.1fs lifetime=%.1fs",
            stream.client_stream_id, stream.target_stream_id, stream.url,
            now - stream.last_activity, now - stream.created_at,
        )
        try:
            self._client_h2.reset_stream(
                stream.client_stream_id,
                error_code=h2.errors.ErrorCodes.CANCEL,
            )
            self._target_h2.reset_stream(
                stream.target_stream_id,
                error_code=h2.errors.ErrorCodes.CANCEL,
            )
        except Exception as e:
            logger.trace(
                "stream-timeout reset failed (client=%d, target=%d): %s",
                stream.client_stream_id, stream.target_stream_id, e,
            )
        # Synchronous: delivers any partial capture and drops the stream
        # (its handle is already cleared, so the disarm inside is a no-op).
        self._handler._finish_stream(
            stream.client_stream_id, self._streams, self._captures,
            deliver_partial=True,
        )
        self._flush_evt.set()

    # -- flush task --------------------------------------------------------

    async def run(self) -> None:
        """Drain RST frames produced by reaps. Cancelled at session teardown.

        Mirrors the lifecycle of the old ``timeout_task``: spawned in
        ``handle`` and cancelled in its ``finally``.  Unlike the old task
        it never polls — it parks on ``event.wait()`` and only wakes when
        :meth:`_fire` (or :meth:`close`) signals it.
        """
        try:
            while not self._closed:
                await self._flush_evt.wait()
                self._flush_evt.clear()
                if self._closed:
                    return
                await self._handler._flush_both(
                    self._client_io, self._target_io,
                    self._client_h2, self._target_h2,
                )
        except asyncio.CancelledError:
            pass


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
        # Strong reference.  See _ProxyHandler.__init__ in session.py for
        # the lifetime contract: SessionProxy.stop() awaits every handler
        # task (registered in SessionProxy._tasks) before clearing
        # ``self._handler``, so handler code can rely on ``self._proxy``
        # being alive for the entire duration of its task.
        self._proxy = proxy
        self.config = config

    async def handle(
        self,
        client_io: ManagedConnection,
        target_io: ManagedConnection,
        target_host: str,
        client_h2: h2.connection.H2Connection,
        target_h2: h2.connection.H2Connection,
        streams: _StreamMap,
        captures: dict[int, _ResponseCapture],
        overread: bytes = b"",
    ) -> None:
        """Main HTTP/2 forwarding loop.

        Spawns two tasks (client→target, target→client) plus a
        stream-timeout reaper.  Runs until one side disconnects or
        sends GOAWAY.

        The ``draining`` set is per-session state: when one side sends
        GOAWAY, its h2 connection object gets added so racing requests
        on the other side can be refused with REFUSED_STREAM.  Keeping
        this set local to the call avoids the cross-session leakage
        that a module-level set would cause.
        """
        logger.debug("[HTTP/2 %s] Handler started", target_host)
        timeout_task: Optional[asyncio.Task[None]] = None
        reaper: Optional[_StreamReaper] = None
        draining: set[h2.connection.H2Connection] = set()

        try:
            # Event-driven idle-stream reaper.  Created before the over-read
            # block below because that path can already create (and must
            # therefore arm) the first stream.
            reaper = _StreamReaper(
                asyncio.get_running_loop(),
                self.config.stream_timeout,
                self,
                client_h2, target_h2, client_io, target_io,
                streams, captures,
            )
            # If start_session over-read past the preface (Chrome routinely
            # packs the HEADERS frame for the first request into the same
            # TLS record as the preface), feed those bytes into client_h2
            # here and process the resulting events through the normal
            # client-event handler before the pump tasks start.  Without
            # this, the bytes are gone from the socket but their events
            # were never fired, and the pump loop sits idle waiting for a
            # request the browser has already sent.
            if overread:
                logger.debug(
                    "[HTTP/2 %s] Processing %d over-read byte(s) from "
                    "preface: %s",
                    target_host, len(overread),
                    self._summarize_h2_frames(overread)[0],
                )
                try:
                    early_events = client_h2.receive_data(overread)
                except h2.exceptions.ProtocolError as e:
                    logger.warning(
                        "[HTTP/2 %s] Preface over-read produced "
                        "ProtocolError: %s",
                        target_host, e,
                    )
                    early_events = []
                for event in early_events:
                    try:
                        await self._process_client_event(
                            event, client_h2, target_h2,
                            streams, captures, draining, target_host,
                            reaper,
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        logger.warning(
                            "[HTTP/2] Error processing early client "
                            "event %s: %s",
                            type(event).__name__, e,
                        )
                await self._flush_both(
                    client_io, target_io, client_h2, target_h2,
                )

            client_task = asyncio.create_task(
                self._pump(
                    "client",
                    client_io, target_io, client_h2, target_h2,
                    streams, captures, draining, target_host,
                    reaper,
                )
            )
            target_task = asyncio.create_task(
                self._pump(
                    "target",
                    client_io, target_io, client_h2, target_h2,
                    streams, captures, draining, target_host,
                    reaper,
                )
            )
            # Event-driven flush task for the reaper's RST frames.  Replaces
            # the old polling _check_stream_timeouts task; same lifecycle
            # (cancelled in the finally below).
            timeout_task = asyncio.create_task(reaper.run())

            handler_start_t = time.monotonic()
            done, pending = await asyncio.wait(
                [client_task, target_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
            wait_returned_t = time.monotonic()
            logger.debug(
                "[HTTP/2 %s] handle: asyncio.wait returned after %.1fs "
                "done=%d pending=%d",
                target_host, wait_returned_t - handler_start_t,
                len(done), len(pending),
            )

            for t in done:
                # Identify which pump finished (by checking the task's
                # coroutine name parameter would be ideal but isn't
                # robustly available; instead, both tasks log their own
                # exit reasons inside _pump, so just emit done/exception
                # here for correlation).
                exc = t.exception()
                if exc is not None:
                    logger.debug(
                        "[HTTP/2 %s] handle: completed task raised %s: %s",
                        target_host, type(exc).__name__, exc,
                    )
                else:
                    logger.debug(
                        "[HTTP/2 %s] handle: completed task returned cleanly",
                        target_host,
                    )

            for t in pending:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass
                except Exception as e:
                    logger.debug(
                        "[HTTP/2 %s] handle: pending task cancel raised "
                        "%s: %s",
                        target_host, type(e).__name__, e,
                    )

            # GOAWAY frames buffered by _process_*_event are flushed to
            # both sides on each pump iteration via _flush_both, so by
            # the time we get here, in-flight bytes are already on the wire.
            # The pump loops exit on EOF or idle timeout — no extra flush
            # needed.

        except asyncio.CancelledError:
            logger.debug("[HTTP/2 %s] handle: cancelled", target_host)
            raise
        except Exception as e:
            logger.error(
                "[HTTP/2 %s] Error: %s\n%s",
                target_host,
                e,
                traceback.format_exc(),
            )
        finally:
            # Diagnostic: if this log appears but "Handler stopped" never
            # does, the hang is somewhere in the cleanup below — most
            # likely timeout_task.cancel() not unblocking, or a deliver
            # callback hanging.
            logger.debug(
                "[HTTP/2 %s] handle: entering finally cleanup", target_host
            )
            # Cancel every outstanding per-stream reap timer first, so no
            # _fire callback can run during/after teardown, then unblock
            # and cancel the flush task.
            if reaper is not None:
                reaper.close()
            if timeout_task:
                timeout_task.cancel()
                try:
                    await timeout_task
                except asyncio.CancelledError:
                    pass
                except Exception as e:
                    logger.debug(
                        "[HTTP/2 %s] handle: timeout_task await raised "
                        "%s: %s",
                        target_host, type(e).__name__, e,
                    )
            logger.debug("[HTTP/2 %s] Handler stopped", target_host)

            # FIX: Deliver partial captures for in-flight streams so that
            # interceptors blocked on capture.get() are unblocked immediately
            # instead of hanging until their timeout.
            for _, capture in list(captures.items()):
                if capture.status_code:
                    self._proxy.policy.deliver_capture(capture)
            captures.clear()
            streams.clear()

    @staticmethod
    def _sync_h2_internal_state_from_local_settings(
        conn: h2.connection.H2Connection,
    ) -> None:
        """Sync h2's internal fields that depend on ``local_settings``.

        h2 normally updates these fields inside ``_local_settings_acked``,
        which runs when the **peer** ACKs a SETTINGS frame we sent.
        The two preface builders bypass that flow entirely: they replace
        ``conn.local_settings`` wholesale before ``initiate_connection``
        and then discard h2's emitted bytes so the proxy can forward the
        browser's exact preface instead.  No SETTINGS exchange happens,
        no ACK arrives, and ``_local_settings_acked`` never fires —
        leaving the dependent internal fields stale at their defaults.

        This helper performs the same sync ``_local_settings_acked``
        would do, for the subset that matters at preface time (i.e.
        before any streams exist):

        * ``decoder.max_allowed_table_size`` (HEADER_TABLE_SIZE) —
          without this, the HPACK decoder rejects table indices the
          peer's encoder thinks are valid: "Invalid table index N".
        * ``decoder.max_header_list_size`` (MAX_HEADER_LIST_SIZE) —
          without this, large headers (long Cookie, big User-Agent +
          client hints) are rejected with HEADER_LIST_TOO_LARGE.
        * ``max_inbound_frame_size`` (MAX_FRAME_SIZE) — without this,
          frames larger than the 16384-byte spec default get rejected
          with FRAME_SIZE_ERROR.  Browsers usually keep the default, so
          this rarely triggers, but Chrome can negotiate larger.

        INITIAL_WINDOW_SIZE is intentionally NOT handled here: it only
        affects existing stream windows (§6.9.2), and no streams exist
        at preface time.  Once streams are created they pick up the
        right initial window from ``local_settings`` directly.

        Keep this list in sync with h2's ``_local_settings_acked`` if
        you upgrade the h2 library.
        """
        ls = conn.local_settings
        conn.decoder.max_allowed_table_size = ls.header_table_size
        mhls = ls.max_header_list_size
        if mhls is not None:
            conn.decoder.max_header_list_size = mhls
        conn.max_inbound_frame_size = ls.max_frame_size

    @staticmethod
    def _build_client_h2(
        mirror_from: Optional[h2.settings.Settings] = None,
    ) -> h2.connection.H2Connection:
        """Build the browser-facing h2 connection (server-side).

        When *mirror_from* is provided (the target's SETTINGS, learned
        during the target preface exchange), the browser-facing
        SETTINGS are aligned to those values so the browser's outgoing
        per-stream window can never exceed what the target will accept.
        This eliminates the flow-control mismatch that would otherwise
        cause ``Cannot send X bytes, flow control window is Y`` errors
        when forwarding browser uploads to conservative servers
        (Cloudflare, etc.).

        Notable mirrored values:

        * ``INITIAL_WINDOW_SIZE`` — per-stream window the browser may use
          when sending to us.  Mirrored exactly so we never need to buffer.
        * ``MAX_FRAME_SIZE`` — frame size cap.  Mirrored so we don't have
          to refragment frames before forwarding.
        * ``MAX_CONCURRENT_STREAMS`` — limit on streams the browser may
          open.  Mirrored (with a sane fallback) so we don't accept
          requests we can't forward.
        * ``MAX_HEADER_LIST_SIZE`` — header bytes cap.  Mirrored.
        * ``ENABLE_PUSH`` — pinned to 0; we don't accept push from the
          browser (it shouldn't initiate any anyway, but explicit is good).
        """
        config = h2.config.H2Configuration(
            client_side=False, validate_inbound_headers=False
        )
        conn = h2.connection.H2Connection(config=config)

        if mirror_from is not None:
            initial_values: dict[h2.settings.SettingCodes, int] = {
                h2.settings.SettingCodes.INITIAL_WINDOW_SIZE:
                    mirror_from.initial_window_size,
                h2.settings.SettingCodes.MAX_FRAME_SIZE:
                    mirror_from.max_frame_size,
                h2.settings.SettingCodes.HEADER_TABLE_SIZE:
                    mirror_from.header_table_size,
                h2.settings.SettingCodes.ENABLE_PUSH: 0,
            }
            mcs = mirror_from.max_concurrent_streams
            # h2 reports a sentinel (2**32+1) when the peer didn't send
            # MAX_CONCURRENT_STREAMS.  Mirror any value that looks like a
            # real per-peer limit; otherwise fall back to Chrome's typical
            # advertised cap.  (The previous < 1024 heuristic silently
            # clamped a target advertising e.g. 2000 streams down to 100;
            # the threshold now only rejects the unset sentinel.)
            if mcs < _H2_UNSET_CONCURRENT_STREAMS_THRESHOLD:
                initial_values[
                    h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS
                ] = mcs
            else:
                initial_values[
                    h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS
                ] = _DEFAULT_MAX_CONCURRENT_STREAMS
            mhls = mirror_from.max_header_list_size
            if mhls is not None:
                initial_values[
                    h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE
                ] = mhls

            conn.local_settings = h2.settings.Settings(
                client=False,
                initial_values=initial_values,
            )
            # Sync h2's internal fields that mirror local_settings.
            # See the helper's docstring for why this is necessary when
            # we replace local_settings wholesale instead of going via
            # update_settings().
            Http2Handler._sync_h2_internal_state_from_local_settings(conn)

        conn.initiate_connection()
        conn.increment_flow_control_window(_BROWSER_FACING_RECV_WINDOW_INCREMENT)
        return conn

    @staticmethod
    async def _read_browser_preface(
        client_io: ManagedConnection,
        timeout: float = 10.0,
    ) -> tuple[bytes, dict[int, int], int, bytes]:
        """Read the browser's HTTP/2 connection preface from the socket.

        The browser sends its preface as soon as TLS completes per
        RFC 7540 §3.5: a 24-byte magic string followed by a SETTINGS
        frame, optionally followed by an immediate WINDOW_UPDATE on
        stream 0 (Chrome does this to bump the connection-level
        receive window).

        Returns ``(raw_bytes, settings_dict, connection_window_increment,
        overread)``:

        * ``raw_bytes`` — the exact preface bytes the browser sent.
          These get forwarded verbatim to the target so the target sees
          the browser's true h2 fingerprint (Akamai H2 hash etc.) without
          us having to maintain a hand-rolled approximation that could
          drift with Chrome version updates.
        * ``settings_dict`` — the SETTINGS values parsed from the frame,
          used to configure our target-facing ``H2Connection``'s
          ``local_settings`` so its internal state matches the wire.
        * ``connection_window_increment`` — the value of the optional
          WINDOW_UPDATE on stream 0, or 0 if absent.  Applied via
          ``increment_flow_control_window`` to keep h2's accounting
          aligned with what the browser actually sent.
        * ``overread`` — bytes the asyncio reader returned past the
          preface (Chrome routinely packs the HEADERS frame for the
          first request into the same TLS record as the preface, and
          we have no way to push them back onto the StreamReader).
          The caller must feed these into ``client_h2.receive_data``
          and process the resulting events; otherwise the first request
          is silently dropped and the connection deadlocks.

        Cost
        ~~~~
        We have to wait for the browser to finish sending its preface
        before we can forward to the target.  Typically a few ms after
        TLS completes, but can be tens of ms on slow connections.  This
        is the runtime price of fingerprint precision that survives
        Chrome version updates — we trade a small per-CONNECT latency
        for never having to chase a moving fingerprint target.
        """
        magic = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

        buf = bytearray()
        async with asyncio.timeout(timeout):
            while len(buf) < len(magic):
                chunk = await client_io.reader.read(len(magic) - len(buf))
                if not chunk:
                    raise ConnectionError(
                        "Browser closed connection before sending h2 preface"
                    )
                buf.extend(chunk)

        if bytes(buf) != magic:
            raise ConnectionError(
                f"Browser did not send valid h2 preface "
                f"(got {bytes(buf[:24])!r})"
            )

        return await Http2Handler._parse_browser_preface(
            client_io, magic, bytes(buf), timeout,
        )

    @staticmethod
    async def _parse_browser_preface(
        client_io: ManagedConnection,
        magic: bytes,
        already_buffered: bytes,
        timeout: float,
    ) -> tuple[bytes, dict[int, int], int, bytes]:
        """Parse SETTINGS [+ WINDOW_UPDATE] frames following the magic string.

        Implementation half of :meth:`_read_browser_preface`.  Reads
        until both control frames are consumed (SETTINGS is required,
        WINDOW_UPDATE is optional), then stops — leaving any subsequent
        HEADERS/DATA frames *in the local buffer* (asyncio's StreamReader
        has no put-back), which the caller must re-feed to client_h2 via
        the ``overread`` return value.

        Per RFC 7540 §4.1, every frame is:

        * 3 B length (big-endian)
        * 1 B type
        * 1 B flags
        * 4 B (R bit + 31 B stream_id, big-endian)

        followed by ``length`` bytes of payload.
        """
        buf = bytearray(already_buffered)
        cursor = len(magic)
        settings_dict: dict[int, int] = {}
        settings_seen = False
        window_increment = 0

        async def _ensure_buffered(n: int) -> None:
            """Read until ``len(buf) - cursor >= n``."""
            while len(buf) - cursor < n:
                async with asyncio.timeout(timeout):
                    chunk = await client_io.reader.read(8192)
                if not chunk:
                    raise ConnectionError(
                        "Browser preface truncated"
                    )
                buf.extend(chunk)

        # SETTINGS is required.  WINDOW_UPDATE is optional but typically
        # follows — we keep parsing until we hit a non-control frame.
        while True:
            try:
                await _ensure_buffered(9)
            except ConnectionError:
                if settings_seen:
                    return bytes(buf[:cursor]), settings_dict, window_increment, b""
                raise

            length = int.from_bytes(buf[cursor:cursor + 3], "big")
            ftype = buf[cursor + 3]
            stream_id = (
                int.from_bytes(buf[cursor + 5:cursor + 9], "big") & 0x7FFFFFFF
            )

            await _ensure_buffered(9 + length)
            payload = bytes(buf[cursor + 9:cursor + 9 + length])

            if ftype == 0x4:  # SETTINGS
                if stream_id != 0:
                    raise ConnectionError(
                        f"SETTINGS on non-zero stream {stream_id}"
                    )
                if length % 6 != 0:
                    raise ConnectionError(
                        f"Malformed SETTINGS payload length {length}"
                    )
                for i in range(0, length, 6):
                    ident = int.from_bytes(payload[i:i + 2], "big")
                    value = int.from_bytes(payload[i + 2:i + 6], "big")
                    settings_dict[ident] = value
                settings_seen = True
                cursor += 9 + length
                continue

            if ftype == 0x8 and stream_id == 0:  # WINDOW_UPDATE on conn
                if length != 4:
                    raise ConnectionError(
                        f"Malformed WINDOW_UPDATE length {length}"
                    )
                window_increment = (
                    int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
                )
                cursor += 9 + length
                # Connection-level WINDOW_UPDATE is the last preface frame
                # Chrome sends; once we have it, stop.
                break

            # Not a SETTINGS or connection-level WINDOW_UPDATE — preface is
            # over.  Don't consume this frame; leave it on the socket.
            break

        # Capture any bytes the asyncio reader returned past the preface.
        # Chrome typically packs the HEADERS frame for the first request
        # into the same TLS record as the preface, and asyncio's
        # StreamReader has no put-back primitive — the bytes we read
        # past ``cursor`` are sitting in the local ``buf`` with no way
        # to get them back onto the socket.  The caller (handle()) must
        # feed ``overread`` to client_h2.receive_data and process the
        # resulting events before the pump loop starts; otherwise the
        # first request is silently dropped and the connection deadlocks
        # until the idle timeout fires.
        overread = bytes(buf[cursor:])
        return bytes(buf[:cursor]), settings_dict, window_increment, overread

    @staticmethod
    def _build_target_h2_from_browser_preface(
        browser_settings: dict[int, int],
        connection_window_increment: int,
    ) -> h2.connection.H2Connection:
        """Build the origin-facing h2 connection using the browser's preface values.

        We forward the browser's exact preface bytes to the target rather
        than hand-rolling a Chrome-fingerprint approximation.  But h2's
        internal state machine still needs to *know* what we sent, so we
        configure ``local_settings`` to match the values the browser
        declared, then call ``initiate_connection()`` and discard h2's
        own preface bytes (since we'll write the browser's bytes to the
        socket instead).

        The result: bytes on the wire are byte-identical to what the
        browser sent (perfect Akamai H2 fingerprint match), and h2's
        internal accounting agrees with those bytes.
        """
        config = h2.config.H2Configuration(
            client_side=True, validate_inbound_headers=False
        )
        conn = h2.connection.H2Connection(config=config)

        # Map raw setting IDs to h2's SettingCodes enum where defined.
        # Unknown IDs are skipped — h2 won't accept them in
        # local_settings, and browsers shouldn't send them anyway.
        initial_values: dict[h2.settings.SettingCodes, int] = {}
        for ident, value in browser_settings.items():
            try:
                code = h2.settings.SettingCodes(ident)
                initial_values[code] = value
            except ValueError:
                logger.debug(
                    "Ignoring unknown SETTINGS id 0x%x = %d (not in h2 enum)",
                    ident, value,
                )

        if initial_values:
            conn.local_settings = h2.settings.Settings(
                client=True,
                initial_values=initial_values,
            )
            # Sync h2's internal fields that mirror local_settings.
            # See the helper's docstring for why this is necessary when
            # we replace local_settings wholesale instead of going via
            # update_settings().
            Http2Handler._sync_h2_internal_state_from_local_settings(conn)

        conn.initiate_connection()
        # Discard h2's own preface bytes — we'll write the browser's
        # exact bytes to the target socket instead.
        conn.data_to_send()

        # Apply the connection-level WINDOW_UPDATE the browser sent
        # (if any) so h2's flow-control accounting matches what's on
        # the wire.  The bytes h2 produces here are also discarded —
        # the browser's bytes already contain a WINDOW_UPDATE.
        if connection_window_increment > 0:
            conn.increment_flow_control_window(connection_window_increment)
            conn.data_to_send()

        return conn

    async def start_session(
        self,
        client_io: ManagedConnection,
        target_io: ManagedConnection,
        target_host: str,
    ) -> None:
        """Set up HTTP/2 connections on both sides and enter the handler loop.

        Order of operations
        ~~~~~~~~~~~~~~~~~~~

        1. Read the **browser's** preface bytes (magic + SETTINGS [+
           WINDOW_UPDATE]).  These carry Chrome's true h2 fingerprint.

        2. Build the target-facing ``H2Connection`` with ``local_settings``
           configured to match what the browser declared, then forward
           the browser's exact preface bytes to the target.  The Akamai
           H2 fingerprint the target sees is byte-identical to what
           Chrome would send if there were no proxy.

        3. Read the target's SETTINGS reply.

        4. Build the browser-facing ``H2Connection`` with ``local_settings``
           mirrored from the target's SETTINGS, so the browser's outgoing
           per-stream window can never exceed what the target will accept.

        5. Send our preface to the browser.  Feed the already-consumed
           browser preface into ``client_h2.receive_data`` so its state
           machine is up to date — without this, ``_pump`` would expect
           to read those bytes from the socket.

        6. Hand off to :meth:`handle`.
        """
        streams = _StreamMap()
        captures: dict[int, _ResponseCapture] = {}

        # Step 1: Read the browser's preface.  This is the cost of
        # forwarding rather than hand-rolling — we must wait for the
        # browser to send before we can forward to the target.
        try:
            (
                browser_preface_bytes,
                browser_settings,
                conn_window_inc,
                overread,
            ) = await self._read_browser_preface(client_io)
        except asyncio.TimeoutError:
            # ``asyncio.TimeoutError`` has no message text; the bare "%s"
            # used to log "read failed: " with nothing after the colon.
            # This is the "browser opened CONNECT but never spoke h2"
            # case, common when JS calls window.stop() right after main
            # page load — debug-level because it's expected behavior.
            logger.debug(
                "[HTTP/2 %s] Browser preface read timed out "
                "(no h2 traffic — likely an aborted CONNECT)",
                target_host,
            )
            return
        except ConnectionError as e:
            # ConnectionError covers the various ways the browser can
            # close before sending its preface.  All expected during
            # navigation aborts; log at debug.
            msg = str(e) or type(e).__name__
            logger.debug(
                "[HTTP/2 %s] CONNECT closed before h2 preface: %s",
                target_host, msg,
            )
            return

        # Step 2: Build target h2 mirroring the browser's settings,
        # then forward the browser's exact bytes to the target.
        target_h2 = self._build_target_h2_from_browser_preface(
            browser_settings, conn_window_inc,
        )

        client_h2: Optional[h2.connection.H2Connection] = None
        try:
            target_io.writer.write(browser_preface_bytes)
            await target_io.writer.drain()

            # Step 3: Read the target's SETTINGS so we can mirror them
            # to the browser side.  SETTINGS is tiny and almost always
            # lands in the first read, but a fragmented TLS record could
            # split it — and mirroring from a half-parsed remote_settings
            # in step 4 would mis-size the browser's window.  Loop until
            # h2 reports it actually parsed a SETTINGS frame
            # (RemoteSettingsChanged) or the target closes first.  The 5s
            # budget now bounds the whole handshake rather than a single
            # read.  Any extra frames the target piggybacks here are fed
            # to h2's internal buffer; their events are safe to ignore
            # because no streams exist yet.
            settings_seen = False
            async with asyncio.timeout(5.0):
                while not settings_seen:
                    data = await target_io.reader.read(
                        self.config.read_buffer_size
                    )
                    if not data:
                        # Target closed before completing its preface;
                        # proceed best-effort with the settings we have.
                        break
                    events = target_h2.receive_data(data)
                    ack = target_h2.data_to_send()
                    if ack:
                        target_io.writer.write(ack)
                        await target_io.writer.drain()
                    if any(
                        isinstance(e, h2.events.RemoteSettingsChanged)
                        for e in events
                    ):
                        settings_seen = True

            # Step 4: Build browser-facing h2 with mirrored SETTINGS so
            # the browser's outgoing window is aligned with what the
            # target will accept.
            client_h2 = self._build_client_h2(
                mirror_from=target_h2.remote_settings
            )

            # Step 5: Send our preface to the browser, then teach
            # client_h2 about the browser preface bytes we already
            # consumed off the socket.  The h2 state machine must see
            # them, otherwise it will reject subsequent frames as
            # arriving on a connection that hasn't been initialised.
            client_io.writer.write(client_h2.data_to_send())
            await client_io.writer.drain()

            # The browser preface bytes start with the magic string
            # (24 B) — h2 expects that on the wire as part of its
            # incoming-preface state.  Pass the whole thing through.
            try:
                client_h2.receive_data(browser_preface_bytes)
            except h2.exceptions.ProtocolError as e:
                logger.warning(
                    "[HTTP/2 %s] Browser preface re-injection failed: %s",
                    target_host, e,
                )
                return

            ack = client_h2.data_to_send()
            if ack:
                client_io.writer.write(ack)
                await client_io.writer.drain()

            # Step 6: Track and hand off to the main loop.
            self._proxy._track_h2_state(
                client_h2, target_h2, client_io, target_io,
            )

            try:
                await self.handle(
                    client_io, target_io, target_host,
                    client_h2, target_h2, streams, captures,
                    overread=overread,
                )
            finally:
                self._proxy._untrack_h2_state(
                    client_h2, target_h2, client_io, target_io,
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
            streams.clear()
            captures.clear()

    # -- internal ----------------------------------------------------------

    async def _pump(
        self,
        side: str,  # "client" or "target"
        client_io: ManagedConnection,
        target_io: ManagedConnection,
        client_h2: h2.connection.H2Connection,
        target_h2: h2.connection.H2Connection,
        streams: _StreamMap,
        captures: dict[int, _ResponseCapture],
        draining: set[h2.connection.H2Connection],
        target_host: str,
        reaper: "_StreamReaper",
    ) -> None:
        """Read loop for one side of the h2 session.

        ``side="client"`` reads from the browser and forwards request
        events to ``_process_client_event``; ``side="target"`` reads
        from the origin and forwards response events to
        ``_process_target_event``.

        Both sides share identical structure (read with idle timeout,
        feed h2 state machine, process each event with per-event
        exception isolation, flush) — the only differences are which
        ``ManagedConnection`` and ``H2Connection`` get read from, and
        which event processor handles the result.
        """
        if side == "client":
            io_in, h2_in = client_io, client_h2
        else:
            io_in, h2_in = target_io, target_h2

        # Session+side identifier for log correlation.  The proxy may
        # have many concurrent h2 sessions, and warnings need to be
        # attributable.  We use id(h2_in) because it's stable for the
        # lifetime of the connection object and uniquely identifies it.
        sid = f"{id(h2_in) & 0xFFFFFF:06x}"

        # Diagnostic: track *why* this pump exits.  When a handler
        # appears to hang (logs go silent without the customary "Handler
        # stopped" message), grepping for this pump's "pump exit" line
        # tells us whether the pump even reached its break statement, or
        # whether it's wedged on an await somewhere in the loop body.
        # Counter-paired with "pump start" so we can match them up.
        pump_start_t = time.monotonic()
        exit_reason = "io_in_closed"  # if loop never enters
        reads_total = 0
        bytes_total = 0
        logger.debug(
            "[HTTP/2 %s sid=%s] pump start (idle_timeout=%.1fs target=%s)",
            side, sid, self.config.idle_timeout, target_host,
        )

        # Rolling history of frame summaries for diagnostic dumps when
        # something goes wrong.  Keeps the last N frames received on
        # this side; on ProtocolError we dump them to show what led up
        # to the failing frame.  Bounded so it can't grow unboundedly
        # on healthy long-lived connections.
        recent_frames: list[str] = []
        max_recent = 32

        # Cross-buffer state for the frame summarizer.  TCP reads chop
        # frame boundaries arbitrarily, so we have to remember how much
        # of the next frame's body still needs to arrive
        # (``pending_body``) and any 0-8 byte fragment of the next
        # frame's header that arrived at the tail of the prior buffer
        # (``header_fragment``).  See ``_summarize_h2_frames``.
        pending_body = 0
        header_fragment = b""

        try:
          while not io_in.closed:
            try:
                async with asyncio.timeout(self.config.idle_timeout):
                    data = await io_in.reader.read(self.config.read_buffer_size)
            except asyncio.TimeoutError:
                exit_reason = "idle_timeout"
                break
            if not data:
                exit_reason = "eof"
                break
            io_in.touch()
            reads_total += 1
            bytes_total += len(data)

            # Frame summarization is DIAGNOSTICS ONLY, so keep it off the
            # hot path.  Previously _summarize_h2_frames ran on every read
            # regardless of log level (only the trace() call below was
            # gated), so a bulk download paid a full hyperframe header parse
            # + string build + ring-buffer maintenance on every buffer for
            # output nobody was looking at.  Now we only summarize when
            # TRACE is enabled.  The cross-read carry state (pending_body /
            # header_fragment) is only meaningful for the rolling trace
            # history, so it too lives under this guard; when TRACE is off
            # the ProtocolError handler below summarizes the single failing
            # buffer on the spot, which is the part actually worth seeing.
            if logger.isEnabledFor(5):
                try:
                    summary, pending_body, header_fragment = (
                        self._summarize_h2_frames(
                            data,
                            prior_body_remaining=pending_body,
                            prior_header_fragment=header_fragment,
                            max_frames=8,
                        )
                    )
                except Exception:
                    # Frame parsing failed — don't let diagnostics crash
                    # the pump loop.  Reset state so we don't compound the
                    # error on the next read.
                    summary = "<summarizer error>"
                    pending_body = 0
                    header_fragment = b""

                logger.trace(
                    "[HTTP/2 %s sid=%s] %d bytes received: %s",
                    side, sid, len(data), summary,
                )

                recent_frames.append(summary)
                if len(recent_frames) > max_recent:
                    del recent_frames[0]

            # If the state machine is already CLOSED, feeding more data
            # into receive_data() is just going to produce ProtocolError
            # (typically "Invalid input X in state ConnectionState.IDLE"
            # — h2 reports "IDLE" because process_input flips the state
            # machine to CLOSED before raising, so the printed "old
            # state" is stale).  HPACK is also corrupt at this point —
            # the encoder kept building up its dynamic table while we
            # weren't decoding, so subsequent HEADERS frames reference
            # table indices we don't have, producing the "Invalid table
            # index N" cascade.  Bail out before generating that noise.
            try:
                if h2_in.state_machine.state == ConnectionState.CLOSED:
                    logger.debug(
                        "[HTTP/2 %s sid=%s] state is CLOSED; pump exiting "
                        "(remaining %d bytes ignored)",
                        side, sid, len(data),
                    )
                    exit_reason = "h2_state_closed"
                    break
            except Exception:
                pass

            try:
                events = h2_in.receive_data(data)
            except h2.exceptions.ProtocolError as e:
                # Rich diagnostic dump.  This is the kind of error that
                # used to be a one-line warning and was extremely hard
                # to debug because it discarded all the context about
                # what triggered it.  Now we log:
                #   - which side/session
                #   - h2's connection state right before the failure
                #   - the failing buffer's frame summary
                #   - the recent-frames history (only populated when TRACE
                #     is on; empty otherwise)
                # We summarize the failing buffer HERE, lazily, so the hot
                # path pays nothing when there's no error.  When TRACE was
                # off there's no rolling history, but the failing buffer is
                # the most actionable part and we still get it.
                conn_state = "?"
                try:
                    conn_state = h2_in.state_machine.state.name
                except Exception:
                    pass
                try:
                    failing_summary, _, _ = self._summarize_h2_frames(
                        data, max_frames=8,
                    )
                except Exception:
                    failing_summary = "<summarizer error>"
                logger.warning(
                    "[HTTP/2 %s sid=%s] ProtocolError: %s\n"
                    "  conn_state_before=%s\n"
                    "  failing_buffer=%s\n"
                    "  recent_frames (oldest first, TRACE only):\n    %s",
                    side, sid, e,
                    conn_state,
                    failing_summary,
                    "\n    ".join(recent_frames) or "(none — enable TRACE for history)",
                )
                exit_reason = "protocol_error"
                break

            for event in events:
                try:
                    if side == "client":
                        await self._process_client_event(
                            event, client_h2, target_h2,
                            streams, captures, draining, target_host,
                            reaper,
                        )
                    else:
                        await self._process_target_event(
                            event, client_h2, target_h2,
                            streams, captures, draining,
                        )
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.warning(
                        "[HTTP/2] Error processing %s event %s: %s",
                        side, type(event).__name__, e,
                    )

            await self._flush_both(client_io, target_io, client_h2, target_h2)
        except asyncio.CancelledError:
            exit_reason = "cancelled"
            raise
        except BaseException as e:
            # Catch BaseException (not just Exception) so any escape from
            # the loop body — including the GeneratorExit / SystemExit
            # paths that might escape from inside an asyncio.timeout —
            # leaves a forensic trail rather than silently terminating
            # the task.  We re-raise after logging so cancellation /
            # shutdown propagate normally.
            exit_reason = f"exception:{type(e).__name__}"
            logger.warning(
                "[HTTP/2 %s sid=%s] pump escaped via %s: %s",
                side, sid, type(e).__name__, e,
            )
            raise
        finally:
            lifetime = time.monotonic() - pump_start_t
            logger.debug(
                "[HTTP/2 %s sid=%s] pump exit reason=%s lifetime=%.1fs "
                "reads=%d bytes=%d io_in.closed=%s",
                side, sid, exit_reason, lifetime,
                reads_total, bytes_total, io_in.closed,
            )

    @staticmethod
    def _summarize_h2_frames(
        data: bytes,
        *,
        prior_body_remaining: int = 0,
        prior_header_fragment: bytes = b"",
        max_frames: int = 16,
    ) -> tuple[str, int, bytes]:
        """Decode raw h2 wire bytes into a human-readable frame summary.

        Used for diagnostics when ``receive_data`` raises ProtocolError —
        the error message itself doesn't tell us which frame triggered
        it, only the state machine input (e.g. RECV_RST_STREAM).  This
        helper unpacks the buffer into ``[type stream_id flags body_len]``
        tuples so we can see exactly what arrived.

        Body bytes are NOT logged — only frame metadata.  Sensitive
        payload data (HEADERS, DATA) is summarised by length only.

        Stateful across reads
        ~~~~~~~~~~~~~~~~~~~~~
        TCP reads chop frame boundaries arbitrarily — a single read may
        end in the middle of a DATA body, or with only 4 bytes of the
        next 9-byte frame header buffered.  Without carry-over state,
        the next read's first 9 bytes get parsed as if they were a frame
        header, producing nonsense like ``len=8533317`` (payload bytes
        being misinterpreted as a length field).

        Callers maintain two pieces of state across reads:

        * ``prior_body_remaining`` — bytes of an in-progress frame body
          that spilled past the prior buffer.  These are consumed first
          before any parsing begins.
        * ``prior_header_fragment`` — between 1 and 8 bytes of the next
          frame's header that arrived at the tail of the prior buffer.
          Prepended to *data* before parsing resumes.

        Returns ``(summary, new_body_remaining, new_header_fragment)``.
        Single-shot callers can pass nothing (defaults) and discard the
        latter two return values.

        Returns a string like::

            [SETTINGS s=0 f=0x00 len=18, HEADERS s=1 f=0x05 len=42,
             RST_STREAM s=3 f=0x00 len=4]

        Truncates to *max_frames* entries with a "+N more" suffix to
        avoid enormous log lines on big buffers.
        """
        out: list[str] = []
        truncated = 0
        pos = 0  # position into the new *data* buffer

        # 1. Consume any pending body bytes from a prior buffer first.
        #    These look like DATA payload (or HEADERS continuation, etc.)
        #    — we don't parse them, just note their presence.
        if prior_body_remaining:
            consume = min(prior_body_remaining, len(data))
            out.append(f"<body cont. {consume}B>")
            pos = consume
            new_body_remaining = prior_body_remaining - consume
            if new_body_remaining:
                # Entire buffer was body continuation; nothing else to do.
                return f"[{', '.join(out)}]", new_body_remaining, b""

        # 2. Combine any leftover header bytes from the prior buffer
        #    with the rest of this buffer.  The fragment is at most 8
        #    bytes (a complete header is 9), so the cost is negligible.
        work = prior_header_fragment + data[pos:]
        wpos = 0

        # 3. Skip the connection preface magic if present.  The magic is
        #    not a frame and would otherwise be misinterpreted (its first
        #    3 bytes 'PRI' look like a frame length of 5263945).
        magic = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        if work[wpos:wpos + len(magic)] == magic:
            out.append("MAGIC")
            wpos += len(magic)

        # 4. Parse complete frame headers; advance past their bodies.
        mv = memoryview(work)
        while wpos + 9 <= len(work):
            header = mv[wpos:wpos + 9]
            try:
                frame, body_len = _HF_Frame.parse_frame_header(header)
            except _HF_UnknownFrameError as e:
                if len(out) < max_frames:
                    out.append(
                        f"UNKNOWN(type=0x{e.frame_type:02x}) s=? len=?"
                    )
                # Without a frame object we can't know body_len.  Best
                # we can do is bail; reseting carry-over state means the
                # next call starts fresh (and likely misaligned, but
                # this branch indicates a corrupt stream anyway).
                return f"[{', '.join(out)}]", 0, b""
            except Exception as e:
                if len(out) < max_frames:
                    out.append(f"<parse error: {e}>")
                return f"[{', '.join(out)}]", 0, b""

            if len(out) < max_frames:
                ftype = type(frame).__name__.replace("Frame", "").upper() or "?"
                flagstr = ",".join(sorted(frame.flags)) or "-"
                out.append(f"{ftype} s={frame.stream_id} f={flagstr} len={body_len}")
            else:
                truncated += 1

            wpos += 9 + body_len

        # 5. Compute carry-over state for the next call.
        if wpos > len(work):
            # Last frame's body extends past the buffer.
            new_body_remaining = wpos - len(work)
            new_header_fragment = b""
        else:
            # Anything left over (0–8 bytes) is the start of a header.
            new_body_remaining = 0
            new_header_fragment = bytes(work[wpos:])

        suffix = f", +{truncated} more" if truncated else ""
        return (
            f"[{', '.join(out)}{suffix}]",
            new_body_remaining,
            new_header_fragment,
        )

    async def _flush_both(
        self,
        client_io: ManagedConnection,
        target_io: ManagedConnection,
        client_h2: h2.connection.H2Connection,
        target_h2: h2.connection.H2Connection,
    ) -> None:
        """Send any pending h2 frame data to both sides.

        Diagnostic: if ``writer.drain()`` blocks for more than a few
        seconds, log a warning. Without this warning the
        whole h2 pump would silently freeze with no log output.
        """
        client_pending = client_h2.data_to_send()
        target_pending = target_h2.data_to_send()
        if client_pending and not client_io.closed:
            client_io.writer.write(client_pending)
        if target_pending and not target_io.closed:
            target_io.writer.write(target_pending)
        coros = []
        labels = []
        if client_pending and not client_io.closed:
            coros.append(client_io.writer.drain())
            labels.append(f"client({len(client_pending)}B)")
        if target_pending and not target_io.closed:
            coros.append(target_io.writer.drain())
            labels.append(f"target({len(target_pending)}B)")
        if not coros:
            return
        # Wrap with a soft warning threshold.  We don't abort the drain
        # because the proxy doesn't have a recovery path for partial
        # writes, but we DO want to know if a drain takes a long time
        flush_start = time.monotonic()
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*coros, return_exceptions=True),
                timeout=30.0,
            )
            elapsed = time.monotonic() - flush_start
            if elapsed > 5.0:
                logger.warning(
                    "[HTTP/2] _flush_both slow: %.1fs for %s",
                    elapsed, "+".join(labels),
                )
            # Surface any drain() exceptions caught by gather.
            for label, res in zip(labels, results):
                if isinstance(res, BaseException):
                    logger.debug(
                        "[HTTP/2] _flush_both drain() %s raised %s: %s",
                        label, type(res).__name__, res,
                    )
        except asyncio.TimeoutError:
            elapsed = time.monotonic() - flush_start
            logger.error(
                "[HTTP/2] _flush_both HARD TIMEOUT after %.1fs on %s — "
                "transport likely wedged",
                elapsed, "+".join(labels),
            )

    async def _handle_goaway(
        self,
        event: h2.events.ConnectionTerminated,
        from_side: str,
        to_h2: h2.connection.H2Connection,
        streams: _StreamMap,
        captures: dict[int, _ResponseCapture],
    ) -> None:
        """Propagate a GOAWAY from one side to the other.

        Both directions follow the same pattern: RST any in-flight streams
        the originating side won't process (those above ``last_stream_id``),
        translate ``last_stream_id`` into the receiving side's ID space, and
        forward the GOAWAY.

        ``from_side`` is one of ``"client"`` or ``"target"`` — only used
        to decide which ID attribute on each ``Http2Stream`` is the
        originating side and which is the receiving side, plus log labels.

        Note we intentionally do *not* raise an exception to bring down
        the session: in-flight streams below ``last_stream_id`` are still
        valid and must be allowed to complete.  The reading loop on the
        originating side will exit on EOF when its TCP socket closes.
        """
        last_id = getattr(event, "last_stream_id", None)
        error_code = getattr(event, "error_code", 0)
        additional = getattr(event, "additional_data", b"")

        if from_side == "target":
            from_attr, to_attr, log_label = "target_stream_id", "client_stream_id", "Target"
        else:
            from_attr, to_attr, log_label = "client_stream_id", "target_stream_id", "Client"

        logger.debug(
            "[GOAWAY] %s GOAWAY (last_stream=%s, error=%s) — "
            "forwarding; draining %d stream(s).",
            log_label, last_id, error_code, len(streams),
        )

        # RST any streams the originator won't process (those above last_id).
        # REFUSED_STREAM (7) tells the receiver these are safe to retry.
        if last_id is not None:
            doomed = [
                s for s in streams.values()
                if getattr(s, from_attr) > last_id
            ]
            for stream in doomed:
                try:
                    to_h2.reset_stream(
                        getattr(stream, to_attr),
                        error_code=h2.errors.ErrorCodes.REFUSED_STREAM,
                    )
                except Exception as e:
                    logger.trace(
                        "%s-GOAWAY reset failed (%s=%d): %s",
                        log_label, to_attr, getattr(stream, to_attr), e,
                    )
                self._finish_stream(
                    stream.client_stream_id, streams, captures,
                    deliver_partial=True,
                )

        # Translate last_id into the receiving side's stream-ID space:
        # the highest receiver-side ID whose originator-side ID ≤ last_id.
        if last_id is not None:
            translated_last_id = max(
                (
                    getattr(s, to_attr) for s in streams.values()
                    if getattr(s, from_attr) <= last_id
                ),
                default=0,
            )
        else:
            # Unknown last_id: echo the highest receiver-side ID we know
            # about so every in-flight request is permitted to complete.
            translated_last_id = max(
                (getattr(s, to_attr) for s in streams.values()),
                default=0,
            )

        # Capture state machine state BEFORE the close_connection call
        # to prove (or disprove) the suspicion that close_connection is
        # what trips client_h2 into CLOSED.  If state moves from OPEN
        # to CLOSED here despite our SEND_GOAWAY patch, that tells us
        # h2 has another path we missed.
        state_before = "?"
        try:
            state_before = to_h2.state_machine.state.name
        except Exception:
            pass

        try:
            to_h2.close_connection(
                error_code=error_code or 0,
                last_stream_id=translated_last_id,
                additional_data=additional,
            )
        except Exception as e:
            logger.debug("Failed to forward GOAWAY: %s", e)

        # Log the post-call state at debug level — useful for tracing
        # the bug where _handle_goaway closes the receive-side h2 so
        # subsequent frames cause ProtocolError + HPACK index errors.
        try:
            state_after = to_h2.state_machine.state.name
            if state_after != state_before:
                logger.debug(
                    "[GOAWAY] %s-side state machine transitioned %s → %s",
                    "client" if from_side == "target" else "target",
                    state_before, state_after,
                )
        except Exception:
            pass

    def _finish_stream(
        self,
        client_stream_id: int,
        streams: _StreamMap,
        captures: dict[int, _ResponseCapture],
        *,
        deliver_partial: bool = False,
    ) -> None:
        """Pop a stream's capture (if any), deliver it, and remove the stream.

        ``deliver_partial=False`` (the default) delivers any non-None capture —
        used when the response completed normally (StreamEnded, TrailersReceived,
        DataReceived with end_stream).

        ``deliver_partial=True`` only delivers if the capture has at least a
        status code — used during GOAWAY teardown where we want to surface
        partial responses but not empty placeholders.
        """
        # Cancel this stream's idle-reap timer before it leaves the map.
        # Centralised here so every finish path (StreamEnded, RST, GOAWAY,
        # and the reaper's own _fire) releases the TimerHandle exactly once.
        stream = streams.get_by_client(client_stream_id)
        if stream is not None:
            _StreamReaper.disarm(stream)
        capture = captures.pop(client_stream_id, None)
        if capture is not None:
            if not deliver_partial or capture.status_code:
                self._proxy.policy.deliver_capture(capture)
        streams.remove_by_client(client_stream_id)

    @staticmethod
    def _forward_data_with_backpressure(
        data: bytes,
        end_stream: bool,
        sender_h2: h2.connection.H2Connection,
        sender_stream_id: int,
        sender_payload_length: int,
        receiver_h2: h2.connection.H2Connection,
        receiver_stream_id: int,
        direction: "_Direction",
    ) -> None:
        """Forward DATA from one h2 connection to another with end-to-end
        backpressure.

        Naïve forwarding ACKs the sender as soon as bytes arrive at us
        (so the sender refills its window) and then tries to send to the
        receiver — which fails with ``Cannot send X bytes, flow control
        window is 0`` whenever the receiver hasn't refilled OUR window
        toward them yet.  Bytes pile up on us, the sender keeps sending,
        and the connection breaks.

        The fix: forward FIRST, ACK to sender SECOND.  If forwarding
        fully succeeds, ACK the original payload length so the sender
        gets its window back.  If forwarding only partially succeeds
        (window allows N < len bytes), send N bytes, queue the
        remainder in *direction.pending*, and accumulate the deferred-ACK
        amount.  When ``WindowUpdated`` later fires for this stream,
        :meth:`_drain_pending_with_backpressure` flushes the queue and
        releases the deferred ACK proportionally.

        This produces real end-to-end backpressure: the sender only sees
        "send more" after we've actually moved their bytes through us.

        The ``sender_payload_length`` is the value we'd pass to
        ``acknowledge_received_data`` — ``flow_controlled_length`` from
        the original event, which differs from ``len(data)`` because
        h2's flow accounting includes padding bytes.
        """
        # If we already have queued data for this stream, append to the
        # tail to preserve ordering.  Don't try to send anything new —
        # let the WindowUpdated handler drain in order.
        if direction.pending:
            direction.pending.extend(data)
            if end_stream:
                direction.pending_end = True
            direction.deferred_ack += sender_payload_length
            return

        # Try to send the whole payload
        try:
            window = receiver_h2.local_flow_control_window(receiver_stream_id)
        except Exception:
            # Stream gone or invalid — ACK the sender and drop silently
            sender_h2.acknowledge_received_data(
                sender_payload_length, sender_stream_id
            )
            return

        if len(data) <= window:
            # Whole payload fits.  Send and ACK fully.
            try:
                receiver_h2.send_data(
                    receiver_stream_id, data, end_stream=end_stream,
                )
            except Exception as e:
                logger.trace(
                    "send_data (stream %d) failed: %s",
                    receiver_stream_id, e,
                )
                # Don't ACK if the send failed — sender shouldn't refill.
                return
            sender_h2.acknowledge_received_data(
                sender_payload_length, sender_stream_id
            )
            return

        # Partial: send what fits, queue the remainder, defer the ACK
        # for the queued bytes.
        sent = 0
        if window > 0:
            try:
                receiver_h2.send_data(
                    receiver_stream_id, data[:window], end_stream=False,
                )
                sent = window
            except Exception as e:
                logger.trace(
                    "send_data (partial, stream %d) failed: %s",
                    receiver_stream_id, e,
                )

        # ACK only the bytes we actually moved through; defer the rest
        # by accumulating into deferred_ack and adding the unsent tail
        # to the pending buffer.
        if sent > 0:
            # Proportional ACK: bytes flow-controlled / total bytes
            # delivered.  For padded frames len(data) <= flow_controlled_length;
            # we ACK proportionally so the sender's window matches what
            # actually moved through.
            ratio = sent / len(data)
            ack_now = int(sender_payload_length * ratio)
            sender_h2.acknowledge_received_data(ack_now, sender_stream_id)
            direction.deferred_ack += sender_payload_length - ack_now
        else:
            direction.deferred_ack += sender_payload_length

        direction.pending.extend(data[sent:])
        if end_stream:
            direction.pending_end = True

    @staticmethod
    def _drain_pending_with_backpressure(
        sender_h2: h2.connection.H2Connection,
        sender_stream_id: int,
        receiver_h2: h2.connection.H2Connection,
        receiver_stream_id: int,
        direction: "_Direction",
    ) -> bool:
        """Flush as much of the pending buffer as the receiver's window
        now allows, releasing deferred ACKs proportionally.

        Returns ``True`` if the buffer was fully drained (the caller can
        then clear ``pending_*_end`` and treat the stream as caught up).
        """
        if not direction.pending:
            return True

        try:
            window = receiver_h2.local_flow_control_window(receiver_stream_id)
        except Exception:
            return False

        if window <= 0:
            return False

        starting_pending = len(direction.pending)
        starting_deferred = direction.deferred_ack

        if len(direction.pending) <= window:
            # Drain it all.  END_STREAM goes on the final flush.
            chunk = bytes(direction.pending)
            try:
                receiver_h2.send_data(
                    receiver_stream_id, chunk,
                    end_stream=direction.pending_end,
                )
            except Exception as e:
                logger.trace(
                    "drain_pending send_data (stream %d) failed: %s",
                    receiver_stream_id, e,
                )
                return False
            direction.pending.clear()
            # Release the entire deferred ACK
            if starting_deferred > 0:
                sender_h2.acknowledge_received_data(
                    starting_deferred, sender_stream_id,
                )
                direction.deferred_ack = 0
            return True

        # Partial drain
        chunk = bytes(direction.pending[:window])
        del direction.pending[:window]
        try:
            receiver_h2.send_data(receiver_stream_id, chunk, end_stream=False)
        except Exception as e:
            logger.trace(
                "drain_pending send_data (partial, stream %d) failed: %s",
                receiver_stream_id, e,
            )
            return False
        # Release proportional ACK based on how much of the original
        # pending we just drained.
        if starting_deferred > 0:
            ratio = window / starting_pending
            ack_now = int(starting_deferred * ratio)
            if ack_now > 0:
                sender_h2.acknowledge_received_data(
                    ack_now, sender_stream_id,
                )
                direction.deferred_ack = starting_deferred - ack_now
        return False

    async def _process_client_event(
        self,
        event: h2.events.Event,
        client_h2: h2.connection.H2Connection,
        target_h2: h2.connection.H2Connection,
        streams: _StreamMap,
        captures: dict[int, _ResponseCapture],
        draining: set[h2.connection.H2Connection],
        target_host: str,
        reaper: "_StreamReaper",
    ) -> None:
        """Handle a single h2 event from the browser side.

        Concurrency invariant
        ~~~~~~~~~~~~~~~~~~~~~~~
        Two pump tasks (client→target and target→client) run on the same
        event loop and both mutate the shared ``streams`` and ``captures``
        maps.  This is safe because event processing never actually yields
        to the loop.  The h2 calls in every branch are synchronous.  The
        one ``await`` here — ``await self._handle_goaway(...)`` — looks
        like a suspension point but isn't: ``_handle_goaway`` contains no
        ``await`` of its own, so awaiting it drives the coroutine to
        completion inline without ever returning control to the scheduler.
        The other pump therefore cannot interleave, and event handling is
        effectively atomic.

        This is correct but fragile.  If you add a *real* suspension point
        (socket I/O, ``asyncio.sleep``, an async lock, ``await`` on a
        future) inside any branch here, in ``_process_target_event``, or
        inside ``_handle_goaway``, the await starts genuinely yielding and
        the other pump can observe half-updated shared state.  Take an
        explicit lock or restructure before introducing one.
        """

        if isinstance(event, h2.events.RequestReceived):
            client_stream_id = event.stream_id

            # Refuse new streams if the target already GOAWAY'd on this tunnel.
            # REFUSED_STREAM is the spec-defined signal to retry on a fresh conn;
            # the browser should have just received our forwarded GOAWAY and will
            # open a new CONNECT for the retry.
            if target_h2 in draining:
                try:
                    client_h2.reset_stream(
                        client_stream_id,
                        error_code=h2.errors.ErrorCodes.REFUSED_STREAM,
                    )
                except Exception as e:
                    logger.trace(
                        "REFUSED_STREAM reset failed (client_stream_id=%d): %s",
                        client_stream_id, e,
                    )
                return

            if len(streams) >= self.config.max_streams_per_connection:
                client_h2.reset_stream(
                    client_stream_id,
                    error_code=h2.errors.ErrorCodes.REFUSED_STREAM,
                )
                return

            # Build the protocol-agnostic request view straight from the
            # wire pairs (h2 already carries the four pseudo-headers in the
            # block; the view splits them into typed fields).  bytes in,
            # bytes out — no str round-trip.
            view = RequestHeaders(
                [(_b2(k), _b2(v)) for k, v in event.headers]
            )

            path = view.path or "/"
            authority = view.authority or target_host
            scheme = view.scheme or "https"
            method = view.method

            if not method:
                client_h2.reset_stream(
                    client_stream_id,
                    error_code=h2.errors.ErrorCodes.PROTOCOL_ERROR,
                )
                return

            url = f"{scheme}://{authority}{path}"
            socks = self._proxy.socks_proxy.get_proxy()
            logger.trace(
                "[REQ] %s %s via %s (h2 stream %d)",
                method,
                url,
                socks or "direct",
                client_stream_id,
            )
            view = self._proxy.policy.transform_request_headers(url, view)
            # HTTP/2 forbids connection-level headers in a HEADERS frame
            # (RFC 9113 §8.2.2).  This is a framing rule the h2 handler owns
            # — not policy hygiene — so we enforce it here on the way to the
            # wire, dropping any the client sent or a policy added.
            modified = [
                (k, v) for k, v in view.to_pairs()
                if k.lower() not in _H2_FORBIDDEN
            ]

            target_stream_id = target_h2.get_next_available_stream_id()
            stream = Http2Stream(
                client_stream_id=client_stream_id,
                target_stream_id=target_stream_id,
                authority=authority,
                path=path,
                scheme=scheme,
                created_at=time.monotonic(),
            )
            streams.add(stream)
            reaper.arm(stream)

            # Start capture if URL is being intercepted
            capture = self._proxy.policy.open_capture(url)
            if capture:
                captures[client_stream_id] = capture

            end_stream = event.stream_ended is not None

            # Preserve Chrome's inline PRIORITY from the HEADERS frame.
            #
            # When a HEADERS frame carries the PRIORITY flag (0x20), h2 embeds
            # the priority in event.priority_updated AND appends a standalone
            # PriorityUpdated to the same events list.  We pass the inline
            # priority to send_headers so the PRIORITY flag appears on the
            # outgoing HEADERS frame — matching Chrome's wire format exactly.
            #
            # We also set _had_inline_priority so the subsequent PriorityUpdated
            # handler skips calling prioritize(), which would emit a redundant
            # standalone PRIORITY frame.  That extra frame shifts the Akamai
            # fingerprint from the correct |0|m,a,s,p to the broken |m,a,s,p1:220.
            pu = event.priority_updated
            if pu is not None:
                stream._had_inline_priority = True
            target_h2.send_headers(
                target_stream_id,
                modified,
                end_stream=end_stream,
                priority_weight=pu.weight if pu is not None else None,
                priority_depends_on=pu.depends_on if pu is not None else None,
                priority_exclusive=pu.exclusive if pu is not None else None,
            )

        elif isinstance(event, h2.events.DataReceived):
            stream = streams.get_by_client(event.stream_id)
            if stream:
                stream.last_activity = time.monotonic()
                # Backpressured forward: send to target FIRST, ACK
                # browser only after we've actually moved bytes through.
                # See ``_forward_data_with_backpressure`` for why naïve
                # ACK-then-send breaks Cloudflare uploads.
                self._forward_data_with_backpressure(
                    data=event.data,
                    end_stream=event.stream_ended is not None,
                    sender_h2=client_h2,
                    sender_stream_id=event.stream_id,
                    sender_payload_length=event.flow_controlled_length,
                    receiver_h2=target_h2,
                    receiver_stream_id=stream.target_stream_id,
                    direction=stream.to_target,
                )

        elif isinstance(event, h2.events.StreamReset):
            stream = streams.get_by_client(event.stream_id)
            if stream:
                try:
                    target_h2.reset_stream(
                        stream.target_stream_id, event.error_code
                    )
                except Exception as e:
                    logger.trace(
                        "target reset_stream failed (target_stream_id=%d): %s",
                        stream.target_stream_id, e,
                    )
                # Browser-initiated reset (user cancelled, navigation, etc).
                # Deliver any partial capture so an interceptor isn't left
                # hanging.  In the common case (cancel before any response
                # bytes), status_code is 0 and the capture is dropped
                # silently — _finish_stream's deliver_partial path handles
                # both cases uniformly.
                self._finish_stream(
                    stream.client_stream_id, streams, captures,
                    deliver_partial=True,
                )

        elif isinstance(event, h2.events.ConnectionTerminated):
            # Note: we do NOT add client_h2 to `draining` here.
            # `draining` exists so that target-side GOAWAY can refuse
            # subsequent browser RequestReceived events that race the
            # GOAWAY in flight.  The reverse direction has no race —
            # browsers don't initiate new streams after sending their
            # own GOAWAY — so adding here would be dead code.
            await self._handle_goaway(
                event,
                from_side="client",
                to_h2=target_h2,
                streams=streams,
                captures=captures,
            )

        elif isinstance(event, h2.events.PriorityUpdated):
            # Browser sent a standalone PRIORITY frame.
            #
            # Note: inline PRIORITY from a HEADERS frame is handled above
            # via event.priority_updated on RequestReceived, NOT here.
            # h2 only fires PriorityUpdated as a top-level event for
            # standalone PRIORITY frames.
            #
            # RFC 9113 §5.3.1 deprecates HTTP/2 priority in favour of the
            # Priority header — most modern servers ignore PRIORITY frames —
            # but forwarding preserves the wire-level fingerprint Chrome
            # presents to the origin.
            #
            # h2 emits PriorityUpdated for stream_id 0 in some edge
            # cases; only forward when there is a known stream.
            #
            # depends_on carries a *client-side* stream ID.  Remap it to
            # the corresponding target-side stream ID before forwarding;
            # 0 means "no dependency" and passes through as-is.
            stream = streams.get_by_client(event.stream_id) if event.stream_id else None
            if stream:
                # If this PriorityUpdated came from a HEADERS frame with
                # inline PRIORITY (h2 appends it to the events list even
                # when priority was already embedded in the HEADERS frame),
                # the priority was already sent inline via send_headers above.
                # Calling prioritize() here would emit a redundant standalone
                # PRIORITY frame, corrupting the Akamai H2 fingerprint by
                # adding a spurious |stream:weight| suffix after the header
                # order (e.g. |m,a,s,p1:220 instead of |0|m,a,s,p).
                if stream._had_inline_priority:
                    stream._had_inline_priority = False
                else:
                    raw_dep = event.depends_on or 0
                    if raw_dep != 0:
                        dep_stream = streams.get_by_client(raw_dep)
                        target_dep = dep_stream.target_stream_id if dep_stream else 0
                    else:
                        target_dep = 0
                    try:
                        target_h2.prioritize(
                            stream_id=stream.target_stream_id,
                            weight=event.weight,
                            depends_on=target_dep,
                            exclusive=event.exclusive,
                        )
                    except (h2.exceptions.ProtocolError, ValueError) as e:
                        # prioritize() rejects self-dependency and other
                        # malformed inputs; drop the frame rather than
                        # tearing down the stream — PRIORITY is advisory.
                        logger.trace(
                            "PRIORITY forward dropped (client=%d, target=%d): %s",
                            event.stream_id, stream.target_stream_id, e,
                        )

        elif isinstance(event, h2.events.RemoteSettingsChanged):
            # Browser changed its SETTINGS mid-session (rare but legal
            # per RFC 9113 §6.5).  The h2 library has already applied
            # the change to client_h2's state — INITIAL_WINDOW_SIZE
            # shifts, MAX_FRAME_SIZE constraint, HPACK encoder bound,
            # etc., per §6.9.2 — and queued a SETTINGS ACK back to the
            # browser.  We need to propagate the SAME change to target_h2
            # so the target sees a consistent view.
            #
            # ``update_settings`` queues a SETTINGS frame on target_h2's
            # outbound buffer.  h2 will apply the change to target_h2's
            # local_settings when the target ACKs (per §6.5.3) — at that
            # point ``_local_settings_acked`` runs and updates flow
            # control, the HPACK decoder's max_allowed_table_size /
            # max_header_list_size, and the inbound frame-size limit,
            # all automatically.  We don't need to touch any of that
            # ourselves; the wholesale-replacement trick used at startup
            # in ``_build_client_h2`` / ``_build_target_h2_from_browser_preface``
            # bypasses ``_local_settings_acked`` and requires manual
            # syncing, but that doesn't apply here.
            mirrored: dict[int, int] = {}
            for setting_code, change in event.changed_settings.items():
                code = int(setting_code)
                # Skip ENABLE_PUSH: we pin it to 0 for the target at
                # connection setup and don't re-enable mid-session.
                if code == h2.settings.SettingCodes.ENABLE_PUSH:
                    continue
                mirrored[code] = change.new_value
            if mirrored:
                try:
                    target_h2.update_settings(mirrored)
                except h2.exceptions.ProtocolError as e:
                    logger.warning(
                        "[HTTP/2] failed to mirror browser SETTINGS to target: %s",
                        e,
                    )

        elif isinstance(event, h2.events.PushedStreamReceived):
            # Browser pushed a stream TO US.  This should never happen:
            # clients don't initiate push, only servers do.  RFC 9113
            # §8.4 — if a server (we look like one to the browser) does
            # not enable push it will not receive PUSH_PROMISE, and we
            # advertise ENABLE_PUSH=0.  Defensive RST in case some
            # browser sends it anyway.
            try:
                if event.pushed_stream_id is not None:
                    client_h2.reset_stream(
                        event.pushed_stream_id,
                        error_code=h2.errors.ErrorCodes.REFUSED_STREAM,
                    )
            except Exception as e:
                logger.trace("RST of unexpected client push failed: %s", e)

        elif isinstance(event, h2.events.WindowUpdated):
            # Browser refilled the window for client_h2's outgoing direction
            # (proxy → browser).  Drain anything we have queued for the
            # browser direction.  stream_id 0 = connection-level update.
            target_streams_to_drain: list[Http2Stream] = []
            if event.stream_id == 0:
                target_streams_to_drain = [
                    s for s in streams.values() if s.to_client.pending
                ]
            else:
                s = streams.get_by_client(event.stream_id)
                if s and s.to_client.pending:
                    target_streams_to_drain = [s]

            for s in target_streams_to_drain:
                drained = self._drain_pending_with_backpressure(
                    sender_h2=target_h2,
                    sender_stream_id=s.target_stream_id,
                    receiver_h2=client_h2,
                    receiver_stream_id=s.client_stream_id,
                    direction=s.to_client,
                )
                if drained and s.to_client.pending_end:
                    # Queued END_STREAM has now been flushed; finish.
                    self._finish_stream(
                        s.client_stream_id, streams, captures,
                    )

    async def _process_target_event(
        self,
        event: h2.events.Event,
        client_h2: h2.connection.H2Connection,
        target_h2: h2.connection.H2Connection,
        streams: _StreamMap,
        captures: dict[int, _ResponseCapture],
        draining: set[h2.connection.H2Connection],
    ) -> None:
        """Handle a single h2 event from the target side.

        Uses ``streams.get_by_target()`` for O(1) lookup instead of the
        previous O(n) linear scan.
        """

        if isinstance(event, h2.events.InformationalResponseReceived):
            # 1xx responses (100 Continue, 103 Early Hints, etc.) per
            # RFC 9113 §8.1.  These arrive BEFORE the final response on
            # the same stream and must not end the stream — the final
            # 200/etc. follows.  h2 emits this as a distinct event class
            # specifically so we don't accidentally treat the 1xx as the
            # final response.
            #
            # Cloudflare and other modern CDNs use 103 Early Hints to
            # preload critical CSS/JS before the origin produces the
            # final response.  Dropping these silently (the prior
            # behaviour) measurably slows page load on those sites.
            stream = streams.get_by_target(event.stream_id)
            if stream:
                stream.last_activity = time.monotonic()
                # send_headers without end_stream — the final response
                # follows on the same stream.  Routed through the same
                # ``transform_response`` hook so policy (Alt-Svc stripping,
                # and any header rule the user targeted at this URL) runs
                # uniformly on 1xx and 2xx alike.
                hdrs = ResponseHeaders([(_b2(k), _b2(v)) for k, v in event.headers])
                hdrs = self._proxy.policy.transform_response_headers(stream.url, hdrs)
                try:
                    client_h2.send_headers(
                        stream.client_stream_id, hdrs.to_pairs(), end_stream=False,
                    )
                except h2.exceptions.ProtocolError as e:
                    # h2 will reject a 1xx if state doesn't allow it
                    # (e.g. final response already sent).  Log and drop;
                    # the final response will still flow.
                    logger.debug(
                        "[HTTP/2] 1xx forward rejected (client_stream=%d): %s",
                        stream.client_stream_id, e,
                    )

        elif isinstance(event, h2.events.ResponseReceived):
            stream = streams.get_by_target(event.stream_id)
            if stream:
                stream.last_activity = time.monotonic()
                # Policy hook: hygiene (h3 Alt-Svc strip) plus any matching
                # response header rule.  ``ResponseHeaders`` exposes the
                # status as the typed ``.status`` field; on serialise it
                # re-emits ``:status`` first, native to the h2 block.
                hdrs = ResponseHeaders([(_b2(k), _b2(v)) for k, v in event.headers])
                # Record the ORIGINAL wire response for capture BEFORE the
                # policy transform runs, so an interceptor sees the unmodified
                # upstream response rather than the browser-facing version.
                # extend() copies the (immutable) byte-pair tuples into the
                # capture's own list, so the in-place transform below can't
                # reach back into it.
                capture = captures.get(stream.client_stream_id)
                if capture:
                    if hdrs.status is not None:
                        capture.status_code = hdrs.status
                    capture.headers.extend(hdrs.items())
                hdrs = self._proxy.policy.transform_response_headers(stream.url, hdrs)
                client_h2.send_headers(
                    stream.client_stream_id,
                    hdrs.to_pairs(),
                    end_stream=event.stream_ended is not None,
                )

        elif isinstance(event, h2.events.DataReceived):
            stream = streams.get_by_target(event.stream_id)
            if stream:
                stream.last_activity = time.monotonic()
                # Do NOT pre-ACK here.  ``_forward_data_with_backpressure``
                # owns the ``acknowledge_received_data`` call (see its
                # docstring: "forward FIRST, ACK to sender SECOND").  A
                # pre-ACK at this point double-acks target_h2's flow-
                # control window: the origin sees +2N receive window
                # advertised for every N bytes we actually consumed,
                # oversends until ``to_client.pending`` overflows, and
                # eventually tears the stream down with FLOW_CONTROL_ERROR.
                # The client-side equivalent in _process_client_event
                # correctly defers ACK'ing to the helper — keep this side
                # symmetric.
                end = event.stream_ended is not None
                # Capture body bytes regardless of whether they get
                # forwarded immediately — interception sees the full
                # response even if backpressure delays it.
                capture = captures.get(stream.client_stream_id)
                if capture:
                    capture.body.extend(event.data)

                # Backpressured forward toward the browser.
                self._forward_data_with_backpressure(
                    data=event.data,
                    end_stream=end,
                    sender_h2=target_h2,
                    sender_stream_id=event.stream_id,
                    sender_payload_length=event.flow_controlled_length,
                    receiver_h2=client_h2,
                    receiver_stream_id=stream.client_stream_id,
                    direction=stream.to_client,
                )
                # Only finish the stream if END_STREAM was set AND the
                # buffer is empty (i.e. the END_STREAM bit actually
                # made it onto a frame).  If to_client still has
                # bytes, the END_STREAM is queued and _drain_pending
                # will fire it later.
                if end and not stream.to_client.pending:
                    self._finish_stream(
                        stream.client_stream_id, streams, captures,
                    )

        elif isinstance(event, h2.events.StreamEnded):
            stream = streams.get_by_target(event.stream_id)
            if stream:
                try:
                    client_h2.end_stream(stream.client_stream_id)
                except Exception as e:
                    logger.trace(
                        "client end_stream failed (client_stream_id=%d): %s",
                        stream.client_stream_id, e,
                    )
                self._finish_stream(stream.client_stream_id, streams, captures)

        elif isinstance(event, h2.events.StreamReset):
            stream = streams.get_by_target(event.stream_id)
            if stream:
                try:
                    client_h2.reset_stream(
                        stream.client_stream_id, event.error_code
                    )
                except Exception as e:
                    logger.trace(
                        "client reset_stream failed (client_stream_id=%d): %s",
                        stream.client_stream_id, e,
                    )
                # Deliver a partial capture if at least a status arrived,
                # so an interceptor waiting on cap.get() is unblocked
                # immediately instead of hanging until its timeout.
                # If no status was received, the capture is dropped — an
                # empty InterceptedResponse would be more confusing than
                # the timeout it replaces.
                self._finish_stream(
                    stream.client_stream_id, streams, captures,
                    deliver_partial=True,
                )

        elif isinstance(event, h2.events.TrailersReceived):
            stream = streams.get_by_target(event.stream_id)
            if stream:
                stream.last_activity = time.monotonic()
                client_h2.send_headers(
                    stream.client_stream_id, event.headers, end_stream=True
                )
                # Trailers always signal end-of-stream (HTTP/2 §8.1): the
                # END_STREAM flag is required on the trailing HEADERS frame.
                self._finish_stream(stream.client_stream_id, streams, captures)

        elif isinstance(event, h2.events.ConnectionTerminated):
            # Mark this target as draining. Any new RequestReceived that races
            # the GOAWAY will be refused so the browser retries on a fresh conn.
            draining.add(target_h2)
            await self._handle_goaway(
                event,
                from_side="target",
                to_h2=client_h2,
                streams=streams,
                captures=captures,
            )

        elif isinstance(event, h2.events.PriorityUpdated):
            # Target sent PRIORITY toward us.  Forward to the browser so
            # the browser's stream dependency tree stays in sync with
            # what the origin advertised.  Targets very rarely send
            # PRIORITY (deprecated per RFC 9113 §5.3.1), but forward for
            # completeness.
            stream = streams.get_by_target(event.stream_id) if event.stream_id else None
            if stream:
                try:
                    client_h2.prioritize(
                        stream_id=stream.client_stream_id,
                        weight=event.weight,
                        depends_on=event.depends_on,
                        exclusive=event.exclusive,
                    )
                except (h2.exceptions.ProtocolError, ValueError) as e:
                    logger.trace(
                        "PRIORITY forward dropped (target=%d, client=%d): %s",
                        event.stream_id, stream.client_stream_id, e,
                    )

        elif isinstance(event, h2.events.RemoteSettingsChanged):
            # Target changed its SETTINGS mid-session.  h2 has already
            # applied the change to target_h2's state and queued a
            # SETTINGS ACK back to the target.  Mirror toward the
            # browser so its view stays consistent with the target.
            # h2 handles flow-control adjustment, HPACK decoder sync,
            # etc., on the browser's ACK — see the matching client-side
            # branch for the full explanation.
            mirrored: dict[int, int] = {}
            for setting_code, change in event.changed_settings.items():
                code = int(setting_code)
                if code == h2.settings.SettingCodes.ENABLE_PUSH:
                    # Don't propagate the target's ENABLE_PUSH choice to
                    # the browser — the browser already declared its own
                    # value at connection setup.  (And clients don't
                    # accept ENABLE_PUSH from peers; SETTINGS frames
                    # with ENABLE_PUSH set on a client receive are a
                    # PROTOCOL_ERROR per §6.5.2.)
                    continue
                mirrored[code] = change.new_value
            if mirrored:
                try:
                    client_h2.update_settings(mirrored)
                except h2.exceptions.ProtocolError as e:
                    logger.warning(
                        "[HTTP/2] failed to mirror target SETTINGS to browser: %s",
                        e,
                    )

        elif isinstance(event, h2.events.PushedStreamReceived):
            # Target initiated a server push (PUSH_PROMISE).  We advertise
            # ENABLE_PUSH=0 to the target in our initial SETTINGS so
            # compliant origins never send these — but a non-compliant
            # origin might.  Refuse the push by RST'ing it on the target
            # side; this is per RFC 9113 §8.4 (a client that doesn't
            # want a push refuses with REFUSED_STREAM).
            #
            # We don't try to forward the promise to the browser because
            # the browser is also seeing ENABLE_PUSH=0 in our mirrored
            # settings, so it wouldn't accept the push anyway.
            try:
                if event.pushed_stream_id is not None:
                    target_h2.reset_stream(
                        event.pushed_stream_id,
                        error_code=h2.errors.ErrorCodes.REFUSED_STREAM,
                    )
            except Exception as e:
                logger.trace(
                    "RST of unwanted target push failed (pushed=%d): %s",
                    event.pushed_stream_id, e,
                )

        elif isinstance(event, h2.events.WindowUpdated):
            # Target refilled the window for target_h2's outgoing direction
            # (proxy → target).  Drain anything we have queued for the
            # target direction.  stream_id 0 = connection-level update.
            target_streams_to_drain: list[Http2Stream] = []
            if event.stream_id == 0:
                target_streams_to_drain = [
                    s for s in streams.values() if s.to_target.pending
                ]
            else:
                s = streams.get_by_target(event.stream_id)
                if s and s.to_target.pending:
                    target_streams_to_drain = [s]

            for s in target_streams_to_drain:
                drained = self._drain_pending_with_backpressure(
                    sender_h2=client_h2,
                    sender_stream_id=s.client_stream_id,
                    receiver_h2=target_h2,
                    receiver_stream_id=s.target_stream_id,
                    direction=s.to_target,
                )
                if drained:
                    s.to_target.pending_end = False
