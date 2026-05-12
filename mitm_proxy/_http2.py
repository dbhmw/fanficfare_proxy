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
from typing import TYPE_CHECKING, Callable, Optional

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.settings
from hyperframe.frame import Frame as _HF_Frame
from hyperframe.exceptions import UnknownFrameError as _HF_UnknownFrameError

from ._common import logger, ProxyConfig, DEFAULT_CONFIG
from ._interceptor import _ResponseCapture
from ._io import ManagedConnection

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
        "url",
        # Per-direction pending buffers + deferred-ACK counters.
        # When we receive DATA on one side but the OTHER side's outgoing
        # window won't accommodate it, we buffer here and defer the
        # WINDOW_UPDATE ACK to the sender.  The sender then naturally
        # backpressures because we're not telling them they have more
        # window until we've actually moved their bytes through.
        #
        # See ``Http2Handler._forward_data_with_backpressure`` for the
        # full protocol — this is where the actual flow control gets
        # plumbed end-to-end across the two h2 connections.
        "pending_to_target",        # bytes from browser, awaiting target window
        "pending_to_target_end",    # was END_STREAM set on the queued tail?
        "deferred_ack_to_client",   # bytes we owe the browser as WINDOW_UPDATE
        "pending_to_client",        # bytes from target, awaiting browser window
        "pending_to_client_end",    # was END_STREAM set on the queued tail?
        "deferred_ack_to_target",   # bytes we owe the target as WINDOW_UPDATE
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
        self.url = f"{scheme}://{authority}{path}"
        self.pending_to_target: bytearray = bytearray()
        self.pending_to_target_end: bool = False
        self.deferred_ack_to_client: int = 0
        self.pending_to_client: bytearray = bytearray()
        self.pending_to_client_end: bool = False
        self.deferred_ack_to_target: int = 0


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
        draining: set[h2.connection.H2Connection] = set()

        try:
            client_task = asyncio.create_task(
                self._pump(
                    "client",
                    client_io, target_io, client_h2, target_h2,
                    streams, captures, draining, target_host,
                )
            )
            target_task = asyncio.create_task(
                self._pump(
                    "target",
                    client_io, target_io, client_h2, target_h2,
                    streams, captures, draining, target_host,
                )
            )
            timeout_task = asyncio.create_task(
                self._check_stream_timeouts(
                    streams, captures, client_h2, target_h2, client_io, target_io
                )
            )

            done, pending = await asyncio.wait(
                [client_task, target_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            for t in done:
                exc = t.exception()
                if exc:
                    logger.debug("[HTTP/2 %s] Task exc: %s", target_host, exc)

            for t in pending:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass

            # GOAWAY frames buffered by _process_*_event are flushed to
            # both sides on each pump iteration via _flush_both, so by
            # the time we get here, in-flight bytes are already on the wire.
            # The pump loops exit on EOF or idle timeout — no extra flush
            # needed.

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
            # interceptors blocked on capture.get() are unblocked immediately
            # instead of hanging until their timeout.
            for _, capture in list(captures.items()):
                if capture.status_code:
                    self._proxy.policy.deliver_capture(capture)
            captures.clear()
            streams.clear()

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
            # h2 returns 2**32+1 (effectively unlimited) when the peer
            # didn't send MAX_CONCURRENT_STREAMS.  Only mirror values
            # that look like a real per-peer limit; otherwise fall back
            # to Chrome's typical advertised cap of 100.
            if mcs < 1024:
                initial_values[
                    h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS
                ] = mcs
            else:
                initial_values[
                    h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS
                ] = 100
            mhls = mirror_from.max_header_list_size
            if mhls is not None:
                initial_values[
                    h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE
                ] = mhls

            conn.local_settings = h2.settings.Settings(
                client=False,
                initial_values=initial_values,
            )
            # Sync the HPACK decoder to the mirrored table size.  h2
            # doesn't auto-update this when local_settings is replaced
            # post-construction.  Mismatch causes "Invalid table index
            # N" errors when the browser's encoder thinks the table is
            # bigger than our decoder allows.
            conn.decoder.max_allowed_table_size = mirror_from.header_table_size
            if mhls is not None:
                conn.decoder.max_header_list_size = mhls

        conn.initiate_connection()
        conn.increment_flow_control_window(15663105)
        return conn

    @staticmethod
    async def _read_browser_preface(
        client_io: ManagedConnection,
        timeout: float = 10.0,
    ) -> tuple[bytes, dict[int, int], int]:
        """Read the browser's HTTP/2 connection preface from the socket.

        The browser sends its preface as soon as TLS completes per
        RFC 7540 §3.5: a 24-byte magic string followed by a SETTINGS
        frame, optionally followed by an immediate WINDOW_UPDATE on
        stream 0 (Chrome does this to bump the connection-level
        receive window).

        Returns ``(raw_bytes, settings_dict, connection_window_increment)``:

        * ``raw_bytes`` — the exact bytes the browser sent.  These get
          forwarded verbatim to the target so the target sees the
          browser's true h2 fingerprint (Akamai H2 hash etc.) without
          us having to maintain a hand-rolled approximation that could
          drift with Chrome version updates.
        * ``settings_dict`` — the SETTINGS values parsed from the frame,
          used to configure our target-facing ``H2Connection``'s
          ``local_settings`` so its internal state matches the wire.
        * ``connection_window_increment`` — the value of the optional
          WINDOW_UPDATE on stream 0, or 0 if absent.  Applied via
          ``increment_flow_control_window`` to keep h2's accounting
          aligned with what the browser actually sent.

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
    ) -> tuple[bytes, dict[int, int], int]:
        """Parse SETTINGS [+ WINDOW_UPDATE] frames following the magic string.

        Implementation half of :meth:`_read_browser_preface`.  Reads
        until both control frames are consumed (SETTINGS is required,
        WINDOW_UPDATE is optional), then stops — leaving any subsequent
        HEADERS/DATA frames on the socket for ``_pump`` to consume
        normally.

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
                    return bytes(buf[:cursor]), settings_dict, window_increment
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

        return bytes(buf[:cursor]), settings_dict, window_increment

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
            # Sync the HPACK decoder to whatever HEADER_TABLE_SIZE the
            # browser declared.  h2 doesn't auto-update it when
            # local_settings is replaced post-construction.
            table_size = initial_values.get(
                h2.settings.SettingCodes.HEADER_TABLE_SIZE, 4096
            )
            conn.decoder.max_allowed_table_size = table_size
            mhls = initial_values.get(
                h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE
            )
            if mhls is not None:
                conn.decoder.max_header_list_size = mhls

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
            browser_preface_bytes, browser_settings, conn_window_inc = (
                await self._read_browser_preface(client_io)
            )
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

            # Step 3: Read target's SETTINGS so we can mirror them to
            # the browser side.
            async with asyncio.timeout(5.0):
                data = await target_io.reader.read(self.config.read_buffer_size)
                if data:
                    target_h2.receive_data(data)
                    ack = target_h2.data_to_send()
                    if ack:
                        target_io.writer.write(ack)
                        await target_io.writer.drain()

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

    async def _check_stream_timeouts(
        self,
        streams: _StreamMap,
        captures: dict[int, _ResponseCapture],
        client_h2: h2.connection.H2Connection,
        target_h2: h2.connection.H2Connection,
        client_io: ManagedConnection,
        target_io: ManagedConnection,
    ) -> None:
        """Periodically RST_STREAM any streams that have exceeded the timeout.

        Also pops the capture for each timed-out stream and delivers it if
        partial data was received — otherwise interceptors blocked on
        ``capture.get()`` would wait the full configured timeout instead
        of getting an early notification.
        """
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
                        client_h2.reset_stream(s.client_stream_id, error_code=8)
                        target_h2.reset_stream(s.target_stream_id, error_code=8)
                    except Exception as e:
                        logger.trace(
                            "stream-timeout reset failed (client=%d, target=%d): %s",
                            s.client_stream_id, s.target_stream_id, e,
                        )
                    self._finish_stream(
                        s.client_stream_id, streams, captures,
                        deliver_partial=True,
                    )
                if timed_out:
                    await self._flush_both(
                        client_io, target_io, client_h2, target_h2
                    )
        except asyncio.CancelledError:
            pass

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

        # Rolling history of frame summaries for diagnostic dumps when
        # something goes wrong.  Keeps the last N frames received on
        # this side; on ProtocolError we dump them to show what led up
        # to the failing frame.  Bounded so it can't grow unboundedly
        # on healthy long-lived connections.
        recent_frames: list[str] = []
        max_recent = 32

        while not io_in.closed:
            try:
                async with asyncio.timeout(self.config.idle_timeout):
                    data = await io_in.reader.read(self.config.read_buffer_size)
            except asyncio.TimeoutError:
                break
            if not data:
                break
            io_in.touch()

            # Per-buffer trace at TRACE level — very chatty, only useful
            # when actively debugging.  Keep behind isEnabledFor so we
            # don't pay the parsing cost when TRACE is off.
            if logger.isEnabledFor(5):
                logger.trace(
                    "[HTTP/2 %s sid=%s] %d bytes received: %s",
                    side, sid, len(data),
                    self._summarize_h2_frames(data),
                )

            # Maintain the rolling recent-frames buffer regardless of
            # log level — needed for the ProtocolError dump below.
            try:
                summary = self._summarize_h2_frames(data, max_frames=8)
                recent_frames.append(summary)
                if len(recent_frames) > max_recent:
                    del recent_frames[0]
            except Exception:
                # Frame parsing failed — don't let diagnostics crash
                # the pump loop.
                pass

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
                #   - the recent-frames history so we can see the
                #     conversation leading up to the error
                conn_state = "?"
                try:
                    conn_state = h2_in.state_machine.state.name
                except Exception:
                    pass
                logger.warning(
                    "[HTTP/2 %s sid=%s] ProtocolError: %s\n"
                    "  conn_state_before=%s\n"
                    "  failing_buffer=%s\n"
                    "  recent_frames (oldest first):\n    %s",
                    side, sid, e,
                    conn_state,
                    self._summarize_h2_frames(data),
                    "\n    ".join(recent_frames) or "(none)",
                )
                break

            for event in events:
                try:
                    if side == "client":
                        await self._process_client_event(
                            event, client_h2, target_h2,
                            streams, captures, draining, target_host,
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

    @staticmethod
    def _summarize_h2_frames(data: bytes, max_frames: int = 16) -> str:
        """Decode raw h2 wire bytes into a human-readable frame summary.

        Used for diagnostics when ``receive_data`` raises ProtocolError —
        the error message itself doesn't tell us which frame triggered
        it, only the state machine input (e.g. RECV_RST_STREAM).  This
        helper unpacks the buffer into ``[type stream_id flags body_len]``
        tuples so we can see exactly what arrived.

        Body bytes are NOT logged — only frame metadata.  Sensitive
        payload data (HEADERS, DATA) is summarised by length only.

        Returns a string like::

            [SETTINGS s=0 f=0x00 len=18, HEADERS s=1 f=0x05 len=42, RST_STREAM s=3 f=0x00 len=4]

        Truncates to *max_frames* entries with a "+N more" suffix to
        avoid enormous log lines on big buffers.
        """
        out: list[str] = []
        view = memoryview(data)
        cursor = 0
        truncated = 0

        # Skip the connection preface magic if present.  The magic is
        # not a frame and would otherwise be misinterpreted (its first
        # 3 bytes 'PRI' look like a frame length of 5263945).
        magic = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        if data[:len(magic)] == magic:
            out.append("MAGIC")
            cursor = len(magic)

        while cursor + 9 <= len(view):
            header = view[cursor:cursor + 9]
            try:
                frame, body_len = _HF_Frame.parse_frame_header(header)
            except _HF_UnknownFrameError as e:
                out.append(f"UNKNOWN(type=0x{e.frame_type:02x}) s=? len=?")
                break
            except Exception as e:
                out.append(f"<parse error: {e}>")
                break

            if cursor + 9 + body_len > len(view):
                out.append(
                    f"<incomplete: need {body_len} body bytes, "
                    f"have {len(view) - cursor - 9}>"
                )
                break

            ftype = type(frame).__name__.replace("Frame", "").upper() or "?"
            out.append(
                f"{ftype} s={frame.stream_id} "
                f"f=0x{int(frame.flags) if hasattr(frame.flags, '__int__') else 0:02x} " # pyright: ignore[reportArgumentType]
                f"len={body_len}"
            )

            cursor += 9 + body_len
            if len(out) >= max_frames:
                # Count remaining without parsing
                while cursor + 9 <= len(view):
                    try:
                        _, more_len = _HF_Frame.parse_frame_header(
                            view[cursor:cursor + 9]
                        )
                        cursor += 9 + more_len
                        truncated += 1
                    except Exception:
                        break
                break

        suffix = f", +{truncated} more" if truncated else ""
        if cursor < len(view):
            suffix += f" [{len(view) - cursor} trailing bytes]"
        return "[" + ", ".join(out) + suffix + "]"

    async def _flush_both(
        self,
        client_io: ManagedConnection,
        target_io: ManagedConnection,
        client_h2: h2.connection.H2Connection,
        target_h2: h2.connection.H2Connection,
    ) -> None:
        """Send any pending h2 frame data to both sides."""
        client_pending = client_h2.data_to_send()
        target_pending = target_h2.data_to_send()
        if client_pending and not client_io.closed:
            client_io.writer.write(client_pending)
        if target_pending and not target_io.closed:
            target_io.writer.write(target_pending)
        coros = []
        if client_pending and not client_io.closed:
            coros.append(client_io.writer.drain())
        if target_pending and not target_io.closed:
            coros.append(target_io.writer.drain())
        if coros:
            await asyncio.gather(*coros, return_exceptions=True)

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
                    to_h2.reset_stream(getattr(stream, to_attr), error_code=7)
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
        pending_buffer: bytearray,
        get_pending_end: Callable[[], bool],
        set_pending_end: Callable[[bool], None],
        get_deferred_ack: Callable[[], int],
        set_deferred_ack: Callable[[int], None],
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
        remainder in *pending_buffer*, and accumulate the deferred-ACK
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
        if pending_buffer:
            pending_buffer.extend(data)
            if end_stream:
                set_pending_end(True)
            set_deferred_ack(get_deferred_ack() + sender_payload_length)
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
            set_deferred_ack(
                get_deferred_ack() + (sender_payload_length - ack_now)
            )
        else:
            set_deferred_ack(get_deferred_ack() + sender_payload_length)

        pending_buffer.extend(data[sent:])
        if end_stream:
            set_pending_end(True)

    @staticmethod
    def _drain_pending_with_backpressure(
        sender_h2: h2.connection.H2Connection,
        sender_stream_id: int,
        receiver_h2: h2.connection.H2Connection,
        receiver_stream_id: int,
        pending_buffer: bytearray,
        get_pending_end: Callable[[], bool],
        set_pending_end: Callable[[bool], None],
        get_deferred_ack: Callable[[], int],
        set_deferred_ack: Callable[[int], None],
    ) -> bool:
        """Flush as much of the pending buffer as the receiver's window
        now allows, releasing deferred ACKs proportionally.

        Returns ``True`` if the buffer was fully drained (the caller can
        then clear ``pending_*_end`` and treat the stream as caught up).
        """
        if not pending_buffer:
            return True

        try:
            window = receiver_h2.local_flow_control_window(receiver_stream_id)
        except Exception:
            return False

        if window <= 0:
            return False

        starting_pending = len(pending_buffer)
        starting_deferred = get_deferred_ack()

        if len(pending_buffer) <= window:
            # Drain it all.  END_STREAM goes on the final flush.
            chunk = bytes(pending_buffer)
            try:
                receiver_h2.send_data(
                    receiver_stream_id, chunk,
                    end_stream=get_pending_end(),
                )
            except Exception as e:
                logger.trace(
                    "drain_pending send_data (stream %d) failed: %s",
                    receiver_stream_id, e,
                )
                return False
            pending_buffer.clear()
            # Release the entire deferred ACK
            if starting_deferred > 0:
                sender_h2.acknowledge_received_data(
                    starting_deferred, sender_stream_id,
                )
                set_deferred_ack(0)
            return True

        # Partial drain
        chunk = bytes(pending_buffer[:window])
        del pending_buffer[:window]
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
                set_deferred_ack(starting_deferred - ack_now)
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
    ) -> None:
        """Handle a single h2 event from the browser side."""

        if isinstance(event, h2.events.RequestReceived):
            client_stream_id = event.stream_id

            # Refuse new streams if the target already GOAWAY'd on this tunnel.
            # REFUSED_STREAM is the spec-defined signal to retry on a fresh conn;
            # the browser should have just received our forwarded GOAWAY and will
            # open a new CONNECT for the retry.
            if target_h2 in draining:
                try:
                    client_h2.reset_stream(client_stream_id, error_code=7)  # REFUSED_STREAM
                except Exception as e:
                    logger.trace(
                        "REFUSED_STREAM reset failed (client_stream_id=%d): %s",
                        client_stream_id, e,
                    )
                return

            if len(streams) >= self.config.max_streams_per_connection:
                client_h2.reset_stream(client_stream_id, error_code=7)
                return

            # h2's RequestReceived.headers is typed as list[tuple[bytes, bytes]].
            # Decode directly; if h2 ever yields strings we'll get a clear
            # AttributeError pointing right at this line.
            headers: list[tuple[str, str]] = [
                (k.decode("utf-8", errors="replace"),
                 v.decode("utf-8", errors="replace"))
                for k, v in event.headers
            ]

            headers_lookup = {k.lower(): v for k, v in headers}
            path = headers_lookup.get(":path", "/")
            authority = headers_lookup.get(":authority", target_host)
            scheme = headers_lookup.get(":scheme", "https")
            method = headers_lookup.get(":method")

            if not method:
                client_h2.reset_stream(client_stream_id, error_code=1)
                return

            url = f"{scheme}://{authority}{path}"
            socks = self._proxy.socks_proxy
            logger.trace(
                "[REQ] %s %s via %s (h2 stream %d)",
                method,
                url,
                socks or "direct",
                client_stream_id,
            )
            modified = self._proxy.policy.transform_request_headers(
                url, headers, is_h2=True
            )

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

            # Start capture if URL is being intercepted
            capture = self._proxy.policy.open_capture(url)
            if capture:
                captures[client_stream_id] = capture

            end_stream = event.stream_ended is not None
            target_h2.send_headers(target_stream_id, modified, end_stream=end_stream)

        elif isinstance(event, h2.events.DataReceived):
            stream = streams.get_by_client(event.stream_id)
            if stream:
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
                    pending_buffer=stream.pending_to_target,
                    get_pending_end=lambda s=stream: s.pending_to_target_end,
                    set_pending_end=lambda v, s=stream: setattr(
                        s, "pending_to_target_end", v
                    ),
                    get_deferred_ack=lambda s=stream: s.deferred_ack_to_client,
                    set_deferred_ack=lambda v, s=stream: setattr(
                        s, "deferred_ack_to_client", v
                    ),
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

        elif isinstance(event, h2.events.WindowUpdated):
            # Browser refilled the window for client_h2's outgoing direction
            # (proxy → browser).  Drain anything we have queued for the
            # browser direction.  stream_id 0 = connection-level update.
            target_streams_to_drain: list[Http2Stream] = []
            if event.stream_id == 0:
                target_streams_to_drain = [
                    s for s in streams.values() if s.pending_to_client
                ]
            else:
                s = streams.get_by_client(event.stream_id)
                if s and s.pending_to_client:
                    target_streams_to_drain = [s]

            for s in target_streams_to_drain:
                drained = self._drain_pending_with_backpressure(
                    sender_h2=target_h2,
                    sender_stream_id=s.target_stream_id,
                    receiver_h2=client_h2,
                    receiver_stream_id=s.client_stream_id,
                    pending_buffer=s.pending_to_client,
                    get_pending_end=lambda ss=s: ss.pending_to_client_end,
                    set_pending_end=lambda v, ss=s: setattr(
                        ss, "pending_to_client_end", v
                    ),
                    get_deferred_ack=lambda ss=s: ss.deferred_ack_to_target,
                    set_deferred_ack=lambda v, ss=s: setattr(
                        ss, "deferred_ack_to_target", v
                    ),
                )
                if drained and s.pending_to_client_end:
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

        if isinstance(event, h2.events.ResponseReceived):
            stream = streams.get_by_target(event.stream_id)
            if stream:
                # Policy-driven response header transformation
                # (default: strips h3 from Alt-Svc).
                filtered_headers = self._proxy.policy.filter_response_headers(
                    event.headers
                )
                client_h2.send_headers(
                    stream.client_stream_id,
                    filtered_headers,
                    end_stream=event.stream_ended is not None,
                )
                capture = captures.get(stream.client_stream_id)
                if capture:
                    for k, v in filtered_headers:
                        key = (
                            k.decode("utf-8", errors="replace") if isinstance(k, bytes) else k
                        )
                        val = (
                            v.decode("utf-8", errors="replace") if isinstance(v, bytes) else v
                        )
                        if key == ":status":
                            try:
                                capture.status_code = int(val)
                            except ValueError:
                                logger.debug(
                                    "Malformed h2 :status %r", val,
                                )
                                capture.status_code = 0
                        else:
                            capture.headers.append((key, val))

        elif isinstance(event, h2.events.DataReceived):
            stream = streams.get_by_target(event.stream_id)
            if stream:
                target_h2.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
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
                    pending_buffer=stream.pending_to_client,
                    get_pending_end=lambda s=stream: s.pending_to_client_end,
                    set_pending_end=lambda v, s=stream: setattr(
                        s, "pending_to_client_end", v
                    ),
                    get_deferred_ack=lambda s=stream: s.deferred_ack_to_target,
                    set_deferred_ack=lambda v, s=stream: setattr(
                        s, "deferred_ack_to_target", v
                    ),
                )
                # Only finish the stream if END_STREAM was set AND the
                # buffer is empty (i.e. the END_STREAM bit actually
                # made it onto a frame).  If pending_to_client still has
                # bytes, the END_STREAM is queued and _drain_pending
                # will fire it later.
                if end and not stream.pending_to_client:
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

        elif isinstance(event, h2.events.WindowUpdated):
            # Target refilled the window for target_h2's outgoing direction
            # (proxy → target).  Drain anything we have queued for the
            # target direction.  stream_id 0 = connection-level update.
            target_streams_to_drain: list[Http2Stream] = []
            if event.stream_id == 0:
                target_streams_to_drain = [
                    s for s in streams.values() if s.pending_to_target
                ]
            else:
                s = streams.get_by_target(event.stream_id)
                if s and s.pending_to_target:
                    target_streams_to_drain = [s]

            for s in target_streams_to_drain:
                drained = self._drain_pending_with_backpressure(
                    sender_h2=client_h2,
                    sender_stream_id=s.client_stream_id,
                    receiver_h2=target_h2,
                    receiver_stream_id=s.target_stream_id,
                    pending_buffer=s.pending_to_target,
                    get_pending_end=lambda ss=s: ss.pending_to_target_end,
                    set_pending_end=lambda v, ss=s: setattr(
                        ss, "pending_to_target_end", v
                    ),
                    get_deferred_ack=lambda ss=s: ss.deferred_ack_to_client,
                    set_deferred_ack=lambda v, ss=s: setattr(
                        ss, "deferred_ack_to_client", v
                    ),
                )
                if drained:
                    s.pending_to_target_end = False
