"""Low-level I/O primitives: connection wrapper, SOCKS5 client, TLS context factory.

Everything in this module touches sockets or TLS state.  Nothing here
knows about HTTP — that's the next layer up.

* ``ManagedConnection`` — wraps an asyncio ``(reader, writer)`` pair
  with last-activity tracking and a robust close path that handles
  the SSL-already-dead edge case.
* ``Socks5Client`` — async SOCKS5 CONNECT client, no-auth method.
* ``SocksProxyPool`` — file-backed pool of SOCKS5 proxies, shared
  across many ``SessionProxy`` instances.
* ``TLSInterceptor`` — creates ``ssl.SSLContext`` pairs for the
  browser-side (uses our CA cert) and target-side (standard outgoing)
  TLS handshakes.  Server contexts are cached by ALPN tuple.
"""

from __future__ import annotations

import asyncio
import random
import ssl
import struct
import time
import urllib.parse
from asyncio import StreamReader, StreamWriter
from typing import Optional

from ._common import logger


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
            if transport is None or transport.is_closing():
                return
            if force:
                transport.abort()
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


class Socks5Client:
    """Async SOCKS5 CONNECT client. Implements RFC 1928 with optional
    RFC 1929 username/password authentication."""

    @staticmethod
    async def connect(
        proxy: str, target_host: str, target_port: int, timeout: float = 30.0
    ) -> tuple[StreamReader, StreamWriter]:
        """Open a SOCKS5 tunnel to ``target_host:target_port`` via *proxy*.

        Parameters
        ----------
        proxy:
            ``host:port`` or ``user:pass@host:port``.  Credentials may
            be percent-encoded (``%3A`` for ``:``, ``%40`` for ``@``)
            if they contain delimiter characters.
        target_host:
            Hostname the SOCKS5 proxy should connect to.
        target_port:
            Port the SOCKS5 proxy should connect to.
        timeout:
            Overall timeout for the handshake + CONNECT.

        Raises
        ------
        ConnectionError
            If the proxy is malformed, the server's responses violate
            RFC 1928 / RFC 1929, or the CONNECT is rejected.
        """
        # ── Parse the proxy URL ───────────────────────────────────────
        username: Optional[str] = None
        password: Optional[str] = None
        if "@" in proxy:
            creds, _, host_port = proxy.rpartition("@")
            if ":" in creds:
                raw_user, _, raw_pass = creds.partition(":")
                username = urllib.parse.unquote(raw_user)
                password = urllib.parse.unquote(raw_pass)
            else:
                # Username-only form (rare but valid in some deployments).
                username = urllib.parse.unquote(creds)
                password = ""
            proxy_host = host_port
        else:
            proxy_host = proxy

        proxy_port = 1080
        if ":" in proxy_host:
            proxy_host, port_str = proxy_host.rsplit(":", 1)
            try:
                proxy_port = int(port_str)
            except ValueError:
                raise ConnectionError(
                    f"Malformed SOCKS5 proxy {proxy!r}: bad port"
                )

        # RFC 1929 §2: ULEN and PLEN are single bytes (max 255).
        u_bytes = username.encode("utf-8") if username is not None else b""
        p_bytes = (password or "").encode("utf-8")
        if username is not None:
            if not u_bytes or len(u_bytes) > 255 or len(p_bytes) > 255:
                raise ConnectionError(
                    "SOCKS5 username/password must be 1-255 bytes each"
                )

        # RFC 1928 §4: DST.ADDR for domain-name ATYP is length-prefixed
        # by a single byte, so the hostname has the same 255-byte cap.
        domain = target_host.encode("utf-8")
        if not domain or len(domain) > 255:
            raise ConnectionError(
                f"SOCKS5 target hostname must be 1-255 bytes "
                f"(got {len(domain)}: {target_host!r})"
            )

        # ── Open TCP to the proxy ─────────────────────────────────────
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port), timeout=timeout
        )
        success: bool = False

        try:
            async with asyncio.timeout(timeout):
                # ── RFC 1928 §3: method selection ─────────────────────
                # Greeting advertises VER=5, NMETHODS, then the method list.
                # We always offer no-auth (0x00); add user/pass (0x02)
                # if credentials were supplied.
                if username is not None:
                    writer.write(b"\x05\x02\x00\x02")
                else:
                    writer.write(b"\x05\x01\x00")
                await writer.drain()

                resp = await reader.readexactly(2)
                if resp[0] != 0x05:
                    raise ConnectionError(
                        f"SOCKS5: bad version 0x{resp[0]:02x} in method "
                        f"selection reply (RFC 1928 §3 requires 0x05)"
                    )
                method = resp[1]
                if method == 0xFF:
                    raise ConnectionError(
                        "SOCKS5: server rejected all offered auth methods"
                    )

                if method == 0x00:
                    if username is not None:
                        logger.debug(
                            "SOCKS5: server selected no-auth despite "
                            "credentials being offered"
                        )
                elif method == 0x02:
                    if username is None:
                        raise ConnectionError(
                            "SOCKS5: server selected user/pass auth "
                            "but no credentials were supplied"
                        )
                    # ── RFC 1929 §2: user/pass sub-negotiation ────────
                    auth_pkt = (
                        b"\x01"
                        + bytes([len(u_bytes)]) + u_bytes
                        + bytes([len(p_bytes)]) + p_bytes
                    )
                    writer.write(auth_pkt)
                    await writer.drain()

                    auth_resp = await reader.readexactly(2)
                    if auth_resp[0] != 0x01:
                        raise ConnectionError(
                            f"SOCKS5 auth: bad sub-negotiation version "
                            f"0x{auth_resp[0]:02x} (RFC 1929 §2 requires 0x01)"
                        )
                    if auth_resp[1] != 0x00:
                        raise ConnectionError(
                            f"SOCKS5 auth: server rejected credentials "
                            f"(status 0x{auth_resp[1]:02x})"
                        )
                else:
                    raise ConnectionError(
                        f"SOCKS5: server selected unsupported method "
                        f"0x{method:02x}"
                    )

                # ── RFC 1928 §4: CONNECT request ──────────────────────
                # VER=5, CMD=CONNECT(1), RSV=0, ATYP=domain(3),
                # DST.ADDR (length-prefixed), DST.PORT (big-endian u16).
                request = (
                    b"\x05\x01\x00\x03"
                    + bytes([len(domain)])
                    + domain
                    + struct.pack(">H", target_port)
                )
                writer.write(request)
                await writer.drain()

                # ── RFC 1928 §6: CONNECT reply ────────────────────────
                resp = await reader.readexactly(4)
                if resp[0] != 0x05:
                    raise ConnectionError(
                        f"SOCKS5: bad version 0x{resp[0]:02x} in CONNECT "
                        f"reply (RFC 1928 §6 requires 0x05)"
                    )
                if resp[2] != 0x00:
                    raise ConnectionError(
                        f"SOCKS5: non-zero RSV byte 0x{resp[2]:02x} in "
                        f"CONNECT reply (RFC 1928 §6 requires 0x00)"
                    )
                if resp[1] != 0x00:
                    errors = {
                        1: "General SOCKS server failure",
                        2: "Connection not allowed by ruleset",
                        3: "Network unreachable",
                        4: "Host unreachable",
                        5: "Connection refused",
                        6: "TTL expired",
                        7: "Command not supported",
                        8: "Address type not supported",
                    }
                    raise ConnectionError(
                        f"SOCKS5: {errors.get(resp[1], f'Unknown error 0x{resp[1]:02x}')}"
                    )

                # Drain BND.ADDR + BND.PORT so the socket starts clean.
                atyp = resp[3]
                if atyp == 0x01:    # IPv4 (4) + port (2)
                    await reader.readexactly(6)
                elif atyp == 0x03:  # Domain: len (1) + name + port (2)
                    length = (await reader.readexactly(1))[0]
                    await reader.readexactly(length + 2)
                elif atyp == 0x04:  # IPv6 (16) + port (2)
                    await reader.readexactly(18)
                else:
                    # Unknown ATYP — we can't safely drain without
                    # knowing how many bytes follow, so abort rather
                    # than leave stale bytes in the read buffer.
                    raise ConnectionError(
                        f"SOCKS5: unknown ATYP 0x{atyp:02x} in CONNECT reply"
                    )

            success = True
            return reader, writer
        finally:
            if not success:
                writer.close()
                try:
                    # wait_closed() can hang indefinitely if the peer is
                    # wedged — bound it.
                    await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                except Exception:
                    pass


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
            logger.info("SOCKS5 proxy file not found: %s", self.proxy_file)
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
