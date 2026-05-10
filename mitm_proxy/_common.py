"""Shared types and the configured logger for the proxy package.

Leaf module — depends on nothing else in the package.  Imported by
every other module to obtain the package logger and the small data
types (``ProxyConfig``, ``Protocol``) that get threaded through the
handler stack.

The logger is registered with a custom subclass that adds a ``trace``
method (level 5, below DEBUG) for high-volume per-frame diagnostics.
``setLoggerClass`` is global, so any ``logging.getLogger("proxy....")``
call elsewhere in the package automatically gets the trace method.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any


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


# Package-wide logger.  Submodules can use this directly or call
# ``logging.getLogger(__name__)`` for finer-grained per-module filtering.
logger: CustomLogger = logging.getLogger("proxy")  # type: ignore[assignment]


@dataclass(frozen=True)
class ProxyConfig:
    """Tunable knobs for a SessionProxy.

    Attributes
    ----------
    max_streams_per_connection:
        Maximum concurrent HTTP/2 streams the proxy will track per
        upstream connection before refusing new ones with
        REFUSED_STREAM.  Sized to match Chrome's default (100).
    verify_ssl:
        Whether to verify the target server's TLS certificate when
        the proxy isn't using the sidecar.  False permits self-signed
        and expired certs but disables real CA checking.
    connect_timeout:
        Maximum seconds to wait for the target TCP/TLS connection
        plus any SOCKS5 negotiation.
    idle_timeout:
        Maximum seconds without data flow before either side of an
        h1 keep-alive or h2 session is torn down.  Tuned slightly
        below typical browser idle timeouts (60 s) so the proxy
        proactively closes before the browser does.
    request_timeout:
        Maximum seconds for a single h1 request/response cycle.
    stream_timeout:
        Maximum seconds an h2 stream may stay alive without
        receiving end-of-stream.  Reaped by ``_check_stream_timeouts``.
    read_buffer_size:
        Size of the ``asyncio`` read buffer passed to ``reader.read()``.
    """

    max_streams_per_connection: int = 100
    verify_ssl: bool = True

    connect_timeout: float = 120.0
    idle_timeout: float = 55.0
    request_timeout: float = 120.0
    stream_timeout: float = 120.0

    read_buffer_size: int = 65536


DEFAULT_CONFIG: ProxyConfig = ProxyConfig()


class Protocol(Enum):
    """ALPN-negotiated protocol for the target connection."""

    HTTP1 = "http/1.1"
    HTTP2 = "h2"