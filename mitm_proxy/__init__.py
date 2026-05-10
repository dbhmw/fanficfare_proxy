"""proxy — Per-session MITM proxy with HTTP/1.1 and HTTP/2 support.

Public API
~~~~~~~~~~
Most callers only need ``SessionProxy`` and (optionally) the
``ProxyConfig`` and ``SocksProxyPool`` constructors::

    from proxy import SessionProxy, ProxyConfig, SocksProxyPool

For interception::

    from proxy import RequestInterceptor, InterceptedResponse

For custom policies::

    from proxy import DefaultPolicy, RequestPolicy, ResponsePolicy

The internal modules (``_common``, ``_io``, ``_interceptor``,
``_policy``, ``_http1``, ``_http2``) are not part of the stable
surface; reach into them at your own risk.

"""

from __future__ import annotations

from ._common import (
    ColoredFormatter,
    CustomLogger,
    DEFAULT_CONFIG,
    Protocol,
    ProxyConfig,
    logger,
)
from ._io import (
    ManagedConnection,
    Socks5Client,
    SocksProxyPool,
    TLSInterceptor,
)
from ._interceptor import (
    InterceptedResponse,
    RequestInterceptor,
)
from ._policy import (
    DefaultPolicy,
    HeaderModifier,
    RequestPolicy,
    ResponsePolicy,
)
from .session import SessionProxy
from .utls_bridge.sidecar import (
    SidecarManager,
    set_sidecar_log_level
)


def set_proxy_log_level(level: int) -> None:
    """Set the log level for the proxy module. Call once from your main script."""
    logger.setLevel(level)


__all__ = [
    # Public API
    "SessionProxy",
    "ProxyConfig",
    "DEFAULT_CONFIG",
    "Protocol",
    "RequestInterceptor",
    "InterceptedResponse",
    "DefaultPolicy",
    "RequestPolicy",
    "ResponsePolicy",
    "HeaderModifier",
    "SocksProxyPool",
    "SidecarManager",
    # Logging
    "logger",
    "set_proxy_log_level",
    "set_sidecar_log_level",
    "CustomLogger",
    "ColoredFormatter",
    # Lower-level (mostly internal but exposed for advanced use)
    "ManagedConnection",
    "Socks5Client",
    "TLSInterceptor",
]