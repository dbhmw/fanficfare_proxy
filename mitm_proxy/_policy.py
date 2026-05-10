"""Policy interface and the default implementation.

Two layers in this module:

* ``HeaderModifier`` — stateless utility class with the
  hygiene/scrubbing/merging logic used by ``DefaultPolicy``.  Pure
  classmethods, no internal state, easy to call from custom policies
  via ``HeaderModifier.scrub_request_headers(...)`` etc.

* ``RequestPolicy`` and ``ResponsePolicy`` — :class:`typing.Protocol`
  interfaces describing what the protocol handlers expect.  Both are
  used at four points per request/response: outgoing-header transform
  (h1 + h2 paths), incoming-header transform (h1 line-by-line and h2
  full-list), capture lifecycle (``open_capture`` / ``deliver_capture``).

* ``DefaultPolicy`` — the reference implementation: hygiene + URL-rule
  merging + interceptor-driven capture.  Subclass and call
  ``super().transform_request_headers(...)`` to layer custom behaviour
  on top of the built-in pipeline.

Reference model
~~~~~~~~~~~~~~~
``SessionProxy`` strongly references its policy.  The default policy
holds the proxy via ``weakref.proxy`` so there's no cycle requiring
cyclic GC to collect.  Custom policies should follow the same pattern.
"""

from __future__ import annotations

import fnmatch
import weakref
from typing import (
    TYPE_CHECKING,
    Optional,
    Sequence,
    Protocol as TypingProtocol,
)

from ._common import logger
from ._interceptor import _ResponseCapture

if TYPE_CHECKING:
    from .session import SessionProxy


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

    # Prefix-based stripping (sec-ch-*, proxy-*)
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
            key_str = k.decode("utf-8", errors="replace") if isinstance(k, bytes) else k
            if key_str.lower() != "alt-svc":
                result.append((k, v))
                continue

            # Filter the value
            val_str = v.decode("utf-8", errors="replace") if isinstance(v, bytes) else v
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
    def scrub_request_headers(
        cls,
        headers: list[tuple[str, str]],
        is_h2: bool = True,
    ) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
        """Strip junk headers and split into ``(pseudo, regular)`` lists.

        Always-on proxy hygiene that runs on *every* request regardless of
        whether any user rules are defined.  Removes client-hints,
        sec-ch-* headers, h2-forbidden connection-level headers, and
        applies the h2/h1 casing rules.

        Casing
        ~~~~~~
        For HTTP/2 (``is_h2=True``) all header names are lowercased,
        because RFC 7540 §8.1.2 requires lowercase and HPACK would
        do it anyway.  For HTTP/1.1 the original casing is preserved
        — browsers send ``User-Agent`` not ``user-agent`` and many
        servers (and fingerprinters) treat the difference as
        meaningful.

        Returns ``(pseudo, regular)`` so the caller can apply rule
        merging to ``regular`` only — pseudo-headers must come first
        in the final h2 frame.  Callers that don't need rule merging
        can simply concatenate the two lists.
        """
        pseudo: list[tuple[str, str]] = []
        regular: list[tuple[str, str]] = []

        for k, v in headers:
            lower = k.lower()
            if cls.should_strip(lower, v, is_h2):
                continue
            # h2 requires lowercased names; h1 must preserve case for
            # fingerprint compatibility.
            name_out = lower if is_h2 else k
            if lower.startswith(":"):
                # Pseudo-headers exist only in h2 and are always
                # lowercase by definition.
                pseudo.append((lower, v))
            else:
                regular.append((name_out, v))

        return pseudo, regular

    @classmethod
    def merge_rule_headers(
        cls,
        regular_headers: list[tuple[str, str]],
        rule_headers: Sequence[tuple[str, str]],
        is_h2: bool = True,
    ) -> list[tuple[str, str]]:
        """Merge *rule_headers* into *regular_headers*, returning a new list.

        For each rule header, if a same-named header exists in
        *regular_headers* its value is replaced *in place* (preserving
        the original header's casing for fingerprint compatibility).
        Rule headers without an existing match are appended at the end.

        Pseudo-headers in the rule are dropped: they're managed by
        the protocol layer, not user policy.  H2-forbidden and
        always-stripped headers in the rule are also dropped.

        Caller is responsible for URL matching: this function does
        the merge unconditionally.  See ``DefaultPolicy.matches_rule``
        for the matching side.
        """
        # Build a lookup of rule headers eligible for this connection
        # type, keyed by lowered name.  The original casing from the
        # rule is preserved as the value to write out for h1 additions.
        rule_overrides: dict[str, tuple[str, str]] = {}  # lower -> (orig_case, value)
        for name, value in rule_headers:
            nl = name.lower()
            if nl.startswith(":"):
                continue
            if is_h2 and nl in cls.FORBIDDEN_H2_HEADERS:
                continue
            if nl in cls.STRIP_HEADERS:
                continue
            rule_overrides[nl] = (name, value)

        # Pass 1: walk regular headers in order, replacing values
        # where the rule provides an override.  Preserve the *existing*
        # header's casing (don't let the rule's casing leak in for
        # replacement; if you want to change the casing, drop and
        # re-add via a new header).
        applied: set[str] = set()
        updated: list[tuple[str, str]] = []
        for k, v in regular_headers:
            kl = k.lower()
            if kl in rule_overrides and kl not in applied:
                _, override_value = rule_overrides[kl]
                updated.append((k, override_value))  # keep original casing
                applied.add(kl)
            else:
                updated.append((k, v))

        # Pass 2: append any rule headers that weren't already
        # present in the original list.  For new additions we use
        # the rule's casing on h1, lowercased on h2.
        for nl, (orig_case, value) in rule_overrides.items():
            if nl not in applied:
                name_out = nl if is_h2 else orig_case
                updated.append((name_out, value))

        return updated


class RequestPolicy(TypingProtocol):
    """Transforms outgoing requests before they leave the proxy.

    Implementations must be **pure** — no I/O, no async — because the
    handlers call them synchronously while holding the event loop.
    """

    def transform_request_headers(
        self,
        url: str,
        headers: list[tuple[str, str]],
        is_h2: bool,
    ) -> list[tuple[str, str]]:
        """Return a new header list with policy applied.

        Receives the request URL plus the full header list (including
        ``:method``, ``:path`` etc. for h2) and returns a new list.
        Must not mutate the input.
        """
        ...


class ResponsePolicy(TypingProtocol):
    """Transforms incoming responses before they reach the browser, plus
    decides whether each request URL should be captured for interception.

    The two paths (h1, h2) consume different parts of this interface:
    h1 forwards headers one line at a time and calls
    ``filter_response_header_line``; h2 has the full header list and
    calls ``filter_response_headers``.  Both delegate to the same
    underlying logic in ``DefaultPolicy``.
    """

    def filter_response_headers(
        self,
        headers: Sequence[tuple[bytes | str, bytes | str]],
    ) -> list[tuple[bytes | str, bytes | str]]:
        """Filter an h2 response header list. Return a new list."""
        ...

    def filter_response_header_line(self, header_line: str) -> Optional[str]:
        """Filter a single h1 response header line (without trailing CRLF).

        Return the new line, or ``None`` to drop the header entirely.
        Returning the input unchanged means "keep as-is".
        """
        ...

    def open_capture(self, url: str) -> Optional[_ResponseCapture]:
        """Open a response capture if *url* matches a live interceptor."""
        ...

    def deliver_capture(self, capture: _ResponseCapture) -> None:
        """Finalise and dispatch a completed capture to interceptors."""
        ...


class DefaultPolicy:
    """The proxy's default policy: hygiene + URL→header rules + capture lifecycle.

    Three layers of behaviour, applied in order:

    1. **Hygiene** — strip client-hints, sec-ch-* headers, h2-forbidden
       headers, and h3 entries from response Alt-Svc.  Always-on.
    2. **Header rules** — if the request URL matches a registered
       pattern (set via :meth:`set_header_rule`), merge those headers
       into the outgoing request.
    3. **Capture lifecycle** — open a :class:`_ResponseCapture` if any
       active interceptor matches the URL, deliver on completion.

    Subclassing
    ~~~~~~~~~~~
    Override :meth:`transform_request_headers` and call ``super()`` to
    inherit hygiene + rules::

        class TaggingPolicy(DefaultPolicy):
            def transform_request_headers(self, url, headers, is_h2):
                headers = super().transform_request_headers(url, headers, is_h2)
                headers.append(("X-Trace-Id", uuid.uuid4().hex))
                return headers

        proxy.set_policy(TaggingPolicy(proxy))
        proxy.set_header_rule({"https://api.example.com/*"}, [("X-Key", "abc")])
        # → both behaviours active: hygiene + rule + tagging

    The hygiene layer cannot be removed without consequences (h2-forbidden
    headers in particular will get the connection closed by the target).
    Custom subclasses that bypass hygiene must reimplement it.

    Rule storage
    ~~~~~~~~~~~~
    Rules are stored as state on the policy, not on the SessionProxy,
    so subclasses inherit them automatically.  ``proxy.set_header_rule(...)``
    delegates to ``policy.set_header_rule(...)`` on the active policy.

    Reference model
    ~~~~~~~~~~~~~~~
    The proxy owns the policy (strong: ``proxy.policy``); the policy
    holds the proxy via ``weakref.proxy`` so there is no cycle that
    depends on cyclic GC.  Calling a policy method after the proxy is
    destroyed raises ``ReferenceError`` — the correct behaviour, because
    policy operations are meaningless without the owning session.
    """

    def __init__(
        self,
        proxy: SessionProxy,
        urls: Optional[set[str]] = None,
        headers: Optional[list[tuple[str, str]]] = None,
    ):
        # weakref.proxy is transparent: ``self._proxy.method()`` works
        # exactly like a strong reference for attribute access.
        self._proxy = weakref.proxy(proxy)
        self._exact_urls: frozenset[str] = frozenset()
        self._glob_patterns: tuple[str, ...] = ()
        self._rule_headers: tuple[tuple[str, str], ...] = ()
        if urls or headers:
            self.set_header_rule(urls or set(), headers or [])

    # -- header-rule state -------------------------------------------------

    def set_header_rule(
        self, urls: set[str], headers: list[tuple[str, str]]
    ) -> None:
        """Replace this policy's URL→headers rule.

        URL matching mirrors :class:`RequestInterceptor`: patterns
        without ``*`` or ``?`` are exact-string matches (O(1) lookup);
        patterns containing them use :func:`fnmatch.fnmatch`-style
        globbing.  Mix and match in the same call.
        """
        exact: set[str] = set()
        globs: list[str] = []
        for u in urls:
            if "*" in u or "?" in u:
                globs.append(u)
            else:
                exact.add(u)
        self._exact_urls = frozenset(exact)
        self._glob_patterns = tuple(globs)
        self._rule_headers = tuple((k, v) for k, v in headers)

    def clear_header_rule(self) -> None:
        """Remove this policy's URL→headers rule (hygiene still applies)."""
        self._exact_urls = frozenset()
        self._glob_patterns = ()
        self._rule_headers = ()

    def matches_rule(self, url: str) -> bool:
        """Return ``True`` if *url* matches this policy's rule URLs."""
        if url in self._exact_urls:
            return True
        for pat in self._glob_patterns:
            if fnmatch.fnmatch(url, pat):
                return True
        return False

    # -- RequestPolicy -----------------------------------------------------

    def transform_request_headers(
        self,
        url: str,
        headers: list[tuple[str, str]],
        is_h2: bool,
    ) -> list[tuple[str, str]]:
        # 1. Always-on hygiene + casing normalization
        pseudo, regular = HeaderModifier.scrub_request_headers(
            headers, is_h2=is_h2
        )
        # 2. URL-rule merge (only if the URL matches and we have rule headers)
        if self._rule_headers and self.matches_rule(url):
            logger.debug("[Policy] Applying header rule for: %s", url)
            regular = HeaderModifier.merge_rule_headers(
                regular, self._rule_headers, is_h2=is_h2
            )
        return pseudo + regular

    # -- ResponsePolicy ----------------------------------------------------

    def filter_response_headers(
        self,
        headers: Sequence[tuple[bytes | str, bytes | str]],
    ) -> list[tuple[bytes | str, bytes | str]]:
        return HeaderModifier.filter_response_headers(headers)

    def filter_response_header_line(self, header_line: str) -> Optional[str]:
        # h1 calls us with a raw header line ("Alt-Svc: h3=...").
        # Apply the same h3-stripping logic used on h2 by routing through
        # filter_alt_svc.  Non-alt-svc headers pass through unchanged.
        if ":" not in header_line:
            return header_line
        name, _, value = header_line.partition(":")
        if name.strip().lower() != "alt-svc":
            return header_line
        filtered = HeaderModifier.filter_alt_svc(value.strip())
        if filtered is None:
            return None
        if filtered == value.strip():
            return header_line
        return f"{name}: {filtered}"

    def open_capture(self, url: str) -> Optional[_ResponseCapture]:
        return self._proxy._start_capture(url)

    def deliver_capture(self, capture: _ResponseCapture) -> None:
        self._proxy._deliver_capture(capture)