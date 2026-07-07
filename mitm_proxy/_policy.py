"""Policy interface and the default implementation.

Components in this module:

* ``Headers`` — an ordered, case-insensitive, multi-value-safe,
  byte-oriented header collection.  The object the response hook works
  with; ``:status`` is just one of its entries.

* ``Policy`` — :class:`typing.Protocol` describing what the protocol
  handlers need from a policy: request-header transformation, response
  transformation (via :class:`Headers`), and the capture lifecycle used
  by the interception API.  See its docstring for the hook points.

* ``DefaultPolicy`` — the reference implementation: hygiene + URL-rule
  merging + interceptor-driven capture.  The header hygiene/scrubbing/
  merging logic (formerly a separate ``HeaderModifier`` class) lives here
  as static/class methods, beside the rule state it serves.  Subclass and
  call ``super().transform_request_headers(...)`` /
  ``super().transform_response_headers(...)`` to layer custom behaviour on top.

Reference model
~~~~~~~~~~~~~~~
``SessionProxy`` strongly references its policy.  ``DefaultPolicy``
holds the proxy via ``weakref.proxy`` so a user-supplied custom policy
doesn't accidentally keep the SessionProxy (and all its connections)
alive past ``stop()``.  Calling a policy method after the proxy is
destroyed raises ``ReferenceError``, by design — policy operations
have no meaning without the owning session.
"""

from __future__ import annotations

import fnmatch
import weakref
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Iterable,
    Optional,
    Sequence,
    Protocol as TypingProtocol,
)

from ._common import logger
from ._interceptor import _ResponseCapture

if TYPE_CHECKING:
    from .session import SessionProxy


# Response headers that govern body framing / connection lifetime.  These
# must never be injected or rewritten by a response rule: changing what the
# browser is told about ``Content-Length`` / ``Transfer-Encoding`` while the
# proxy reads the body according to what the *target* actually sent desyncs
# the two ends (the browser mis-frames the body, then mis-reads every
# subsequent response on a keep-alive connection).  ``add_response_rule``
# rejects rules that touch these.
_FRAMING_HEADERS: frozenset[str] = frozenset(
    {"content-length", "transfer-encoding", "connection"}
)

# Reserved rule name used by the singular ``set_*_header_rule(...)`` calls
# (and the legacy ``set_header_rule``) when no explicit ``name`` is given,
# so "call it again to replace" holds for the common single-rule case while
# explicitly-named rules added alongside it stay independent.
_DEFAULT_RULE_NAME: str = "default"


def _as_bytes(s: bytes | str) -> bytes:
    """Coerce a header name/value to ``bytes`` (latin1 for str).

    Header tokens are ASCII/latin1 in practice; latin1 is a total,
    lossless byte<->str mapping, so this never raises and round-trips.
    Lets callers pass either ``b"location"`` or ``"location"`` while the
    store stays uniformly bytes.
    """
    return s if isinstance(s, bytes) else s.encode("latin1")

class _Headers:
    """Base header collection: ordered, case-insensitive, multi-value-safe.

    Holds the **regular** headers (everything whose name does not start
    with ``:``).  Pseudo-headers are *not* stored here — they live in the
    typed fields of the :class:`RequestHeaders` / :class:`ResponseHeaders`
    subclasses, because pseudo-headers form a fixed, spec-defined namespace
    (RFC 9113 §8.3) that is structurally separate from the header block.
    The dict-like API below therefore can never see or collide with a
    pseudo-header: ``h.get(":path")`` finds nothing, and assigning a
    ``:``-prefixed name raises.

    Design
    ~~~~~~
    * **Source of truth** is an ordered ``list[tuple[bytes, bytes]]`` of
      regular headers, kept as they arrived on the wire — order and (on h1)
      original name casing preserved, which matters for fingerprinting.
    * **Bytes throughout.**  Names/values are stored and returned as
      ``bytes``.  Lookups accept ``bytes`` or ``str`` (str is latin1-
      encoded for you); stored data is never decoded.
    * **Case-insensitive matching** at the lookup boundary only: a
      throwaway lowercased copy is compared; the stored name is untouched.
    * **Multi-value safe.**  ``Set-Cookie`` keeps every entry; ``get_all``
      returns them all, ``__delitem__`` removes them all, ``get`` returns
      the first.
    * **Dirty tracking.**  If neither the regular headers nor the pseudo
      fields were mutated, :meth:`to_pairs` rebuilds from the untouched
      inputs; the handlers can fast-path an unmodified response.

    Mutation semantics (regular headers)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    * ``h[name] = value`` — replace the first case-insensitive match's
      value in place (keeping its original name bytes + position), else
      append at the end with the caller's casing.
    * ``del h[name]`` — remove all matching entries; ``KeyError`` if none
      (use :meth:`discard` for no-raise).
    * ``h[name]`` — first matching value; ``KeyError`` if absent.
    * ``h.get(name, default=None)`` — first matching value or *default*.
    """

    __slots__ = ("_pairs", "_dirty", "_pseudo_order")

    # Subclasses list their permitted pseudo-header names (lowercased,
    # ``:``-prefixed) in canonical wire order — used only as the *fallback*
    # order for pseudo-headers a policy adds that weren't on the wire.  The
    # order pseudo-headers actually *arrived* in is recorded per-instance
    # (``_pseudo_order``) and re-emitted verbatim, because that order is a
    # fingerprint signal (Chrome / Firefox / Safari each order them
    # differently, e.g. Akamai's HTTP/2 fingerprint).
    _PSEUDO: tuple[bytes, ...] = ()

    def __init__(self, pairs: Sequence[tuple[bytes, bytes]] | None = None) -> None:
        self._pairs: list[tuple[bytes, bytes]] = []
        # Pseudo-header names in the exact order they arrived on the wire.
        # Preserves the client's ordering through a rewrite for fingerprint
        # fidelity; policy-added pseudo-headers are appended here too.
        self._pseudo_order: list[bytes] = []
        self._dirty = False
        if pairs:
            self._ingest(pairs)

    def _ingest(self, pairs: Sequence[tuple[bytes, bytes]]) -> None:
        """Split incoming pairs: pseudo-headers → fields, rest → ``_pairs``."""
        for k, v in pairs:
            kb = _as_bytes(k)
            if kb[:1] == b":":
                name = kb.lower()
                if name not in self._pseudo_order:
                    self._pseudo_order.append(name)
                self._set_pseudo(name, _as_bytes(v))
            else:
                self._pairs.append((kb, _as_bytes(v)))

    def _note_pseudo(self, name: bytes) -> None:
        """Record a pseudo-header name's position (call from field setters).

        A field set on a header that wasn't on the wire appends it to the
        recorded order (so it serialises after the original pseudo-headers,
        before regular headers).  Setting one already present leaves its
        original position untouched.
        """
        if name not in self._pseudo_order:
            self._pseudo_order.append(name)

    # Subclasses implement pseudo storage.
    def _set_pseudo(self, name: bytes, value: bytes) -> None:
        raise NotImplementedError

    def _pseudo_value(self, name: bytes) -> Optional[bytes]:
        """Return the raw byte value of pseudo-header *name*, or None."""
        raise NotImplementedError

    def _pseudo_pairs(self) -> list[tuple[bytes, bytes]]:
        """Pseudo-headers as ``(name, value)`` pairs, in recorded wire order.

        Re-emits in the order recorded in ``_pseudo_order`` (the order they
        arrived, plus any policy-added ones appended), preserving the
        client's pseudo-header ordering — a fingerprint signal — across a
        rewrite.  Implemented once here for both request and response.
        """
        out: list[tuple[bytes, bytes]] = []
        for name in self._pseudo_order:
            val = self._pseudo_value(name)
            if val is not None:
                out.append((name, val))
        return out

    # -- internal helpers --

    @staticmethod
    def _fold(name: bytes) -> bytes:
        return name.lower()

    @staticmethod
    def _reject_pseudo(nb: bytes) -> None:
        if nb[:1] == b":":
            raise KeyError(
                f"{nb!r} is a pseudo-header; use the typed field "
                f"(e.g. .status / .path) instead of the dict API"
            )

    # -- read API (regular headers only) --

    def get(self, name: bytes | str, default: Optional[bytes] = None) -> Optional[bytes]:
        """First value matching *name* (case-insensitive), or *default*."""
        target = self._fold(_as_bytes(name))
        for k, v in self._pairs:
            if self._fold(k) == target:
                return v
        return default

    def __getitem__(self, name: bytes | str) -> bytes:
        v = self.get(name, None)
        if v is None:
            raise KeyError(name)
        return v

    def get_all(self, name: bytes | str) -> list[bytes]:
        """All values matching *name* (the ``Set-Cookie``-safe accessor)."""
        target = self._fold(_as_bytes(name))
        return [v for k, v in self._pairs if self._fold(k) == target]

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, (bytes, str)):
            return False
        target = self._fold(_as_bytes(name))
        return any(self._fold(k) == target for k, _ in self._pairs)

    def __iter__(self):
        return iter(self._pairs)

    def items(self) -> list[tuple[bytes, bytes]]:
        """A copy of the ordered regular ``(name, value)`` pairs."""
        return list(self._pairs)

    def __len__(self) -> int:
        return len(self._pairs)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.to_pairs()!r})"

    # -- write API (regular headers only) --

    def __setitem__(self, name: bytes | str, value: bytes | str) -> None:
        nb, vb = _as_bytes(name), _as_bytes(value)
        self._reject_pseudo(nb)
        target = self._fold(nb)
        for i, (k, _v) in enumerate(self._pairs):
            if self._fold(k) == target:
                self._pairs[i] = (k, vb)  # keep original name bytes + index
                self._dirty = True
                return
        self._pairs.append((nb, vb))  # new header: caller's casing, at end
        self._dirty = True

    def __delitem__(self, name: bytes | str) -> None:
        if not self.discard(name):
            raise KeyError(name)

    def discard(self, name: bytes | str) -> bool:
        """Remove all entries matching *name*; return ``True`` if any went."""
        nb = _as_bytes(name)
        self._reject_pseudo(nb)
        target = self._fold(nb)
        kept = [(k, v) for k, v in self._pairs if self._fold(k) != target]
        if len(kept) != len(self._pairs):
            self._pairs = kept
            self._dirty = True
            return True
        return False

    def setdefault(self, name: bytes | str, value: bytes | str) -> bytes:
        """Return existing first value, or set and return *value* if absent."""
        nb = _as_bytes(name)
        self._reject_pseudo(nb)
        existing = self.get(nb, None)
        if existing is not None:
            return existing
        vb = _as_bytes(value)
        self._pairs.append((nb, vb))
        self._dirty = True
        return vb

    def insert_after(
        self,
        anchor: bytes,
        name: bytes,
        value: bytes,
    ) -> None:
        """Insert ``(name, value)`` immediately after the first header whose
        name case-insensitively matches *anchor*.

        Regular headers only — *anchor* and *name* must not be pseudo-headers.
        ``KeyError`` if *anchor* isn't present.  Does not de-duplicate.

        All three args are raw ``bytes`` (no ``str`` coercion).
        """
        self._reject_pseudo(anchor)   # anchor can't be a pseudo-header
        self._reject_pseudo(name)     # nor the inserted name
        target = self._fold(anchor)
        for i, (k, _v) in enumerate(self._pairs):
            if self._fold(k) == target:
                self._pairs.insert(i + 1, (name, value))
                self._dirty = True
                return
        raise KeyError(anchor)

    # -- serialisation --

    @property
    def dirty(self) -> bool:
        return self._dirty

    def to_pairs(self) -> list[tuple[bytes, bytes]]:
        """Full wire form: pseudo-headers first (canonical order), then regular.

        Pseudo-headers must precede regular headers in an h2 HEADERS block
        (RFC 9113 §8.3); emitting them first is also harmless for the h1
        handler, which peels them back off into the request/status line.
        """
        return self._pseudo_pairs() + self._pairs

class RequestHeaders(_Headers):
    """Request headers with the four request pseudo-headers as typed fields.

    ``method`` / ``scheme`` / ``authority`` / ``path`` are accessed as
    ``str`` properties (decoded latin1) and assigned as ``str`` or
    ``bytes``.  Regular headers use the inherited dict API.  This is what
    :meth:`Policy.transform_request_headers` receives, identically for h1
    and h2 — the handler builds it from the request line (h1) or the
    pseudo-header block (h2), and the policy never branches on protocol.
    """

    __slots__ = ("_method", "_scheme", "_authority", "_path", "_pseudo_dirty")

    _PSEUDO = (b":method", b":scheme", b":authority", b":path")

    def __init__(self, pairs: Sequence[tuple[bytes, bytes]] | None = None) -> None:
        self._method: Optional[bytes] = None
        self._scheme: Optional[bytes] = None
        self._authority: Optional[bytes] = None
        self._path: Optional[bytes] = None
        self._pseudo_dirty = False
        super().__init__(pairs)

    def _set_pseudo(self, name: bytes, value: bytes) -> None:
        if name == b":method":
            self._method = value
        elif name == b":scheme":
            self._scheme = value
        elif name == b":authority":
            self._authority = value
        elif name == b":path":
            self._path = value
        # Unknown request pseudo-headers are dropped: RFC 9113 §8.3
        # permits only these four, and endpoints must reject others.

    def _pseudo_value(self, name: bytes) -> Optional[bytes]:
        if name == b":method":
            return self._method
        if name == b":scheme":
            return self._scheme
        if name == b":authority":
            return self._authority
        if name == b":path":
            return self._path
        return None

    @property
    def dirty(self) -> bool:
        return self._dirty or self._pseudo_dirty

    def _get(self, v: Optional[bytes]) -> Optional[str]:
        return v.decode("latin1") if v is not None else None

    @property
    def method(self) -> Optional[str]:
        return self._get(self._method)

    @method.setter
    def method(self, value: bytes | str) -> None:
        self._method = _as_bytes(value)
        self._note_pseudo(b":method")
        self._pseudo_dirty = True

    @property
    def scheme(self) -> Optional[str]:
        return self._get(self._scheme)

    @scheme.setter
    def scheme(self, value: bytes | str) -> None:
        self._scheme = _as_bytes(value)
        self._note_pseudo(b":scheme")
        self._pseudo_dirty = True

    @property
    def authority(self) -> Optional[str]:
        return self._get(self._authority)

    @authority.setter
    def authority(self, value: bytes | str) -> None:
        self._authority = _as_bytes(value)
        self._note_pseudo(b":authority")
        self._pseudo_dirty = True

    @property
    def path(self) -> Optional[str]:
        return self._get(self._path)

    @path.setter
    def path(self, value: bytes | str) -> None:
        self._path = _as_bytes(value)
        self._note_pseudo(b":path")
        self._pseudo_dirty = True

class ResponseHeaders(_Headers):
    """Response headers with the ``:status`` pseudo-header as a typed field.

    ``status`` is an ``int`` property; everything else is a regular header
    via the inherited dict API.  This is what
    :meth:`Policy.transform_response_headers` receives, identically for h1 and h2.
    Changing the status the browser sees is ``headers.status = 200`` —
    h2 maps it to ``:status``, h1 to the status line.
    """

    __slots__ = ("_status", "_pseudo_dirty")

    _PSEUDO = (b":status",)

    def __init__(
        self,
        pairs: Sequence[tuple[bytes, bytes]] | None = None,
        *,
        status: Optional[int] = None,
    ) -> None:
        self._status: Optional[int] = None
        self._pseudo_dirty = False
        super().__init__(pairs)
        # h1 has no :status in the header block (it's in the status line);
        # the handler seeds it here.  A :status in *pairs* (h2) wins if both
        # are somehow present, since ingest runs first.
        if status is not None and self._status is None:
            self._status = status
            self._note_pseudo(b":status")

    def _set_pseudo(self, name: bytes, value: bytes) -> None:
        if name == b":status":
            try:
                self._status = int(value)
            except ValueError:
                logger.debug("Malformed :status %r", value)
                self._status = 0

    def _pseudo_value(self, name: bytes) -> Optional[bytes]:
        if name == b":status" and self._status is not None:
            return str(self._status).encode("latin1")
        return None

    @property
    def dirty(self) -> bool:
        return self._dirty or self._pseudo_dirty

    @property
    def status(self) -> Optional[int]:
        return self._status

    @status.setter
    def status(self, code: int) -> None:
        self._status = int(code)
        self._note_pseudo(b":status")
        self._pseudo_dirty = True

@dataclass(frozen=True)
class _UrlMatcher:
    """Compiled URL matcher shared by request and response rules.

    Mirrors :class:`RequestInterceptor`: patterns without ``*`` are exact
    matches (O(1) set lookup); patterns containing ``*`` use
    :func:`fnmatch.fnmatch`-style globbing.  ``?`` is treated literally
    since it occurs in query strings.
    """

    exact: frozenset[str]
    globs: tuple[str, ...]

    @classmethod
    def compile(cls, urls: Iterable[str]) -> "_UrlMatcher":
        exact: set[str] = set()
        globs: list[str] = []
        for u in urls:
            if "*" in u:
                globs.append(u)
            else:
                exact.add(u)
        return cls(frozenset(exact), tuple(globs))

    def matches(self, url: str) -> bool:
        if url in self.exact:
            return True
        return any(fnmatch.fnmatch(url, p) for p in self.globs)

@dataclass(frozen=True)
class _HeaderRule:
    """A named URL→headers rule: when *matcher* matches, merge *headers*.

    Used symmetrically for both request and response rules — both sides do
    nothing fancier than "if the URL matches, set/override these headers"
    (the request side merges via :meth:`self.merge_rule_headers`,
    the response side via the :class:`Headers` dict-like API).  A header
    value of ``None`` means *drop that header*; ``""`` sets it to a
    present-but-empty value.  Anything *conditional* — rewriting a status
    code, dropping a header only for certain responses — is deliberately
    *not* expressible here; that's what subclassing :class:`DefaultPolicy`
    and overriding the transform hook is for.
    """

    matcher: _UrlMatcher
    headers: tuple[tuple[str, Optional[str]], ...]

class Policy(TypingProtocol):
    """The policy contract the proxy requires.

    Implementations must be **pure** — no I/O, no async — because the
    handlers call them synchronously while holding the event loop.
    Each request/response touches the policy at four points:

    1. **Outgoing request headers** (h1 + h2):
       :meth:`transform_request_headers` rewrites the full header list
       before it's sent to the target.
    2. **Incoming response headers** (h1 + h2):
       :meth:`transform_response_headers` receives the URL and a :class:`Headers`
       object and returns the :class:`Headers` to forward to the browser.
       A single hook for both protocols — see below.
    3. **Capture lifecycle** (h1 + h2): :meth:`open_capture` decides
       whether a URL is being intercepted; :meth:`deliver_capture`
       hands the completed body to the interceptor when the response
       finishes.

    Response hook
    ~~~~~~~~~~~~~
    Response handling used to be split (h1 filtered headers line-by-line
    as bytes streamed out; h2 had the whole HEADERS frame buffered).
    Both handlers now buffer the full header block into a
    :class:`Headers` object and call this one hook, mirroring how
    :meth:`transform_request_headers` unifies the request side.  There is
    **no separate status** — the HTTP/2 ``:status`` pseudo-header is just
    the ``b":status"`` entry in the collection, read and written through
    the same case-insensitive API as any other header.  The h1 handler
    populates a ``:status`` entry from the status line so a policy sees one
    uniformly, and reads it back out to write the status line; the h2
    handler passes the collection's pairs straight to ``send_headers``,
    where ``:status`` is native.  Everything is ``bytes``; an untouched
    :class:`Headers` re-serialises the exact original wire bytes for free.

    ``SessionProxy(policy=...)`` is typed against this protocol.
    ``DefaultPolicy`` satisfies it structurally; custom policies
    should either subclass ``DefaultPolicy`` (to inherit hygiene and
    URL-rule merging) or implement every method below from scratch.
    """
    def __init__(
        self,
        proxy: SessionProxy,
        urls: Optional[set[str]] = None,
        headers: Optional[list[tuple[str, Optional[str]]]] = None,
    ):
        ...

    # -- request side ------------------------------------------------------

    def transform_request_headers(
        self,
        url: str,
        headers: RequestHeaders,
    ) -> RequestHeaders:
        """Transform an outgoing request before it's sent to the target.

        Receives the request *url* and a :class:`RequestHeaders` view and
        returns the view to send (mutate and return it, or return a fresh
        one).  The four request pseudo-headers are typed fields
        (``.method`` / ``.scheme`` / ``.authority`` / ``.path``); regular
        headers use the dict API.  Symmetric with :meth:`transform_response_headers`
        — no ``is_h2``, no pseudo-headers leaking into the dict API; each
        handler builds the view from its wire form (request line for h1,
        pseudo block for h2) and serialises it back appropriately.
        """
        ...

    # -- response side -----------------------------------------------------

    def transform_response_headers(
        self,
        url: str,
        headers: ResponseHeaders,
    ) -> ResponseHeaders:
        """Transform an incoming response before it's forwarded to the browser.

        Receives the request *url* and a :class:`ResponseHeaders` view and
        returns the view to forward (mutate and return it, or return a
        fresh one).  The status is the typed ``.status`` field (an ``int``);
        regular headers use the dict API.  Changing ``.status`` is how a
        policy changes the status the browser sees — h2 maps it to the
        ``:status`` pseudo-header, h1 to the status line.  Symmetric with
        :meth:`transform_request_headers`.
        """
        ...

    # -- capture lifecycle -------------------------------------------------

    def open_capture(self, url: str) -> Optional[_ResponseCapture]:
        """Open a response capture if *url* matches a live interceptor.

        Called once per request, before any response bytes arrive.
        Return a fresh ``_ResponseCapture`` to start buffering, or
        ``None`` if no interceptor wants this URL.
        """
        ...

    def deliver_capture(self, capture: _ResponseCapture) -> None:
        """Finalise and dispatch a completed capture to interceptors.

        Called once the response body has been fully received.  The
        capture's status, headers, and body buffer are populated by
        the handler before this is invoked.
        """
        ...

class DefaultPolicy:
    """The proxy's default policy: hygiene + URL→header rules + capture lifecycle.

    Satisfies the :class:`Policy` protocol.  When ``SessionProxy`` is
    constructed without an explicit ``policy=`` argument, an instance
    of this class is used as the default.

    Three layers of behaviour, applied in order:

    1. **Hygiene** — strip client-hints, sec-ch-* headers, h2-forbidden
       headers, and h3 entries from response Alt-Svc.  Always-on.
    2. **Header rules** — symmetric request/response header merging:
       :meth:`set_request_header_rule` merges headers into matching
       outgoing requests; :meth:`set_response_header_rule` merges headers
       into matching incoming responses.  Each header is set/overridden,
       or *dropped* if its value is ``None`` (``""`` sets an empty value).
       Each call takes an optional ``name`` so multiple rules can be active
       at once; omit it for a single rule.
    3. **Capture lifecycle** — open a :class:`_ResponseCapture` if any
       active interceptor matches the URL, deliver on completion.  The
       capture reflects the **post-transform** view (the status/headers
       the browser sees), so interception and forwarding never disagree.

    Multiple rules
    ~~~~~~~~~~~~~~
    Rules are keyed by name and applied in insertion order.  When several
    matching rules set the same header, the last one wins.  Add a second
    rule by passing a distinct ``name``; re-using a name replaces that one
    rule and leaves the others alone.

    Where the advanced stuff goes
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    The declarative layer covers set / override / drop, but only
    *unconditionally* (drop by giving a header the value ``None``).
    Rewriting the status, or dropping a header for only *some* responses,
    belongs in a subclass that overrides the transform hook and calls
    ``super()`` to keep hygiene + rules.  The hook gets a typed view
    (:class:`ResponseHeaders` / :class:`RequestHeaders`): pseudo-headers
    are fields (``.status``; ``.method`` / ``.path`` / ``.scheme`` /
    ``.authority``), regular headers use the dict API.

    Stop the browser following a redirect — protocol-agnostic, because
    ``.status`` is the same field on h1 and h2 and there's no ``is_h2`` to
    branch on::

        class NoRedirectPolicy(DefaultPolicy):
            REDIRECTS = {301, 302, 303, 307, 308}

            def transform_response_headers(self, url, headers):
                headers = super().transform_response_headers(url, headers)
                if headers.status in self.REDIRECTS:
                    headers.status = 200
                    headers.discard(b"location")
                return headers

        proxy.set_policy(NoRedirectPolicy(proxy))

    A request example — pin a path or strip a query — using the fields::

        class CanonicalizePolicy(DefaultPolicy):
            def transform_request_headers(self, url, headers):
                headers = super().transform_request_headers(url, headers)
                headers["X-Trace-Id"] = uuid.uuid4().hex
                return headers

        proxy.set_policy(CanonicalizePolicy(proxy))
        proxy.set_request_header_rule({"https://api.example.com/*"}, [("X-Key", "abc")])
        # → hygiene + rule + custom logic all active

    The hygiene layer cannot be removed without consequences (h2-forbidden
    headers in particular will get the connection closed by the target).
    Custom subclasses that bypass hygiene must reimplement it.

    Rule storage
    ~~~~~~~~~~~~
    Rules are stored as state on the policy, not on the SessionProxy,
    so subclasses inherit them automatically.  ``proxy.set_request_header_rule(...)``
    and friends delegate to the active policy.  Storage is copy-on-write
    (each mutation rebinds a fresh dict), so the event-loop thread can read
    rules concurrently with off-loop ``set_*``/``remove_*`` calls without a
    lock — an in-progress request sees a consistent snapshot.

    Reference model
    ~~~~~~~~~~~~~~~
    The proxy owns the policy strongly (``proxy.policy``).  This class
    holds the proxy via ``weakref.proxy`` so a user holding a reference
    to a custom subclass doesn't accidentally keep the SessionProxy (and
    all its connections) alive past ``stop()``.  Calling a policy method
    after the proxy is destroyed raises ``ReferenceError``, by design —
    policy operations are meaningless without the owning session.
    """

    def __init__(
        self,
        proxy: SessionProxy,
        urls: Optional[set[str]] = None,
        headers: Optional[list[tuple[str, Optional[str]]]] = None,
    ):
        # weakref.proxy is transparent: ``self._proxy.method()`` works
        # exactly like a strong reference for attribute access.
        self._proxy = weakref.proxy(proxy)
        # Copy-on-write dicts keyed by rule name; insertion order = apply
        # order.  Never mutated in place (each mutation rebinds a fresh
        # dict) so the event-loop thread reads a consistent snapshot.
        self._request_rules: dict[str, _HeaderRule] = {}
        self._response_rules: dict[str, _HeaderRule] = {}
        if urls or headers:
            self.set_request_header_rule(urls or set(), headers or [])

    # -- header-rule API (symmetric request / response) --------------------
    #
    # Both sides do exactly one thing: when the request URL matches, merge
    # the rule's headers — set/override existing, append new, and *drop* any
    # whose value is ``None`` (``""`` sets a present-but-empty value).
    # ``name`` lets several rules coexist; omitting it targets the shared
    # "default" rule, so ``set_*_header_rule(urls, headers)`` called twice
    # replaces rather than accumulates (matching the original single feel).
    #
    # Anything *conditional* — rewriting a status code, dropping a header
    # only for certain responses, inspecting the body — is intentionally
    # absent.  Subclass and override the transform hook (see class docstring).

    @staticmethod
    def _reject_framing(name: str, headers: list[tuple[str, Optional[str]]]) -> None:
        # Value-agnostic: setting *or* dropping a framing header desyncs
        # body framing, so reject either.
        bad = {k.lower() for k, _ in headers} & _FRAMING_HEADERS
        if bad:
            raise ValueError(
                f"header rule {name!r} may not set or drop framing header(s) "
                f"{sorted(bad)}: changing body framing desyncs proxy↔browser"
            )

    # -- header hygiene + request-rule merging --------------------------
    #
    # Stateless helpers (formerly the separate ``HeaderModifier`` class).
    # Kept as static/class methods so subclasses and the protocol handlers
    # can call them, and so request hygiene lives beside the rule state it
    # serves.  Response hygiene (Alt-Svc h3 stripping) reuses filter_alt_svc
    # via the Headers API in transform_response_headers.

    # Headers that reveal client-hint / network data
    STRIP_HEADERS: frozenset[str] = frozenset(
        {"rtt", "ect", "downlink", "device-memory", "viewport-width", "dpr"}
    )

    # Prefix-based stripping (sec-ch-*, proxy-*)
    STRIP_PREFIXES: tuple[str, ...] = ("sec-ch-", "proxy-")

    # Note: HTTP/2's forbidden connection-level headers are enforced by the
    # h2 handler at serialise time (``_http2._H2_FORBIDDEN``), not here —
    # that's a per-protocol framing rule, not protocol-agnostic hygiene.

    @classmethod
    def should_strip(cls, name: str, value: str = "") -> bool:
        """Return ``True`` if the header is proxy-hygiene junk to remove.

        Protocol-agnostic: client-hints, sec-ch-* / proxy-* prefixes, and a
        non-``trailers`` ``te``.  HTTP/2's connection-level forbidden headers
        (``connection``, ``keep-alive``, ``transfer-encoding``, …) are *not*
        handled here — that's a framing rule the h2 handler enforces when it
        serialises into an h2 frame, not policy hygiene.
        """
        lower = name.lower()
        if lower in cls.STRIP_HEADERS:
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

            >>> self.filter_alt_svc('h3=":443"; ma=86400')
            None
            >>> self.filter_alt_svc('h2="alt:443", h3=":443"')
            'h2="alt:443"'
            >>> self.filter_alt_svc('clear')
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
    def scrub_request_headers(cls, headers: RequestHeaders) -> None:
        """Strip junk regular headers from a :class:`RequestHeaders` in place.

        Always-on, protocol-agnostic proxy hygiene that runs on *every*
        request: removes client-hints, sec-ch-* / proxy-* headers, and a
        non-``trailers`` ``te``.  Pseudo-headers are untouched (they're typed
        fields, not in the block this scrubs).  HTTP/2's forbidden
        connection-level headers are *not* removed here — the h2 handler
        drops those when it serialises into an h2 frame.

        Casing is preserved as stored: the view holds h1 names in their
        original case (fingerprint-sensitive) and h2 names lowercased, so
        scrubbing — which only *removes* — needs no casing logic.
        """
        for k, v in list(headers):  # snapshot; we mutate during iteration
            if cls.should_strip(k.decode("latin1"), v.decode("latin1")):
                headers.discard(k)

    @classmethod
    def merge_rule_headers(
        cls,
        headers: RequestHeaders,
        rule_headers: Sequence[tuple[str, Optional[str]]],
    ) -> None:
        """Merge *rule_headers* into a :class:`RequestHeaders` in place.

        Each rule header is set/overridden, or *dropped* if its value is
        ``None`` (``""`` sets a present-but-empty value).  Within a single
        rule a later entry for the same name wins.  Pseudo-headers and
        always-stripped (client-hint) headers in the rule are ignored —
        those aren't user-policy's to set via the regular block.  Set /
        override / drop all go through the view's API, which preserves
        existing casing + position and appends new headers at the end.

        (h2-forbidden connection headers are *not* filtered here; if a rule
        sets one, the h2 handler drops it at serialise time, same as for
        client-supplied forbidden headers.)
        """
        for name, value in rule_headers:
            nl = name.lower()
            if nl.startswith(":"):
                continue
            if nl in cls.STRIP_HEADERS:
                continue
            if value is None:
                headers.discard(name)
            else:
                headers[name] = value

    def set_request_header_rule(
        self,
        urls: set[str],
        headers: list[tuple[str, Optional[str]]],
        *,
        name: str = _DEFAULT_RULE_NAME,
    ) -> None:
        """Set (or replace) a named request-header rule.

        When a request URL matches any pattern in *urls*, *headers* are
        merged into the outgoing request: each is set/overridden, or
        *removed* if its value is ``None`` (``""`` keeps it as an empty
        value).  Dropping a header that isn't present is a no-op.  URL
        matching mirrors :class:`RequestInterceptor` (exact unless the
        pattern contains ``*``).  Re-using a *name* replaces just that
        rule; distinct names coexist and apply in insertion order.  Omit
        *name* for the common single-rule case::

            proxy.set_request_header_rule({"https://*"}, [("Referer", None)])
        """
        rule = _HeaderRule(_UrlMatcher.compile(urls), tuple((k, v) for k, v in headers))
        self._request_rules = {**self._request_rules, name: rule}

    def remove_request_header_rule(self, name: str = _DEFAULT_RULE_NAME) -> bool:
        """Remove a request rule by name.  Returns ``True`` if it existed."""
        if name not in self._request_rules:
            return False
        new = dict(self._request_rules)
        del new[name]
        self._request_rules = new
        return True

    def clear_request_header_rules(self) -> None:
        """Remove all request rules (hygiene still applies)."""
        self._request_rules = {}

    def set_response_header_rule(
        self,
        urls: set[str],
        headers: list[tuple[str, Optional[str]]],
        *,
        name: str = _DEFAULT_RULE_NAME,
    ) -> None:
        """Set (or replace) a named response-header rule.

        Symmetric with :meth:`set_request_header_rule`: when a response's
        request URL matches *urls*, *headers* are merged into the response
        before it reaches the browser — each set/overridden, or *removed*
        if its value is ``None`` (``""`` keeps it as an empty value).
        Dropping an absent header is a no-op.  This is still unconditional
        header merging; to rewrite a status code or drop a header only for
        *some* responses, subclass and override :meth:`transform_response_headers`.

        Example — strip a fingerprinting header from every response::

            proxy.set_response_header_rule({"https://*"}, [("Server", None)])

        Raises:
            ValueError: if *headers* sets or drops a framing header
                (``Content-Length``, ``Transfer-Encoding``, ``Connection``)
                — changing those desyncs body framing.
        """
        self._reject_framing(name, headers)
        rule = _HeaderRule(_UrlMatcher.compile(urls), tuple((k, v) for k, v in headers))
        self._response_rules = {**self._response_rules, name: rule}

    def remove_response_header_rule(self, name: str = _DEFAULT_RULE_NAME) -> bool:
        """Remove a response rule by name.  Returns ``True`` if it existed."""
        if name not in self._response_rules:
            return False
        new = dict(self._response_rules)
        del new[name]
        self._response_rules = new
        return True

    def clear_response_header_rules(self) -> None:
        """Remove all response rules (hygiene still applies)."""
        self._response_rules = {}

    def matches_rule(self, url: str) -> bool:
        """Return ``True`` if *url* matches any request rule's patterns."""
        return any(r.matcher.matches(url) for r in self._request_rules.values())

    # -- Policy: request side ----------------------------------------------

    def transform_request_headers(
        self,
        url: str,
        headers: RequestHeaders,
    ) -> RequestHeaders:
        # 1. Always-on hygiene (strip client-hints / proxy junk).
        self.scrub_request_headers(headers)
        # 2. Apply every matching request rule, in insertion order.
        for name, rule in self._request_rules.items():  # snapshot (copy-on-write)
            if rule.headers and rule.matcher.matches(url):
                logger.debug("[Policy] Applying request rule %r for: %s", name, url)
                self.merge_rule_headers(headers, rule.headers)
        return headers

    # -- Policy: response side ---------------------------------------------

    def transform_response_headers(
        self,
        url: str,
        headers: ResponseHeaders,
    ) -> ResponseHeaders:
        # 1. Always-on hygiene: strip h3 (QUIC) entries from Alt-Svc so the
        #    browser can't upgrade to a protocol we can't intercept.
        alt = headers.get(b"alt-svc")
        if alt is not None:
            filtered = self.filter_alt_svc(alt.decode("latin1"))
            if filtered is None:
                headers.discard(b"alt-svc")
            elif filtered.encode("latin1") != alt:
                headers[b"alt-svc"] = filtered.encode("latin1")

        # 2. Apply every matching response rule, in insertion order.  The
        #    default policy only sets/drops headers and never touches the
        #    status — subclasses override this method for status rewrites
        #    and conditional logic, using the same Headers API.  A rule
        #    value of None means "drop"; everything else is a set/override.
        for name, rule in self._response_rules.items():  # snapshot (copy-on-write)
            if not (rule.headers and rule.matcher.matches(url)):
                continue
            logger.debug("[Policy] Applying response rule %r for: %s", name, url)
            for hk, hv in rule.headers:
                if hv is None:
                    headers.discard(hk)
                else:
                    headers[hk] = hv

        return headers

    def open_capture(self, url: str) -> Optional[_ResponseCapture]:
        return self._proxy._start_capture(url)

    def deliver_capture(self, capture: _ResponseCapture) -> None:
        self._proxy._deliver_capture(capture)
