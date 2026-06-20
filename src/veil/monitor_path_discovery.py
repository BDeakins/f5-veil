"""Pass 1.85k.1 — Monitor URL-path walker (v1.2.1 T2 + T8).

Scans for the URL path component of monitor request lines,
success-match values, AND non-monitor URL-bearing fields (T8
widening 2026-06-20). Surfaces:

1. ``send "<method> <path> HTTP/<v>"`` (T2) — extracts the URL path
   from the HTTP request line inside the ``send`` QSTRING body.
2. ``success-match-value <value>`` (T2) — interns the value (WORD or
   QSTRING) when it is URL-shaped (leading ``/``).
3. ``request-value <value>`` (T8) — APM access-policy expression /
   event-result URL paths. Same shape as ``success-match-value``.
4. ``uri <value>`` (T8) — SAML/OAuth IdP/SP connector URLs where the
   walker handles the PATH component; the FQDN walker handles the
   host portion separately. Skipped when the value already matched
   one of the dedicated SAML/OAuth field walkers (``sso-uri``,
   ``single-logout-uri``, etc.) which intern the full URL.
5. ``application-uri <value>`` (T8) — LTM/GTM application-URI
   references; same handling as ``uri``.

All routed to ``Kind.MONITOR_PATH``. The existing substring-sub
machinery then rewrites every occurrence of the path globally with
word-boundary protection.

Why this exists
---------------
v1.2 red-team T2 finding: monitor ``send`` strings and
``success-match-value`` fields leaked vendor / application
fingerprints — ``/NMC/<base64>/logon.htm`` (APC NMC web UI),
``/top.asp`` (classic ASP/IIS), ``/vdesk/hangup.php3`` (Citrix VDI
gateway), ``/zabbix/`` (Zabbix), ``/graph`` (Grafana data path),
``/cs<hex>/home.htm`` (per-tenant Citrix StoreFront). The existing
``monitor_recv_discovery`` walker handles the ``recv`` body but does
not parse the request-line URL inside ``send``.

Allowlist
---------
A small set of commodity paths (``/``, ``/index.html``, ``/login``,
``/health``, etc.) pass through verbatim — they're shipped with
every BIG-IP example config and tokenizing them would only add
noise without redacting anything identifying.
"""

from __future__ import annotations

import ipaddress
import re

from .ledger import Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize


# v1.2.2 — IPv4 literal (with optional CIDR) inside ``send`` / ``recv``
# QSTRING bodies. Catches the ``Host: 192.168.100.1`` shape that
# survived through v1.2.1 (T2 parses the request line but doesn't
# walk header values; the strict pass-1.5 IP walker doesn't descend
# into QSTRING content).
_IPV4_IN_QSTRING_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"(?:/\d{1,2})?"
    r"(?![A-Za-z0-9_-])"
)


# Commodity URL paths that pass through verbatim. Tokenizing these
# adds noise without obfuscating anything customer-identifying —
# they ship with every BIG-IP example config and appear in stock
# monitor templates.
_PATH_ALLOWLIST = frozenset({
    "/",
    "/index.html", "/index.htm", "/index.php", "/index.jsp",
    "/login", "/login.html", "/login.htm",
    "/health", "/healthz", "/healthcheck",
    "/status", "/ping", "/heartbeat",
    "/robots.txt", "/favicon.ico",
    "/sys-health", "/api/health", "/api/healthz", "/api/status",
})

# Matches an HTTP request line: ``<METHOD> <path> HTTP/<version>``
# inside the body of a ``send`` QSTRING. The path capture excludes
# whitespace so it terminates cleanly at the next space before
# ``HTTP/``. ``<METHOD>`` covers the F5-supported set; case-
# sensitive (TMSH-shipped templates use uppercase).
_HTTP_REQUEST_LINE_RE = re.compile(
    r"(?P<method>GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)"
    r"\s+(?P<path>/[^\s]*)\s+HTTP/"
)


# T8 — URL with scheme + host + path. Captures the leading scheme +
# host span (so we can locate the path's byte offset) and the path
# component separately. Path runs from the first ``/`` after the host
# until end-of-string or whitespace.
_FULL_URL_RE = re.compile(
    r"(?P<prefix>https?://[^/\s]+)(?P<path>/[^\s]*)"
)


# T8 — additional URL-bearing field names to gate. ``uri`` is generic
# but the walker only fires when the value is URL-shaped, so non-URL
# uses (rare) pass through verbatim.
_URL_FIELD_NAMES = frozenset({
    "request-value",
    "uri",
    "application-uri",
})


def discover_monitor_paths(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Walk the token stream, find ``send <qstring>`` HTTP request
    lines and ``success-match-value <value>`` URL-shaped values,
    intern paths as ``Kind.MONITOR_PATH``. Must run before
    ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "monitor_path_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        tk = tokens[i]
        if tk.kind == TokKind.WORD and i + 1 < n:
            if tk.value == "send":
                _intern_send_path(tokens[i + 1], ledger)
                _intern_ipv4_in_qstring(tokens[i + 1], ledger)
                i += 2
                continue
            if tk.value == "recv":
                _intern_ipv4_in_qstring(tokens[i + 1], ledger)
                i += 2
                continue
            if tk.value == "success-match-value":
                _intern_success_match_value(tokens[i + 1], ledger)
                i += 2
                continue
            if tk.value in _URL_FIELD_NAMES:
                _intern_url_field_value(tokens[i + 1], ledger)
                i += 2
                continue
        i += 1


def _intern_send_path(value_tok: Token, ledger: Ledger) -> None:
    """If ``value_tok`` is a QSTRING containing an HTTP request line,
    intern the URL path as ``Kind.MONITOR_PATH`` (unless allowlisted)."""
    if value_tok.kind != TokKind.QSTRING:
        return
    if len(value_tok.value) < 2:
        return
    content = value_tok.value[1:-1]
    if not content:
        return
    match = _HTTP_REQUEST_LINE_RE.search(content)
    if match is None:
        return
    path = match.group("path")
    if path in _PATH_ALLOWLIST:
        return
    if (Kind.MONITOR_PATH, path) in ledger.by_original:
        return
    # Byte offset of the path inside the QSTRING content (skipping the
    # opening quote). Use the match's start position in ``content``.
    path_start_in_content = match.start("path")
    ref = Ref(
        byte_offset=value_tok.offset + 1 + path_start_in_content,
        length=len(path),
        line=value_tok.line,
    )
    ledger.intern(Kind.MONITOR_PATH, path, ref, partition=None)


def _intern_success_match_value(value_tok: Token, ledger: Ledger) -> None:
    """If ``value_tok`` is a URL-shaped value (leading ``/``), intern
    it as ``Kind.MONITOR_PATH`` (unless allowlisted)."""
    if value_tok.kind == TokKind.QSTRING:
        if len(value_tok.value) < 2:
            return
        content = value_tok.value[1:-1]
        if not content or not content.startswith("/"):
            return
        if content in _PATH_ALLOWLIST:
            return
        if (Kind.MONITOR_PATH, content) in ledger.by_original:
            return
        ref = Ref(
            byte_offset=value_tok.offset + 1,
            length=len(content),
            line=value_tok.line,
        )
        ledger.intern(Kind.MONITOR_PATH, content, ref, partition=None)
        return
    if value_tok.kind == TokKind.WORD:
        v = value_tok.value
        if not v.startswith("/"):
            return
        if v in _PATH_ALLOWLIST:
            return
        if (Kind.MONITOR_PATH, v) in ledger.by_original:
            return
        ref = Ref(
            byte_offset=value_tok.offset,
            length=value_tok.length,
            line=value_tok.line,
        )
        ledger.intern(Kind.MONITOR_PATH, v, ref, partition=None)


def _intern_url_field_value(value_tok: Token, ledger: Ledger) -> None:
    """T8 — intern a URL-bearing field value as ``Kind.MONITOR_PATH``.

    Handles two shapes:
    1. ``/path`` (bareword or quoted) — intern as-is.
    2. ``http(s)://host/path`` (bareword or quoted) — intern the FULL
       URL (host AND path together) so substring-sub's strict
       word-boundary check passes (interning only the path leaves it
       flanked on the left by the host's alphanumeric, blocking
       substitution). The FQDN walker also interns the host as a
       FQDN entry; substring-sub's longest-match-first picks the
       full URL for the URL occurrence and the bare FQDN for any
       standalone host references elsewhere.

    Non-URL values pass through (allows ``uri`` field to safely
    handle non-URL uses). Allowlist passthrough mirrors
    ``_intern_success_match_value``. Skips QSTRINGs already interned
    as SAML_*_URI by the SAML/OAuth walker."""
    if value_tok.kind == TokKind.QSTRING:
        if len(value_tok.value) < 2:
            return
        content = value_tok.value[1:-1]
        if not content:
            return
        if _is_already_full_url_interned(content, ledger):
            return
        if not _is_url_shaped(content):
            return
        if content in _PATH_ALLOWLIST:
            return
        if (Kind.MONITOR_PATH, content) in ledger.by_original:
            return
        ref = Ref(
            byte_offset=value_tok.offset + 1,
            length=len(content),
            line=value_tok.line,
        )
        ledger.intern(Kind.MONITOR_PATH, content, ref, partition=None)
        return
    if value_tok.kind == TokKind.WORD:
        v = value_tok.value
        if _is_already_full_url_interned(v, ledger):
            return
        if not _is_url_shaped(v):
            return
        if v in _PATH_ALLOWLIST:
            return
        if (Kind.MONITOR_PATH, v) in ledger.by_original:
            return
        ref = Ref(
            byte_offset=value_tok.offset,
            length=value_tok.length,
            line=value_tok.line,
        )
        ledger.intern(Kind.MONITOR_PATH, v, ref, partition=None)


def _is_url_shaped(value: str) -> bool:
    """True if ``value`` is a URL-shape we want to redact: either a
    leading-``/`` path, or a ``http(s)://host/...`` form."""
    if value.startswith("/"):
        return True
    return bool(_FULL_URL_RE.match(value))


def _intern_ipv4_in_qstring(value_tok: Token, ledger: Ledger) -> None:
    """v1.2.2 — scan a ``send`` / ``recv`` QSTRING content for IPv4
    literals (with optional CIDR) and intern via
    :meth:`Ledger.intern_ipaddr`. Catches IPs embedded in HTTP
    request headers (``Host: 10.0.0.1``) that T2's request-line
    parser misses and the strict pass-1.5 IP walker doesn't reach
    (QSTRING content). CIDR suffix is left literal — mask values
    aren't customer-identifying."""
    if value_tok.kind != TokKind.QSTRING:
        return
    if len(value_tok.value) < 2:
        return
    content = value_tok.value[1:-1]
    if not content:
        return
    content_start = value_tok.offset + 1
    for m in _IPV4_IN_QSTRING_RE.finditer(content):
        ip_str = m.group("ip")
        try:
            ipaddress.IPv4Address(ip_str)
        except ipaddress.AddressValueError:
            continue
        if (Kind.IPADDR, ip_str) in ledger.by_original:
            continue
        ref = Ref(
            byte_offset=content_start + m.start("ip"),
            length=len(ip_str),
            line=value_tok.line,
        )
        try:
            ledger.intern_ipaddr(ip_str, ref)
        except (ValueError, RuntimeError):
            continue


def _is_already_full_url_interned(value: str, ledger: Ledger) -> bool:
    """True if a SAML/OAuth walker already interned this exact value
    under one of the full-URL kinds. Prevents T8 from orphaning a
    sub-path entry when the SAML walker has the whole URL."""
    for kind in (
        Kind.SAML_ENTITY_ID,
        Kind.SAML_SSO_URI,
        Kind.SAML_SLO_URI,
        Kind.SAML_SLO_RESPONSE_URI,
        Kind.OAUTH_AUDIENCE,
        Kind.OAUTH_ISSUER,
    ):
        if (kind, value) in ledger.by_original:
            return True
    return False
