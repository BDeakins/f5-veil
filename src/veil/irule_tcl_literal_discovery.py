r"""Pass 1.95 — iRule TCL literal walker (v1.2.1 T4+T5).

Scans QSTRING bodies inside iRule TCL contexts for identity-shaped
literals that escape every other walker class. Four high-precision
shape detectors:

1. NETBIOS domain prefix (``CORP\\`` shape) — uppercase-leading 2-15
   char identifier followed by a literal backslash. Reveals
   customer's AD NETBIOS domain name.
2. Permissive FQDN (any TLD, 3+ labels) — SaaS tenant subdomains
   (``api-ce04d788.duosecurity.com``), vendor product subdomains,
   any customer-authored URL. The strict ``fqdn_discovery`` walker
   intentionally skips public TLDs to avoid false positives in
   stock pool members; inside iRule TCL string literals the same
   protection isn't needed because the strings are 100% customer-
   authored.
3. Email literal (``user@domain.tld``).
4. UNC server\share literal (``\\\\server\\share``).

Scope of TCL bodies to scan
---------------------------
- ``ltm rule /<partition>/<name> { ... }`` body
- ``apm policy customization /...`` and ``customization-source``
- ``apm policy agent <subtype> /...`` — any subtype (variable-assign,
  irule-event, decision-box all carry TCL ``expression`` bodies)

Why this exists
---------------
v121_t1a round 2 surfaced ``corp\\`` (NETBIOS prefix) inside an
``apm policy agent variable-assign`` TCL expression — escapes T1A
(description), T1B (session-namespace), and AD-DN walkers because
it's a raw TCL string literal carrying identity-shaped content.

v121_t2 round 3 surfaced ``api-ce04d788.duosecurity.com`` (Duo SaaS
tenant URL) inside an iRule TCL QSTRING — the strict FQDN walker
skipped it because ``duosecurity.com`` is a public TLD.

Both leaks share the root cause: free-form QSTRING content inside
TCL bodies. This walker closes that scope.

Shape detector design notes
---------------------------
NETBIOS: source text inside a TMSH QSTRING preserves backslash
escapes byte-for-byte, so the canonical NETBIOS-prefix shape
``CORP\`` appears in the QSTRING content as ``CORP\\`` (single
escape level, e.g. ``set domain "CORP\\username"``) or as
``CORP\\\\`` (nested escape, e.g. inside an APM ``expression``
QSTRING whose content is itself a TCL string). Regex accepts
either with ``\\\\+`` (one or more pairs of backslashes).

Permissive FQDN: requires 3+ labels (skips 2-label false positives
like ``index.html``, ``config.json``) and an alphabetic 2-24 char
TLD (skips numeric labels like timestamps and version triplets).

Email: standard ``local@domain`` shape. Domain doesn't require 3+
labels (``user@example.com`` is valid).

UNC: matches both single-escape ``\\\\server\\share`` (2 leading
backslashes in TMSH-escaped form) and nested-escape variants.
"""

from __future__ import annotations

import ipaddress
import re

from .ledger import Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize


# ---------------------------------------------------------------------------
# Block-header matchers — variable-arity to handle the apm-policy-agent
# subtype slot (4-word with a free-form last word).


def _try_match_irule_header(tokens: list[Token], i: int) -> int:
    """Return the number of WORD tokens consumed if ``tokens[i:]``
    matches an iRule-context block header, else 0."""
    n = len(tokens)

    # ``ltm rule /partition/name { ... }`` — 2-word
    if (
        i + 1 < n
        and tokens[i].kind == TokKind.WORD and tokens[i].value == "ltm"
        and tokens[i + 1].kind == TokKind.WORD and tokens[i + 1].value == "rule"
    ):
        return 2

    # ``apm policy agent <subtype> /...`` — 4-word (subtype varies:
    # variable-assign, irule-event, decision-box, aaa-active-directory,
    # category-lookup, etc.). Matched BEFORE the generic 3-word case
    # so the 4-word agent header isn't shadowed.
    if (
        i + 3 < n
        and tokens[i].kind == TokKind.WORD and tokens[i].value == "apm"
        and tokens[i + 1].kind == TokKind.WORD and tokens[i + 1].value == "policy"
        and tokens[i + 2].kind == TokKind.WORD and tokens[i + 2].value == "agent"
        and tokens[i + 3].kind == TokKind.WORD
    ):
        return 4

    # ``apm policy <subtype> /...`` — 3-word (subtype: policy-item,
    # access-policy, customization, customization-source,
    # customization-group, customization-group-set, image-file, ...).
    # All these blocks carry TCL ``expression`` fields, child block
    # leaf names, or inline customization strings that need scanning.
    if (
        i + 2 < n
        and tokens[i].kind == TokKind.WORD and tokens[i].value == "apm"
        and tokens[i + 1].kind == TokKind.WORD and tokens[i + 1].value == "policy"
        and tokens[i + 2].kind == TokKind.WORD
    ):
        return 3

    # ``apm sso <subtype> /...`` — 3-word (subtype varies:
    # form-based, form-basedv2, kerberos, ntlmv2, oauth-bearer, saml,
    # saml-resource, saml-sp-connector, ...). These blocks contain
    # ``forms { ... <vendor>_logon_form { ... } ... }`` child blocks
    # where the leaf bareword embeds a vendor name (T5 scope).
    if (
        i + 2 < n
        and tokens[i].kind == TokKind.WORD and tokens[i].value == "apm"
        and tokens[i + 1].kind == TokKind.WORD and tokens[i + 1].value == "sso"
        and tokens[i + 2].kind == TokKind.WORD
    ):
        return 3

    return 0


# ---------------------------------------------------------------------------
# Shape detectors.


# NETBIOS: 2-15 char identifier (NETBIOS rule) + 2+ trailing backslashes
# (1+ escape pairs).  Left boundary excludes identifier chars so
# ``foocorp\\`` doesn't false-match ``corp\\``.
_NETBIOS_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"(?P<name>[A-Za-z][A-Za-z0-9_-]{1,14})"
    r"\\\\+"
)


# TCL keywords + common identifiers that look NETBIOS-shaped but are
# actually TCL syntax. Lowercase compare. ``set``, ``puts``, ``expr``,
# etc. could each be followed by ``\\`` in a line-continuation context;
# skip those.
_NETBIOS_SKIP = frozenset({
    "set", "puts", "expr", "if", "else", "elseif", "return", "regexp",
    "regsub", "string", "split", "lindex", "lrange", "list", "array",
    "incr", "proc", "global", "upvar", "foreach", "for", "while",
    "break", "continue", "switch", "catch", "error", "eval", "exec",
    "format", "scan", "subst", "unset", "call", "lset", "llength",
    "append", "concat", "join", "trim", "tolower", "toupper", "map",
    "info", "namespace", "package", "uplevel",
    # iRule HTTP/TCP/SSL command base names occasionally preceding
    # backslash-line-continuation.
    "http", "https", "tcp", "ssl", "log", "rule", "node", "pool",
})


# Permissive FQDN: 3+ labels, TLD alphabetic 2-24 chars. Length
# constraints prevent matching ``index.html`` (2 labels) or
# ``12.30.45`` (numeric TLD).
_PERMISSIVE_FQDN_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?P<fqdn>"
    r"[A-Za-z0-9][A-Za-z0-9-]{0,62}"
    r"(?:\.[A-Za-z0-9][A-Za-z0-9-]{0,62}){1,}"
    r"\.[A-Za-z]{2,24}"
    r")"
    r"(?![A-Za-z0-9_-])"
)


# Email: ``local@domain.tld``. Local part liberal (RFC 5321 permits
# many chars but configs rarely use exotic ones); domain reuses
# permissive shape (any TLD).
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9_.+-])"
    r"(?P<email>"
    r"[A-Za-z0-9._+-]+"
    r"@"
    r"[A-Za-z0-9][A-Za-z0-9-]{0,62}"
    r"(?:\.[A-Za-z0-9][A-Za-z0-9-]{0,62})*"
    r"\.[A-Za-z]{2,24}"
    r")"
    r"(?![A-Za-z0-9_-])"
)


# UNC: ``\\server\share`` shape. In QSTRING content, the leading
# ``\\`` is at least 4 backslashes (TMSH single-escape) or 8
# (nested). Match the canonical 4-backslash form plus optional
# extra pairs.
_UNC_RE = re.compile(
    r"\\\\\\\\(?:\\\\)*"  # leading \\\\ + optional extra pairs
    r"(?P<server>[A-Za-z][A-Za-z0-9_-]{1,62})"
    r"\\\\(?:\\\\)?"  # one or two backslash pairs
    r"(?P<share>[A-Za-z0-9][A-Za-z0-9_$.-]{0,62})"
)


# IPv4 literal with optional CIDR suffix. Captures the IP portion
# separately so the substring sub substitutes only the IP and leaves
# the ``/<cidr>`` literal intact (CIDR masks aren't customer-
# identifying on their own).
_IPV4_LITERAL_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"(?:/\d{1,2})?"
    r"(?![A-Za-z0-9_-])"
)


# ---------------------------------------------------------------------------
# Walker entry point.


def discover_irule_tcl_literals(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Walk the token stream, find every iRule-context top-level
    block, scan QSTRINGs inside the body, and apply the four shape
    detectors. Must run before ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "irule_tcl_literal_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        consumed = _try_match_irule_header(tokens, i)
        if consumed > 0:
            j = i + consumed
            while j < n and tokens[j].kind == TokKind.WORD:
                j += 1
            if j < n and tokens[j].kind == TokKind.LBRACE:
                i = _walk_irule_body(tokens, j + 1, ledger)
                continue
        i += 1


def _walk_irule_body(
    tokens: list[Token],
    start: int,
    ledger: Ledger,
) -> int:
    """Walk an iRule-context body from ``start`` (token after the
    opening ``{``). Scan every QSTRING inside; apply shape detectors.
    Returns the index just past the matching outer RBRACE."""
    n = len(tokens)
    i = start
    depth = 1
    while i < n and depth > 0:
        tk = tokens[i]
        if tk.kind == TokKind.LBRACE:
            depth += 1
            i += 1
            continue
        if tk.kind == TokKind.RBRACE:
            depth -= 1
            i += 1
            continue
        if tk.kind == TokKind.QSTRING:
            _scan_qstring(tk, ledger)
        i += 1
    return i


def _scan_qstring(tok: Token, ledger: Ledger) -> None:
    """Apply the four shape detectors to a QSTRING token's content.
    Skips QSTRINGs already interned as descriptions (pass-1.7 covers
    them via DESC)."""
    if len(tok.value) < 2:
        return
    # If pass-1.7 already interned this QSTRING as a description, skip
    # — the DESC substitution will replace the whole token and any
    # shape we'd register here would orphan.
    if (Kind.DESC, tok.value) in ledger.by_original:
        return
    content = tok.value[1:-1]
    if not content:
        return
    content_start = tok.offset + 1

    _scan_netbios(content, content_start, tok.line, ledger)
    _scan_unc(content, content_start, tok.line, ledger)
    _scan_fqdn(content, content_start, tok.line, ledger)
    _scan_email(content, content_start, tok.line, ledger)
    _scan_ipv4(content, content_start, tok.line, ledger)


def _scan_netbios(
    content: str,
    content_start: int,
    line: int,
    ledger: Ledger,
) -> None:
    for m in _NETBIOS_RE.finditer(content):
        name = m.group("name")
        if name.lower() in _NETBIOS_SKIP:
            continue
        if (Kind.AD_NETBIOS, name) in ledger.by_original:
            continue
        ref = Ref(
            byte_offset=content_start + m.start("name"),
            length=len(name),
            line=line,
        )
        ledger.intern(Kind.AD_NETBIOS, name, ref, partition=None)


def _scan_unc(
    content: str,
    content_start: int,
    line: int,
    ledger: Ledger,
) -> None:
    for m in _UNC_RE.finditer(content):
        # Intern the full UNC text as it appears in the source (matches
        # what substring-sub will look for).
        full = m.group(0)
        if (Kind.UNC_PATH, full) in ledger.by_original:
            continue
        ref = Ref(
            byte_offset=content_start + m.start(),
            length=len(full),
            line=line,
        )
        ledger.intern(Kind.UNC_PATH, full, ref, partition=None)


def _scan_fqdn(
    content: str,
    content_start: int,
    line: int,
    ledger: Ledger,
) -> None:
    for m in _PERMISSIVE_FQDN_RE.finditer(content):
        fqdn = m.group("fqdn")
        # Dedup against the strict FQDN walker (pass 2.0).
        if (Kind.FQDN, fqdn) in ledger.by_original:
            continue
        ref = Ref(
            byte_offset=content_start + m.start("fqdn"),
            length=len(fqdn),
            line=line,
        )
        ledger.intern(Kind.FQDN, fqdn, ref, partition=None)


def _scan_email(
    content: str,
    content_start: int,
    line: int,
    ledger: Ledger,
) -> None:
    for m in _EMAIL_RE.finditer(content):
        addr = m.group("email")
        if (Kind.USERNAME, addr) in ledger.by_original:
            continue
        ref = Ref(
            byte_offset=content_start + m.start("email"),
            length=len(addr),
            line=line,
        )
        ledger.intern(Kind.USERNAME, addr, ref, partition=None)


def _scan_ipv4(
    content: str,
    content_start: int,
    line: int,
    ledger: Ledger,
) -> None:
    """Find IPv4 literals (with optional CIDR) inside an iRule TCL
    QSTRING and intern via :meth:`Ledger.intern_ipaddr` so they
    substitute to RFC 5737 docs-range addresses. The CIDR suffix is
    left literal (mask values aren't customer-identifying)."""
    for m in _IPV4_LITERAL_RE.finditer(content):
        ip_str = m.group("ip")
        try:
            addr = ipaddress.IPv4Address(ip_str)
        except ipaddress.AddressValueError:
            continue
        # Skip already-docs-range IPs (idempotent).
        if (Kind.IPADDR, ip_str) in ledger.by_original:
            continue
        ref = Ref(
            byte_offset=content_start + m.start("ip"),
            length=len(ip_str),
            line=line,
        )
        try:
            ledger.intern_ipaddr(ip_str, ref)
        except (ValueError, RuntimeError):
            # Allocator exhaustion or bad address shape — leave
            # untokenized (leak detector will flag if relevant).
            continue
        _ = addr  # silence unused-variable lint


# ---------------------------------------------------------------------------
# T5 — iRule TCL identifier walker.
#
# Runs as a SEPARATE pass (2.25) so it observes the SESSION_NS entries
# minted by T1B (pass 2.2). For every WORD token inside an iRule-context
# block body, checks whether the token contains a SESSION_NS vendor word
# as a TCL-identifier-bounded substring (i.e. flanked by ``_`` / ``::`` /
# start/end of identifier — characters that the strict ``_WORD_CHARS``
# substring-sub treats as identifier-internal, so the existing SESSION_NS
# substring-sub won't fire). When a match is found, the FULL identifier
# is interned as ``Kind.IRULE_IDENT`` with a rendered placeholder that
# replaces every embedded vendor word with its SESSION_NS placeholder.
#
# Example: T1B interns ``grafana -> foo``. T5 sees
# ``static::jwt_grafana_debug`` inside an iRule body; the embedded
# ``grafana`` is flanked by ``_`` on both sides. T5 interns:
#   original  = ``static::jwt_grafana_debug``
#   rendered  = ``static::jwt_foo_debug``
# Pass-2 substring-sub then substitutes the whole identifier word-
# bounded (its identifier-edge chars are whitespace / ``{`` / ``$`` /
# ``[`` / etc., all in the strict boundary set), so no false-fire risk.


# Identifier-internal separator chars in TCL: ``_`` and ``:`` (for
# ``::`` namespace separator). Anything else flanking an embedded
# vendor word is an identifier-edge and the substring is already
# substitutable by SESSION_NS's existing strict substring-sub —
# T5 would just double-handle it.
_IDENT_SEP_CHARS = frozenset({"_", ":"})


def discover_irule_tcl_identifiers(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Pass 2.25 — scan WORD tokens inside iRule-context bodies for
    TCL identifiers that embed an already-interned SESSION_NS vendor
    word; intern each such identifier as ``Kind.IRULE_IDENT`` with a
    rewritten placeholder. Must run AFTER SESSION_NS interning
    (pass 2.2) and BEFORE ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "irule_tcl_identifier_discovery must run before ledger.freeze()"
        )
    # Collect SESSION_NS vendor words once. The lookup is small (vocab
    # tops out at ~13 entries before recycling).
    session_ns_entries: list[tuple[str, str]] = []
    for (kind, orig), placeholder in ledger.by_original.items():
        if kind == Kind.SESSION_NS:
            session_ns_entries.append((orig, placeholder))
    if not session_ns_entries:
        return
    # Longest-original-first ensures multi-match identifiers resolve
    # the largest vendor word before any shorter overlapping one.
    session_ns_entries.sort(key=lambda p: -len(p[0]))

    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        consumed = _try_match_irule_header(tokens, i)
        if consumed > 0:
            j = i + consumed
            while j < n and tokens[j].kind == TokKind.WORD:
                j += 1
            if j < n and tokens[j].kind == TokKind.LBRACE:
                i = _walk_irule_body_for_idents(
                    tokens, j + 1, ledger, session_ns_entries,
                )
                continue
        i += 1


def _walk_irule_body_for_idents(
    tokens: list[Token],
    start: int,
    ledger: Ledger,
    session_ns_entries: list[tuple[str, str]],
) -> int:
    n = len(tokens)
    i = start
    depth = 1
    while i < n and depth > 0:
        tk = tokens[i]
        if tk.kind == TokKind.LBRACE:
            depth += 1
            i += 1
            continue
        if tk.kind == TokKind.RBRACE:
            depth -= 1
            i += 1
            continue
        if tk.kind == TokKind.WORD:
            _maybe_intern_identifier(tk, ledger, session_ns_entries)
        i += 1
    return i


def _maybe_intern_identifier(
    tok: Token,
    ledger: Ledger,
    session_ns_entries: list[tuple[str, str]],
) -> None:
    """If ``tok.value`` embeds one or more SESSION_NS vendor words as
    identifier-bounded substrings, intern the full token as
    ``Kind.IRULE_IDENT`` with the embedded vendor words replaced by
    their SESSION_NS placeholders."""
    v = tok.value
    # Skip trivially short tokens (no room for embedded vendor word).
    if len(v) < 4:
        return
    # Skip path-shaped tokens — they're handled by other walkers (the
    # REMOTE_ROLE / PROFILE / etc. machinery rewrites paths with
    # partition awareness). T5 only handles bareword identifiers.
    if v.startswith("/"):
        return
    # Skip if already a IRULE_IDENT entry's original (dedup).
    if (Kind.IRULE_IDENT, v) in ledger.by_original:
        return

    # Find non-overlapping embedded SESSION_NS matches with identifier-
    # bounded flanks.
    matches: list[tuple[int, int, str]] = []  # (start, end, placeholder)
    used = [False] * len(v)
    for orig, placeholder in session_ns_entries:
        olen = len(orig)
        pos = 0
        while True:
            idx = v.find(orig, pos)
            if idx < 0:
                break
            pos = idx + 1
            # Boundary check: flanking chars must be identifier
            # separators OR start/end-of-token. ``_``, ``:`` are TCL
            # identifier-internal separators; alphanumeric chars
            # indicate the vendor word is part of a larger sub-token
            # (likely false-positive, skip).
            left_ok = idx == 0 or v[idx - 1] in _IDENT_SEP_CHARS
            right_ok = (
                idx + olen == len(v)
                or v[idx + olen] in _IDENT_SEP_CHARS
            )
            if not (left_ok and right_ok):
                continue
            # Reserve range; skip if any byte already used by a
            # longer earlier match.
            if any(used[idx:idx + olen]):
                continue
            matches.append((idx, idx + olen, placeholder))
            for k in range(idx, idx + olen):
                used[k] = True

    if not matches:
        return

    # Stitch the rendered identifier — left-to-right replacement.
    matches.sort(key=lambda t: t[0])
    out_parts: list[str] = []
    cursor = 0
    for start_idx, end_idx, placeholder in matches:
        out_parts.append(v[cursor:start_idx])
        out_parts.append(placeholder)
        cursor = end_idx
    out_parts.append(v[cursor:])
    rendered = "".join(out_parts)
    if rendered == v:
        # Defensive: no actual change — would orphan the entry. Skip.
        return

    ref = Ref(
        byte_offset=tok.offset,
        length=tok.length,
        line=tok.line,
    )
    try:
        ledger.intern_irule_ident(v, rendered, ref)
    except RuntimeError:
        # Collision with existing entry (rare) — skip rather than
        # crashing. The leak detector will flag it post-substitute
        # if the original survives.
        pass
