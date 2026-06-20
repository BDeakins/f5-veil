"""bigip.conf pass-1 scanner — top-level object discovery.

Walks the token stream from :func:`veil.tokenizer.tokenize` and registers
every named top-level object in the ledger. Inside a block body the
scanner tracks brace depth and ignores token content — body substitution
is the concern of pass 2, not pass 1.

Tracer-bullet object scope (v0.1):
- ``ltm pool /<partition>/<name> { ... }``
- ``ltm virtual /<partition>/<name> { ... }``
- ``ltm node /<partition>/<name> { ... }``
- ``ltm monitor <subtype> /<partition>/<name> { ... }``
- ``ltm rule /<partition>/<name> { ... }``
- The partition path itself (``/Common/`` is exempt; everything else
  gets a ``PARTITION_NNNN`` placeholder).

Known gaps deferred to follow-up PRs (flagged by TEMPER, owned by HAMMER
to address before pass-2 substitution lands):
- TMSH ``description { brace-quoted string }`` is parsed as an opening
  LBRACE by the current tokenizer. Pass 1 never traverses descriptions
  so this is currently harmless, but pass-2 substitution must avoid
  treating a brace-quoted description body as a nested block.
- iRule (Tcl) bodies are brace-counted but not Tcl-lexed. Pass-2
  substitution inside an iRule body must skip Tcl strings and ``#``
  comments instead of blindly rewriting every match.
- Unknown ``ltm <subtype>`` headers (e.g. ``ltm dns ...``) are silently
  skipped — by design until the kind list expands.
"""

from __future__ import annotations

from types import MappingProxyType

from .ad_dn_discovery import discover_ad_dns
from .ad_query_attrname_discovery import discover_ad_query_attrnames
from .apm_session_var_discovery import (
    discover_apm_session_namespaces,
    preregister_session_ns_collisions,
)
from .description_discovery import discover_descriptions
from .diagnostics import Diagnostics
from .fqdn_discovery import discover_fqdns
from .ip_discovery import discover_ip_literals
from .irule_comment_discovery import discover_irule_comments
from .irule_tcl_literal_discovery import (
    discover_irule_tcl_identifiers,
    discover_irule_tcl_literals,
)
from .ledger import COMMON_PARTITION, Kind, Ledger, Ref
from .remote_role_discovery import discover_remote_roles
from .apm_var_literal_discovery import discover_apm_var_literals
from .cert_keychain_discovery import discover_cert_keychains
from .client_policy_discovery import discover_client_policies
from .data_group_records_discovery import discover_data_group_records
from .krb_realm_discovery import discover_krb_realms
from .ldap_filter_discovery import discover_ldap_filters
from .monitor_path_discovery import discover_monitor_paths
from .monitor_recv_discovery import discover_monitor_recv
from .saml_oauth_discovery import discover_saml_oauth
from .snmp_discovery import discover_snmp
from .sshd_discovery import discover_sshd_banners
from .syslog_discovery import discover_syslog
from .timestamp_discovery import discover_timestamps
from .tokenizer import Token, TokKind, tokenize
from .username_discovery import discover_usernames

_TWO_WORD_KINDS = MappingProxyType({
    "pool": Kind.POOL,
    "virtual": Kind.VS,
    "node": Kind.NODE,
    "rule": Kind.IRULE,
    "snat": Kind.SNAT,
    "snatpool": Kind.SNATPOOL,
    "virtual-address": Kind.VADDR,
})

# Top-level TMSH module words. Anything seen at depth 0 that starts with
# one of these but is not registered as a known kind goes into the
# scanner's Diagnostics. The leak detector (later PR) reads diagnostics
# to fail closed instead of silently passing customer-identifying data
# through unrecognised blocks.
_KNOWN_MODULES = frozenset({"ltm", "gtm", "net", "sys", "auth", "apm",
                            "asm", "pem", "security", "wom", "ilx", "cli"})

# BIG-IP factory built-in profile leaf names. These are universal TMOS
# signal — every config references ``/Common/http``, ``/Common/tcp``,
# etc. Substituting them would defeat AI reasoning ("which built-in
# profile is this virtual using?") without obfuscating customer data.
# v15.1+ factory set plus the common per-version variants. TEMPER /
# CRUCIBLE may extend on real-config feedback.
_BUILTIN_PROFILES = frozenset({
    # Layer 4 / 7 protocol
    "http", "http2", "http-explicit", "http-transparent",
    "tcp", "tcp-lan-optimized", "tcp-wan-optimized",
    "tcp-mobile-optimized", "tcp-legacy", "f5-tcp-lan",
    "f5-tcp-wan", "f5-tcp-mobile", "f5-tcp-progressive",
    "udp", "udp_decrement_ttl", "udp_gtm_dns",
    "fastL4", "fasthttp",
    # SSL
    "clientssl", "clientssl-insecure-compatible",
    "clientssl-secure", "wom-default-clientssl",
    "serverssl", "serverssl-insecure-compatible",
    "apm-default-clientssl", "splitsession-default-clientssl",
    "crypto-server-default-clientssl",
    "crypto-client-default-serverssl",
    # OneConnect / SNAT
    "oneconnect",
    # Application protocols
    "ftp", "dns", "sip", "rtsp", "stream", "ipother",
    "smtp", "smtps", "imap", "pop3", "ldap", "radius",
    "diameter", "mqtt", "websocket",
    # Acceleration / security
    "web-acceleration", "web-security", "wa-cache",
    "analytics", "request-log", "response-adapt",
    "request-adapt", "icap",
    # Persistence (shows up as ltm persistence <subtype> but profile
    # field appears for some forms — include defensively)
    "cookie", "source_addr", "dest_addr", "hash", "ssl",
    "universal", "msrdp", "sip_info",
})


def scan(
    src: str,
    ledger: Ledger | None = None,
    diagnostics: Diagnostics | None = None,
) -> tuple[Ledger, Diagnostics]:
    """Pass 1: discover named objects and populate the ledger.

    Returns ``(ledger, diagnostics)``. ``diagnostics.unknown_top_level``
    lists every top-level block the scanner did not register — pass 2
    callers MUST inspect this and fail closed on non-empty results unless
    the operator has explicitly opted into partial obfuscation.
    """
    if ledger is None:
        ledger = Ledger()
    if diagnostics is None:
        diagnostics = Diagnostics()
    tokens = list(tokenize(src))
    i = 0
    depth = 0
    while i < len(tokens):
        tok = tokens[i]
        if depth > 0:
            if tok.kind == TokKind.LBRACE:
                depth += 1
            elif tok.kind == TokKind.RBRACE:
                depth -= 1
            i += 1
            continue
        if tok.kind != TokKind.WORD:
            i += 1
            continue
        consumed = _try_match_object(tokens, i, ledger, diagnostics)
        if consumed > 0:
            i += consumed
            depth = 1
            continue
        # Unrecognised top-level header — record it and skip the block so
        # pass 2 callers can decide whether to fail closed.
        consumed = _record_unknown_top_level(tokens, i, ledger, diagnostics)
        if consumed > 0:
            i += consumed
            depth = 1
            continue
        i += 1
    # Pass 1.5 — bare IP literal discovery. Runs over the full token
    # stream (not constrained to top-level) because IP literals appear
    # in body context (``address 10.0.0.42``, ``destination 10.0.0.1:80``,
    # etc.). Must run before freeze.
    discover_ip_literals(src, ledger, diagnostics)
    # Pass 1.7 — description body redaction. Walks tokens looking for
    # the ``description`` keyword and its value; interns the value so
    # pass-2 can substitute it with a ``DESC_NNNN`` placeholder.
    discover_descriptions(src, ledger, diagnostics)
    # Pass 1.8 — Tcl ``#`` comment redaction inside ``ltm rule`` bodies
    # (v0.0.11). Top-level comments (e.g. ``#TMSH-VERSION:``) are NOT
    # discovered — they are universal BIG-IP signal.
    discover_irule_comments(src, ledger, diagnostics)
    # Pass 1.85 — ``auth remote-role role-info`` bucket-path discovery
    # (v1.2). The customer-defined role bucket names
    # (``/Common/F5_Admins``, ``/Common/Domain_Admins``, etc.) live
    # inside an unknown-top-level body that pass-1's main loop skips.
    # Without this pass they survive into sanitized output.
    discover_remote_roles(src, ledger, diagnostics)
    # Pass 1.85b — ``sys snmp`` body walker (v1.2). Pre-v1.2 the
    # community / trap bucket headers, plaintext community-string
    # values, and ``sys-contact`` / ``sys-location`` free-text fields
    # all leaked verbatim because ``sys snmp`` lands in
    # ``_record_unknown_top_level`` and pass-1 skips its body.
    discover_snmp(src, ledger, diagnostics)
    # Pass 1.85c — ``sys syslog`` body walker (v1.2). Pre-v1.2 the
    # remote-server bucket headers leaked verbatim for the same
    # reason as ``sys snmp``. Inner ``host`` field already caught by
    # pass-1.5; no secret-bearing body fields exist.
    discover_syslog(src, ledger, diagnostics)
    # Pass 1.85d — ``sys sshd`` banner walker (v1.2). Banner text
    # (``banner-text`` / ``pre-login-banner`` / ``post-login-banner``)
    # is multi-line free-text that customers frequently use to embed
    # company name, legal jurisdiction, or contact info.
    discover_sshd_banners(src, ledger, diagnostics)
    # Pass 1.85e — ``cert-key-chain`` nested bucket walker (v1.2).
    # The bucket-name bareword inside an ``ltm profile client-ssl``
    # body is composed from cert + root-CA filenames; pass-1 brace-
    # skips the PROFILE body so the nested bucket-name leaks.
    discover_cert_keychains(src, ledger, diagnostics)
    # Pass 1.85f — ``client-policy`` nested bucket walker (v1.2).
    # Same shape as cert-key-chain: nested bareword inside a profile
    # body that pass-1 brace-skips. Observed inside
    # ``apm profile connectivity``.
    discover_client_policies(src, ledger, diagnostics)
    # Pass 1.85g — identity / hostname field walker (v1.2). Field-
    # name allowlist (``admin-name``, ``basic-auth-username``,
    # ``user``, ``account-name``, ``server-name``) intern the
    # value as ``Kind.USERNAME``.
    discover_usernames(src, ledger, diagnostics)
    # Pass 1.85i — LDAP filter walker (v1.2). Context-gated to LDAP-
    # flavoured top-level blocks; interns ``filter <value>`` pairs
    # as ``Kind.LDAP_FILTER``.
    discover_ldap_filters(src, ledger, diagnostics)
    # Pass 1.85i.1 — AD query-attrname walker (v1.2.1 T3A). Shares
    # the LDAP-flavoured header allowlist with pass 1.85i. Interns
    # non-standard AD/LDAP attribute names listed inside
    # ``query-attrname { ... }`` as ``Kind.AD_ATTR``. Standard AD
    # schema attrs (``sAMAccountName``, ``mail``, etc.) pass through
    # via the walker's bundled allowlist.
    discover_ad_query_attrnames(src, ledger, diagnostics)
    # Pass 1.85j — SAML / OAuth identifier field walker (v1.2). Runs
    # BEFORE the FQDN walker so longest-match-first substring sub at
    # substitution time picks the full-URL SAML_ENTITY_ID over the
    # inner FQDN (user explicitly approved double-tokenization).
    discover_saml_oauth(src, ledger, diagnostics)
    # Pass 1.85k — Monitor recv walker (v1.2). Interns the value of
    # the ``recv`` field inside LTM/GTM monitor blocks as
    # ``Kind.MONITOR_RECV``.
    discover_monitor_recv(src, ledger, diagnostics)
    # Pass 1.85k.1 — Monitor URL-path walker (v1.2.1 T2). Parses the
    # request-line URL path inside ``send`` QSTRINGs and the value
    # of ``success-match-value`` fields when URL-shaped; interns
    # paths as ``Kind.MONITOR_PATH``. Catches vendor / application
    # fingerprints (``/NMC/...``, ``/top.asp``, ``/vdesk/...``, etc.)
    # that the v1.2 walker class missed.
    discover_monitor_paths(src, ledger, diagnostics)
    # Pass 1.85l — Data-group records walker (v1.2). Context-gated
    # to ``ltm data-group internal/external`` records bodies; interns
    # each non-path bareword bucket header as
    # ``Kind.DATA_GROUP_RECORD``.
    discover_data_group_records(src, ledger, diagnostics)
    # Pass 1.85n — Timestamp year-coarsening walker (v1.2.1 T3B).
    # Scans every ``creation-time`` / ``last-modified-time`` field
    # value and interns as ``Kind.TIMESTAMP`` with a year-coarsened
    # rendered form (``YYYY-01-01:00:00:00``). Year preserved for
    # low-fidelity operational metadata; specific date / time
    # generalized away.
    discover_timestamps(src, ledger, diagnostics)
    # Pass 1.85m — APM variable-assign expression literal walker.
    # Catches ``expression "return {LITERAL}"`` hard-coded values
    # being assigned to session variables (AD domain names, user-
    # names, plaintext passwords — F5's ``secure true`` does NOT
    # encrypt source-config literals).
    discover_apm_var_literals(src, ledger, diagnostics)
    # Pass 1.9 — LDAP / AD distinguished-name discovery inside QSTRINGs
    # (v0.0.13). Catches ``auth remote-role attribute "memberOf=CN=...,
    # DC=..."`` and APM access-policy ``expression "... CN=...,DC=..."``.
    discover_ad_dns(src, ledger, diagnostics)
    # Pass 1.95 — iRule TCL literal walker (v1.2.1 T4). Context-gated
    # to ``ltm rule`` / ``apm policy customization{,-source}`` /
    # ``apm policy agent`` bodies. Inside, scans every QSTRING for
    # NETBIOS prefix (``CORP\\``), permissive FQDN (any TLD, 3+
    # labels — catches SaaS tenant subdomains like
    # ``api-ce04d788.duosecurity.com`` that strict pass-2.0 skips),
    # email literal, and UNC path. Runs BEFORE pass 2.0 so the strict
    # walker can dedup internal-suffix FQDNs already interned here.
    discover_irule_tcl_literals(src, ledger, diagnostics)
    # Pass 2.0 — internal-FQDN discovery (v1.2). Catches
    # ``example.local`` / ``foo.lan`` / ``host.home.arpa`` shapes
    # embedded anywhere in WORD or QSTRING tokens. Pre-v1.2 these
    # leaked verbatim (the leak detector flagged them but nothing
    # redacted them). Public-internet FQDNs (``vendor.example.com``)
    # pass through.
    discover_fqdns(src, ledger, diagnostics)
    # Pass 2.1 — Kerberos realm walker (v1.2). Catches public-TLD
    # realms (``ACME.CORP``, ``BOGUS.COM``) that the FQDN walker
    # skips by design. Runs AFTER FQDN so the dedup short-circuit
    # sees internal-suffix realms (``ACME.LOCAL``) already registered
    # as FQDN entries.
    discover_krb_realms(src, ledger, diagnostics)
    # Pass 2.15 — pre-register SESSION_NS vocab collisions for THIS
    # source file. Multi-file callers (``scan_many``) should pre-
    # register across ALL files before entering this loop; the
    # in-loop call here is a safety net for single-file ``scan()``
    # callers and is idempotent for the multi-file case.
    preregister_session_ns_collisions(src, ledger)
    # Pass 2.2 — APM session-variable user-namespace tokenization
    # (v1.2.1 T1B). Catches ``session.custom.<word>.<rest>`` and
    # ``session.<non-builtin>.<rest>``. Placeholder vocab is the
    # canonical 13-word metasyntactic set (foo, bar, baz, ...).
    discover_apm_session_namespaces(src, ledger, diagnostics)
    # Pass 2.25 — iRule TCL identifier walker (v1.2.1 T5). Scans
    # WORD tokens inside iRule-context bodies for TCL identifiers
    # that embed a SESSION_NS vendor word as an identifier-bounded
    # substring (``static::jwt_grafana_debug`` → rewritten to
    # ``static::jwt_foo_debug``). Must run AFTER pass 2.2 so the
    # SESSION_NS entries exist in the ledger when the walker
    # iterates.
    discover_irule_tcl_identifiers(src, ledger, diagnostics)
    return ledger, diagnostics


def scan_many(
    sources: list[tuple[str, str]],
    ledger: Ledger | None = None,
    diagnostics: Diagnostics | None = None,
) -> tuple[Ledger, Diagnostics]:
    """Pass 1 across multiple source files sharing one ledger.

    ``sources`` is a list of ``(filename, content)`` pairs. Each pair is
    processed in order via :func:`scan` with the shared ledger forwarded
    between calls. Order matters: typical use is
    ``[("bigip_base.conf", base_src), ("bigip.conf", main_src)]`` so the
    base file's partitions / VLANs / self-IPs are registered before the
    main file's references to them are resolved.

    The shared ledger is what makes cross-file references work — when
    ``bigip.conf`` mentions ``vlan-name`` defined in ``bigip_base.conf``,
    the v1.1 BAREWORD infix substring substitution machinery substitutes
    the reference because the bareword is in the ledger.

    Returns the same ``(ledger, diagnostics)`` shape as :func:`scan`.
    Per-file substitution (pass 2) is the caller's responsibility — call
    :func:`veil.substitute.substitute` once per source file against the
    returned shared ledger.

    ``filename`` is stored only at the call-site level (the caller uses
    it to label outputs and to populate the answer-file ``sources``
    list); the scanner itself doesn't propagate filenames into ledger
    state.
    """
    if ledger is None:
        ledger = Ledger()
    if diagnostics is None:
        diagnostics = Diagnostics()
    # v1.2.1 T1B — pre-register SESSION_NS vocab collisions across
    # ALL source files before any per-file walker runs. Vocab
    # assignments are ledger-wide; a vocab word that collides with
    # content in file B can't be safely reassigned after file A's
    # walker has already minted placeholders.
    for _filename, src in sources:
        preregister_session_ns_collisions(src, ledger)
    for _filename, src in sources:
        scan(src, ledger=ledger, diagnostics=diagnostics)
    return ledger, diagnostics


def _record_unknown_top_level(
    tokens: list[Token],
    i: int,
    ledger: Ledger,
    diagnostics: Diagnostics,
) -> int:
    """If ``tokens[i:]`` looks like an unrecognised top-level block
    header (``<module> ... {``), log it to diagnostics, register the
    header path as ``Kind.UNKNOWN`` so pass-2 substitution rewrites it
    (preventing prefix-substring leaks), and return the tokens consumed
    up to and including the opening ``{``. Else 0."""
    first = tokens[i].value
    if first not in _KNOWN_MODULES:
        return 0
    # Walk forward until we hit an LBRACE or run out of tokens.
    j = i + 1
    while j < len(tokens) and tokens[j].kind != TokKind.LBRACE:
        j += 1
    if j >= len(tokens):
        return 0
    # Build a short header signature for diagnostics (first 1-2 words).
    if j - i >= 2 and tokens[i + 1].kind == TokKind.WORD:
        signature = f"{first} {tokens[i + 1].value}"
    else:
        signature = first
    diagnostics.unknown_top_level.append((signature, tokens[i].line))
    # Register the header path (the last bareword before LBRACE that
    # starts with '/') so pass-2 substitutes it instead of letting the
    # literal path leak via substring inside the unknown block header.
    # Skip if the same path is already registered under any other kind —
    # otherwise the UNK entry becomes an orphan (pass-2 substitutes via
    # the more specific kind, which comes first in the Kind iteration).
    path_tok = _find_unknown_header_path(tokens, i, j)
    if path_tok is not None and not _path_already_registered(ledger, path_tok.value):
        _register(ledger, Kind.UNKNOWN, path_tok, diagnostics)
    return (j - i) + 1  # consume through the LBRACE


def _path_already_registered(ledger: Ledger, path: str) -> bool:
    for kind in Kind:
        if kind == Kind.UNKNOWN:
            continue
        if (kind, path) in ledger.by_original:
            return True
    return False


def _find_unknown_header_path(
    tokens: list[Token], start: int, lbrace_idx: int
) -> Token | None:
    """Find the rightmost ``/Partition/leaf`` path between ``start`` and
    ``lbrace_idx`` (exclusive). Returns the WORD token directly, OR a
    synthetic WORD-shaped Token for QSTRING-wrapped paths (the
    customer's identifier had a space, so TMSH quoted it — e.g.
    ``security bot-defense signature "/Common/Example Bot B"``).
    Returns None if no such token exists — some unknown blocks
    (e.g. ``sys global-settings``) have no path component.

    The synthetic Token's ``value`` is the path WITHOUT the wrapping
    quotes; offset/length point into the QSTRING content (skipping
    the opening quote). This lets ``_register`` and the downstream
    ledger entry use the bare path as the canonical original, so
    pass-2's QSTRING substring substitution finds and replaces it
    cleanly inside the original ``"..."`` token."""
    for k in range(lbrace_idx - 1, start, -1):
        tk = tokens[k]
        if tk.kind == TokKind.WORD and tk.value.startswith("/"):
            return tk
        # QSTRING-wrapped path: ``"/Common/<name with spaces>"``.
        # Require at least 2 chars (the wrapping quotes) and a leading
        # ``/`` inside. Substring length > 0 is implied by the leading
        # ``/`` check (since a 2-char QSTRING ``""`` is empty).
        if (
            tk.kind == TokKind.QSTRING
            and len(tk.value) >= 3
            and tk.value[0] == '"'
            and tk.value[-1] == '"'
            and tk.value[1] == "/"
        ):
            stripped = tk.value[1:-1]
            return Token(
                kind=TokKind.WORD,
                value=stripped,
                offset=tk.offset + 1,
                length=tk.length - 2,
                line=tk.line,
            )
    return None


def _try_match_object(
    tokens: list[Token],
    i: int,
    ledger: Ledger,
    diagnostics: Diagnostics,
) -> int:
    """If ``tokens[i:]`` matches an object header, register it (or log a
    malformed-path diagnostic) and return the number of tokens consumed
    including the opening ``{``. Else 0."""
    if i + 3 >= len(tokens):
        return 0
    if tokens[i].value == "gtm":
        return _try_match_gtm_object(tokens, i, ledger, diagnostics)
    if tokens[i].value == "net":
        return _try_match_net_object(tokens, i, ledger, diagnostics)
    if tokens[i].value == "apm":
        return _try_match_apm_object(tokens, i, ledger, diagnostics)
    if tokens[i].value == "security":
        return _try_match_security_object(tokens, i, ledger, diagnostics)
    if tokens[i].value != "ltm":
        return 0
    second = tokens[i + 1].value
    if second == "monitor":
        # ltm monitor <subtype> /path {
        if i + 4 >= len(tokens):
            return 0
        path_tok = tokens[i + 3]
        lbrace = tokens[i + 4]
        if path_tok.kind != TokKind.WORD or lbrace.kind != TokKind.LBRACE:
            return 0
        _register(ledger, Kind.MON, path_tok, diagnostics)
        return 5
    if second == "data-group":
        # ltm data-group <internal|external> /path {
        if i + 4 >= len(tokens):
            return 0
        path_tok = tokens[i + 3]
        lbrace = tokens[i + 4]
        if path_tok.kind != TokKind.WORD or lbrace.kind != TokKind.LBRACE:
            return 0
        _register(ledger, Kind.DG, path_tok, diagnostics)
        return 5
    if second == "profile":
        # ltm profile <subtype> /path {
        if i + 4 >= len(tokens):
            return 0
        path_tok = tokens[i + 3]
        lbrace = tokens[i + 4]
        if path_tok.kind != TokKind.WORD or lbrace.kind != TokKind.LBRACE:
            return 0
        # Built-in profiles (``/Common/http``, ``/Common/tcp``, etc.)
        # are universal TMOS signal — pass through literal. Consume the
        # header (so the body is skipped via brace depth) but don't
        # intern.
        if _is_builtin_profile_path(path_tok.value):
            return 5
        _register(ledger, Kind.PROFILE, path_tok, diagnostics)
        return 5
    kind = _TWO_WORD_KINDS.get(second)
    if kind is None:
        return 0
    # ltm <kind> /path {
    path_tok = tokens[i + 2]
    lbrace = tokens[i + 3]
    if path_tok.kind != TokKind.WORD or lbrace.kind != TokKind.LBRACE:
        return 0
    _register(ledger, kind, path_tok, diagnostics)
    return 4


_GTM_TWO_WORD_KINDS = MappingProxyType({
    "server": Kind.GTM_SERVER,
    "datacenter": Kind.GTM_DC,
    "region": Kind.GTM_REGION,
})
_GTM_THREE_WORD_KINDS = MappingProxyType({
    "pool": Kind.GTM_POOL,
    "wideip": Kind.GTM_WIDEIP,
})

_NET_TWO_WORD_KINDS = MappingProxyType({
    "vlan": Kind.VLAN,
    "route-domain": Kind.ROUTE_DOMAIN,
    "self": Kind.SELF_IP,
    "trunk": Kind.TRUNK,
})

# APM uses three-word headers: ``apm <module> <subtype> /path {``.
# Modules: policy (covers access-policy, customization-source, etc.),
# profile (access, log-setting, etc.). AAA / SSO / ACL are deferred.
_APM_THREE_WORD_KINDS = MappingProxyType({
    "policy": Kind.APM_POLICY,
    "profile": Kind.APM_PROFILE,
})

# ``security firewall <kind> /path {`` — 5 tokens.
_SECURITY_FIREWALL_KINDS = MappingProxyType({
    "policy": Kind.FIREWALL_POLICY,
    "rule-list": Kind.FIREWALL_RULE_LIST,
    "address-list": Kind.FIREWALL_ADDRESS_LIST,
    "port-list": Kind.FIREWALL_PORT_LIST,
})


def _try_match_apm_object(
    tokens: list[Token],
    i: int,
    ledger: Ledger,
    diagnostics: Diagnostics,
) -> int:
    """``apm <module> <subtype> /path {`` — 5 tokens."""
    if i + 4 >= len(tokens):
        return 0
    second = tokens[i + 1].value
    kind = _APM_THREE_WORD_KINDS.get(second)
    if kind is None:
        return 0
    path_tok = tokens[i + 3]
    lbrace = tokens[i + 4]
    if path_tok.kind != TokKind.WORD or lbrace.kind != TokKind.LBRACE:
        return 0
    _register(ledger, kind, path_tok, diagnostics)
    return 5


def _try_match_security_object(
    tokens: list[Token],
    i: int,
    ledger: Ledger,
    diagnostics: Diagnostics,
) -> int:
    """``security firewall <kind> /path {`` — 5 tokens. Other security
    sub-modules (dos, log, nat, etc.) deferred."""
    if i + 4 >= len(tokens):
        return 0
    if tokens[i + 1].value != "firewall":
        return 0
    third = tokens[i + 2].value
    kind = _SECURITY_FIREWALL_KINDS.get(third)
    if kind is None:
        return 0
    path_tok = tokens[i + 3]
    lbrace = tokens[i + 4]
    if path_tok.kind != TokKind.WORD or lbrace.kind != TokKind.LBRACE:
        return 0
    _register(ledger, kind, path_tok, diagnostics)
    return 5


def _try_match_net_object(
    tokens: list[Token],
    i: int,
    ledger: Ledger,
    diagnostics: Diagnostics,
) -> int:
    """Recognise ``net <kind> /path {`` (4-token) headers. Returns
    tokens consumed or 0. ``net interface`` is intentionally NOT
    handled — interface names like ``1.1`` lack a ``/partition/leaf``
    structure and would slip into ``malformed_paths`` if registered."""
    second = tokens[i + 1].value
    kind = _NET_TWO_WORD_KINDS.get(second)
    if kind is None:
        return 0
    if i + 3 >= len(tokens):
        return 0
    path_tok = tokens[i + 2]
    lbrace = tokens[i + 3]
    if path_tok.kind != TokKind.WORD or lbrace.kind != TokKind.LBRACE:
        return 0
    _register(ledger, kind, path_tok, diagnostics)
    return 4


def _try_match_gtm_object(
    tokens: list[Token],
    i: int,
    ledger: Ledger,
    diagnostics: Diagnostics,
) -> int:
    """Recognise GTM family headers and intern them. Returns tokens
    consumed (including the opening ``{``) or 0 if no match.

    Shapes handled:
    - ``gtm pool <subtype> /path {``    — 5 tokens (GTM_POOL)
    - ``gtm wideip <subtype> /path {``  — 5 tokens (GTM_WIDEIP)
    - ``gtm server /path {``            — 4 tokens (GTM_SERVER)
    - ``gtm datacenter /path {``        — 4 tokens (GTM_DC)

    ``gtm topology`` / ``gtm region`` deferred to v0.0.7 — fall through
    to the unknown-top-level path so callers still see a diagnostic.
    """
    second = tokens[i + 1].value
    kind = _GTM_THREE_WORD_KINDS.get(second)
    if kind is not None:
        # gtm <pool|wideip> <subtype> /path {
        if i + 4 >= len(tokens):
            return 0
        path_tok = tokens[i + 3]
        lbrace = tokens[i + 4]
        if path_tok.kind != TokKind.WORD or lbrace.kind != TokKind.LBRACE:
            return 0
        _register(ledger, kind, path_tok, diagnostics)
        return 5
    kind = _GTM_TWO_WORD_KINDS.get(second)
    if kind is not None:
        # gtm <server|datacenter> /path {
        if i + 3 >= len(tokens):
            return 0
        path_tok = tokens[i + 2]
        lbrace = tokens[i + 3]
        if path_tok.kind != TokKind.WORD or lbrace.kind != TokKind.LBRACE:
            return 0
        _register(ledger, kind, path_tok, diagnostics)
        return 4
    return 0


def _is_builtin_profile_path(path: str) -> bool:
    """True if ``path`` is the well-known leaf of a BIG-IP factory
    built-in profile (e.g. ``/Common/http``, ``/Common/clientssl``)."""
    parsed = _split_partition_path(path)
    if parsed is None:
        return False
    partition, leaf = parsed
    if partition != COMMON_PARTITION:
        return False
    return leaf in _BUILTIN_PROFILES


def _split_partition_path(path: str) -> tuple[str, str] | None:
    """Parse ``/Partition/leaf`` -> ``(partition, leaf)``. Returns ``None``
    if the value is not a well-formed TMSH path (no partition, empty
    partition, or empty leaf — any of which would let a malformed config
    slip a garbage entry into the ledger)."""
    if not path.startswith("/"):
        return None
    parts = path.split("/")
    if len(parts) < 3:
        return None
    partition = parts[1]
    leaf = "/".join(parts[2:])
    if not partition or not leaf:
        return None
    return partition, leaf


def _register(
    ledger: Ledger,
    kind: Kind,
    path_tok: Token,
    diagnostics: Diagnostics,
) -> None:
    parsed = _split_partition_path(path_tok.value)
    if parsed is None:
        # Malformed path on a recognised object kind — fail closed by
        # surfacing to diagnostics rather than interning garbage.
        diagnostics.malformed_paths.append(
            (kind.value, path_tok.value, path_tok.line)
        )
        return
    partition, _leaf = parsed
    discovery = Ref(
        byte_offset=path_tok.offset,
        length=path_tok.length,
        line=path_tok.line,
    )
    # The partition substring sits inside the path token's byte span;
    # compute its absolute byte offset (skip the leading '/').
    part_discovery = Ref(
        byte_offset=path_tok.offset + 1,
        length=len(partition),
        line=path_tok.line,
    )
    ledger.intern_partition(partition, part_discovery)
    ledger.intern(kind, path_tok.value, discovery, partition=partition)
