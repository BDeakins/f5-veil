"""Post-substitution leak detector — last line of defense.

Runs over the sanitized output of :func:`veil.substitute.substitute`
*before* the result is written to disk. Flags content that looks like
customer-identifying data which slipped through obfuscation:

- RFC1918 IPv4 (``10/8``, ``172.16/12``, ``192.168/16``)
- CGNAT IPv4 (``100.64/10``, RFC 6598)
- Link-local IPv4 (``169.254/16``, RFC 3927)
- Loopback IPv4 (``127/8``, RFC 1122)
- IPv6 ULA (``fc00::/7``, RFC 4193)
- IPv6 link-local (``fe80::/10``, RFC 4291)
- IPv6 loopback (``::1``, RFC 4291)
- Internal-shaped FQDN suffixes (``.local``, ``.corp``, ``.lan``,
  ``.internal``, ``.intranet``, ``.lan.local``, ``.home.arpa``,
  ``.private``)
- MAC addresses (``aa:bb:cc:dd:ee:ff``, ``aa-bb-...``, Cisco ``aabb.ccdd.eeff``)
- Identifier-shaped barewords (heuristic — letters with embedded digit,
  underscore, or hyphen) that aren't placeholders or TMSH keywords
- Path-shaped barewords whose partition piece isn't ``/Common/`` or
  ``/PARTITION_NNNN/`` (covers any non-safe partition leak)

Exemptions
----------
- RFC 5737 IPv4 documentation ranges (``192.0.2/24``, ``198.51.100/24``,
  ``203.0.113/24``) — these are the substituted IP placeholders.
- RFC 3849 IPv6 documentation range (``2001:db8::/32``).
- Literal ``Common`` — universal BIG-IP signal, not customer identity.
- Tokens matching ``^(POOL|VS|NODE|MON|IRULE|PARTITION|UNK)_\\d{4,}$``.

Design
------
- Pure function. Returns a :class:`LeakReport`; no I/O, no logging.
- Operates on the sanitized string. Line/col reported as 1-based pairs
  computed from the leak's byte offset.
- Heuristic by nature. A clean run is strong evidence; a flagged run
  needs operator review. ``--strict`` (CLI) treats any non-empty report
  as a fail-and-exit-5 condition.
"""

from __future__ import annotations

import bisect
import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum


class LeakKind(Enum):
    RFC1918_IPV4 = "RFC1918_IPV4"
    CGNAT_IPV4 = "CGNAT_IPV4"
    LINKLOCAL_IPV4 = "LINKLOCAL_IPV4"
    LOOPBACK_IPV4 = "LOOPBACK_IPV4"
    ULA_IPV6 = "ULA_IPV6"
    LINKLOCAL_IPV6 = "LINKLOCAL_IPV6"
    LOOPBACK_IPV6 = "LOOPBACK_IPV6"
    INTERNAL_FQDN = "INTERNAL_FQDN"
    MAC_ADDRESS = "MAC_ADDRESS"
    IDENTIFIER_BAREWORD = "IDENTIFIER_BAREWORD"
    IDENTIFIER_PATH = "IDENTIFIER_PATH"


@dataclass(frozen=True)
class Leak:
    kind: LeakKind
    token: str
    byte_offset: int
    line: int
    col: int
    reason: str


@dataclass
class LeakReport:
    leaks: list[Leak] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.leaks)

    def __len__(self) -> int:
        return len(self.leaks)


# ----- IP classification -------------------------------------------------

_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# IPv6 candidate — broad pattern, validated with ipaddress.
# Matches both full and compressed (::) forms, plus standalone ``::1``.
_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"  # full 8-group
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4})?"  # right-truncated
    r"|(?:[0-9A-Fa-f]{1,4}:){0,6}:(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4}"
    r"|::1"
    r"|::"
    r")"
    r"(?![0-9A-Fa-f:])"
)

# RFC 5737 IPv4 docs ranges (exempt — these are the obfuscator's placeholders).
_RFC5737_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
# RFC 3849 IPv6 docs range (exempt).
_RFC3849_NET = ipaddress.ip_network("2001:db8::/32")

# Flagged IPv4 networks with their reason labels.
_FLAGGED_V4 = (
    (ipaddress.ip_network("10.0.0.0/8"), LeakKind.RFC1918_IPV4, "RFC 1918 private"),
    (ipaddress.ip_network("172.16.0.0/12"), LeakKind.RFC1918_IPV4, "RFC 1918 private"),
    (ipaddress.ip_network("192.168.0.0/16"), LeakKind.RFC1918_IPV4, "RFC 1918 private"),
    (ipaddress.ip_network("100.64.0.0/10"), LeakKind.CGNAT_IPV4, "RFC 6598 CGNAT"),
    (ipaddress.ip_network("169.254.0.0/16"), LeakKind.LINKLOCAL_IPV4, "RFC 3927 link-local"),
    (ipaddress.ip_network("127.0.0.0/8"), LeakKind.LOOPBACK_IPV4, "RFC 1122 loopback"),
)
# Flagged IPv6 networks.
_FLAGGED_V6 = (
    (ipaddress.ip_network("fc00::/7"), LeakKind.ULA_IPV6, "RFC 4193 ULA"),
    (ipaddress.ip_network("fe80::/10"), LeakKind.LINKLOCAL_IPV6, "RFC 4291 link-local"),
    (ipaddress.ip_network("::1/128"), LeakKind.LOOPBACK_IPV6, "RFC 4291 loopback"),
)


# ----- FQDN ---------------------------------------------------------------

# Suffix alternation — order matters: multi-component suffixes first so
# ``.lan.local`` reports as ``.lan.local`` rather than just ``.local``.
# Prefix uses ``+?`` (non-greedy) so the regex engine tries the shortest
# label-prefix first, letting the alternation match the longest-possible
# suffix on the first attempt — otherwise a greedy prefix consumes
# ``box.lan.`` and the suffix is forced to the bare ``local``.
_INTERNAL_FQDN_RE = re.compile(
    r"\b(?:[A-Za-z0-9][A-Za-z0-9-]{0,62}\.)+?"
    r"(lan\.local|home\.arpa|intranet|internal|private|local|corp|lan)"
    r"\b",
    re.IGNORECASE,
)


# ----- MAC ---------------------------------------------------------------

_MAC_COLON_DASH_RE = re.compile(
    r"\b[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}\b"
)
_MAC_CISCO_RE = re.compile(
    r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b"
)


# ----- Placeholder / bareword / path -------------------------------------

_PLACEHOLDER_RE = re.compile(
    r"^(?:POOL|VS|NODE|MON|IRULE|PARTITION|UNK|DESC|PROFILE"
    r"|GTM_POOL|GTM_WIDEIP|GTM_SERVER|GTM_DC|GTM_REGION"
    r"|DG|SNAT|SNATPOOL|VADDR"
    r"|VLAN|ROUTE_DOMAIN|SELF_IP|TRUNK"
    r"|APM_POLICY|APM_PROFILE"
    r"|FIREWALL_POLICY|FIREWALL_RULE_LIST|FIREWALL_ADDRESS_LIST|FIREWALL_PORT_LIST"
    r"|IRULE_COMMENT|AD_GROUP_DN|FQDN|REMOTE_ROLE"
    r"|SNMP_COMMUNITY_SECRET|SNMP_COMMUNITY|SNMP_TRAP"
    r"|SYS_CONTACT|SYS_LOCATION|SYSLOG_SERVER|SSHD_BANNER"
    r"|CERT_KEY_CHAIN|CLIENT_POLICY|USERNAME|KRB_REALM"
    r"|LDAP_FILTER|SAML_ENTITY_ID|SAML_SSO_URI"
    r"|SAML_SLO_URI|SAML_SLO_RESPONSE_URI"
    r"|OAUTH_AUDIENCE|OAUTH_ISSUER|OAUTH_KEY_ID)"
    r"_\d{4,}$"
)

# TMSH bareword tokens that may appear unquoted in the body of any object.
# Goal: filter out the common-noise vocabulary so the identifier-shape
# heuristic doesn't drown the operator. Not exhaustive — TEMPER/CRUCIBLE
# expected to extend on demand.
_TMSH_KEYWORDS = frozenset({
    # Modules
    "ltm", "gtm", "net", "sys", "auth", "apm", "asm", "pem", "security",
    "wom", "ilx", "cli", "tmos",
    # Common attribute names
    "pool", "virtual", "node", "monitor", "rule", "members", "member",
    "address", "mask", "destination", "ip-protocol", "profiles", "profile",
    "snat", "snatpool", "source", "source-address", "vlans",
    "vlans-enabled", "vlans-disabled", "translate-address",
    "translate-port", "rules", "policies", "persist", "persistence",
    "default-persistence", "fallback-persistence", "context", "send",
    "recv", "interval", "timeout", "retry", "min-active-members",
    "load-balancing-mode", "description", "ratio", "priority-group",
    "session", "state", "user-down", "force-disable", "force-down",
    "partition", "any", "any6", "none", "all", "host", "manual",
    "yes", "no", "true", "false", "on", "off", "enabled", "disabled",
    "type", "kind", "name", "value", "default", "auto", "global",
    "request", "response", "string", "binary", "number",
    # Universal BIG-IP signal — exempt per spec.
    "Common",
    # Common profile / protocol short names (not customer-identifying).
    "http", "https", "tcp", "udp", "ssl", "clientssl", "serverssl",
    "fastL4", "fasthttp", "oneconnect", "stream", "sip", "rtsp", "ftp",
    "dns", "smtp", "ldap", "radius",
})

# A bareword candidate — letter-led, only word chars + hyphen.
_BAREWORD_CANDIDATE_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9_-]{2,62}\b")

# A path-shaped token. We extract from the input by allowing word chars,
# dots, hyphens, slashes, colon, percent (route domain), in the body.
_PATH_RE = re.compile(r"/[A-Za-z0-9_][A-Za-z0-9_./:%~-]*")

# Safe partition prefixes for paths.
# - ``/Common/...`` — universal BIG-IP signal.
# - ``/PARTITION_NNNN/...`` — customer partition substituted by pass-2.
# - ``/FQDN_NNNN/...`` — customer FQDN substituted by pass-2.0 (v1.2);
#   sub-segments are still scanned for identifier shape.
# - ``/UNK_NNNN/...`` — unknown-kind path placeholder.
_SAFE_PARTITION_RE = re.compile(
    r"^/(?:Common|PARTITION_\d{4,}|FQDN_\d{4,}|UNK_\d{4,})(?:/|$)"
)

# Built-in profile leaf names that survive substitution as universal
# TMOS signal. Mirror of `scanner._BUILTIN_PROFILES`; intentionally
# duplicated to keep leak_detector standalone (no scanner imports here).
_BUILTIN_PROFILE_LEAVES = frozenset({
    "http", "http2", "http-explicit", "http-transparent",
    "tcp", "tcp-lan-optimized", "tcp-wan-optimized",
    "tcp-mobile-optimized", "tcp-legacy",
    "f5-tcp-lan", "f5-tcp-wan", "f5-tcp-mobile", "f5-tcp-progressive",
    "udp", "udp_decrement_ttl", "udp_gtm_dns",
    "fastL4", "fasthttp",
    "clientssl", "clientssl-insecure-compatible",
    "clientssl-secure", "wom-default-clientssl",
    "serverssl", "serverssl-insecure-compatible",
    "apm-default-clientssl", "splitsession-default-clientssl",
    "crypto-server-default-clientssl",
    "crypto-client-default-serverssl",
    "oneconnect",
    "ftp", "dns", "sip", "rtsp", "stream", "ipother",
    "smtp", "smtps", "imap", "pop3", "ldap", "radius",
    "diameter", "mqtt", "websocket",
    "web-acceleration", "web-security", "wa-cache",
    "analytics", "request-log", "response-adapt",
    "request-adapt", "icap",
    "cookie", "source_addr", "dest_addr", "hash", "ssl",
    "universal", "msrdp", "sip_info",
})


# ----- Public API --------------------------------------------------------


def scan_leaks(sanitized: str) -> LeakReport:
    """Scan ``sanitized`` for content that looks like a customer-identifying
    leak survivor. Pure function; no I/O.
    """
    report = LeakReport()
    if not sanitized:
        return report
    line_starts = _compute_line_starts(sanitized)
    flagged_offsets: set[tuple[int, int]] = set()

    _scan_ipv4(sanitized, line_starts, report, flagged_offsets)
    _scan_ipv6(sanitized, line_starts, report, flagged_offsets)
    _scan_macs(sanitized, line_starts, report, flagged_offsets)
    _scan_internal_fqdns(sanitized, line_starts, report, flagged_offsets)
    _scan_paths(sanitized, line_starts, report, flagged_offsets)
    _scan_barewords(sanitized, line_starts, report, flagged_offsets)

    report.leaks.sort(key=lambda lk: (lk.byte_offset, lk.kind.value))
    return report


# ----- Internals ---------------------------------------------------------


def _compute_line_starts(s: str) -> list[int]:
    starts = [0]
    for idx, ch in enumerate(s):
        if ch == "\n":
            starts.append(idx + 1)
    return starts


def _line_col(offset: int, line_starts: list[int]) -> tuple[int, int]:
    line_idx = bisect.bisect_right(line_starts, offset) - 1
    return line_idx + 1, offset - line_starts[line_idx] + 1


def _add(
    report: LeakReport,
    flagged: set[tuple[int, int]],
    kind: LeakKind,
    token: str,
    offset: int,
    line_starts: list[int],
    reason: str,
) -> None:
    key = (offset, len(token))
    if key in flagged:
        return
    flagged.add(key)
    line, col = _line_col(offset, line_starts)
    report.leaks.append(
        Leak(kind=kind, token=token, byte_offset=offset,
             line=line, col=col, reason=reason)
    )


def _is_exempt_ipv4(addr: ipaddress.IPv4Address) -> bool:
    return any(addr in net for net in _RFC5737_NETS)


def _is_exempt_ipv6(addr: ipaddress.IPv6Address) -> bool:
    return addr in _RFC3849_NET


def _scan_ipv4(
    s: str, line_starts: list[int], report: LeakReport,
    flagged: set[tuple[int, int]],
) -> None:
    for m in _IPV4_RE.finditer(s):
        text = m.group(0)
        try:
            addr = ipaddress.IPv4Address(text)
        except ValueError:
            continue
        if _is_exempt_ipv4(addr):
            continue
        for net, kind, reason in _FLAGGED_V4:
            if addr in net:
                _add(report, flagged, kind, text, m.start(), line_starts, reason)
                break


def _scan_ipv6(
    s: str, line_starts: list[int], report: LeakReport,
    flagged: set[tuple[int, int]],
) -> None:
    for m in _IPV6_RE.finditer(s):
        text = m.group(0)
        # Skip degenerate single ``::`` matches with no surrounding hextets —
        # those are valid IPv6 (the unspecified address) but are also a
        # common false-positive shape inside config noise; require at least
        # one hex digit or the explicit ``::1`` form.
        if text == "::":
            continue
        try:
            addr = ipaddress.IPv6Address(text)
        except ValueError:
            continue
        if _is_exempt_ipv6(addr):
            continue
        # v4-mapped IPv6 (``::ffff:10.0.0.1``): classify by the embedded v4
        # so a leak doesn't slip through by virtue of being wrapped in
        # IPv6 syntax. Real BIG-IP configs use this form for dual-stack.
        mapped = addr.ipv4_mapped
        if mapped is not None:
            if _is_exempt_ipv4(mapped):
                continue
            for net, kind, reason in _FLAGGED_V4:
                if mapped in net:
                    _add(
                        report, flagged, kind, text, m.start(),
                        line_starts,
                        f"{reason} (v4-mapped in IPv6)",
                    )
                    break
            continue
        for net, kind, reason in _FLAGGED_V6:
            if addr in net:
                _add(report, flagged, kind, text, m.start(), line_starts, reason)
                break


def _scan_macs(
    s: str, line_starts: list[int], report: LeakReport,
    flagged: set[tuple[int, int]],
) -> None:
    for m in _MAC_COLON_DASH_RE.finditer(s):
        _add(report, flagged, LeakKind.MAC_ADDRESS, m.group(0),
             m.start(), line_starts, "MAC address")
    for m in _MAC_CISCO_RE.finditer(s):
        # Avoid double-flagging where a Cisco-style MAC overlaps an IPv4
        # match (impossible by character set, but defence in depth).
        _add(report, flagged, LeakKind.MAC_ADDRESS, m.group(0),
             m.start(), line_starts, "MAC address (Cisco)")


def _scan_internal_fqdns(
    s: str, line_starts: list[int], report: LeakReport,
    flagged: set[tuple[int, int]],
) -> None:
    for m in _INTERNAL_FQDN_RE.finditer(s):
        text = m.group(0)
        suffix = m.group(1).lower()
        _add(report, flagged, LeakKind.INTERNAL_FQDN, text,
             m.start(), line_starts, f".{suffix} suffix")


def _scan_paths(
    s: str, line_starts: list[int], report: LeakReport,
    flagged: set[tuple[int, int]],
) -> None:
    for m in _PATH_RE.finditer(s):
        text = m.group(0)
        # Path with no second slash — not really a path-shaped identifier
        # (could be a regex fragment, an option flag, etc.). Skip.
        if text.count("/") < 2:
            continue
        if not _SAFE_PARTITION_RE.match(text):
            _add(report, flagged, LeakKind.IDENTIFIER_PATH, text,
                 m.start(), line_starts, "non-safe partition")
            continue
        # Safe partition prefix — but sub-folder leaks past the prefix
        # still need catching. ``/Common/Customer_X/leaf`` has the safe
        # ``/Common/`` partition but ``Customer_X`` is a customer label
        # that should have been substituted. The leaf bareword catches
        # plain words but a path-shaped sub-folder needs its own check.
        parts = text.split("/")
        # parts == ["", "<partition>", "<seg>", ..., "<leaf>"]
        if len(parts) < 4:
            continue
        for seg in parts[2:]:
            if not seg:
                continue
            if _PLACEHOLDER_RE.match(seg):
                continue
            # Permit a trailing ``:port`` / ``%rd`` suffix on the leaf.
            seg_core = seg.split(":", 1)[0].split("%", 1)[0]
            if _PLACEHOLDER_RE.match(seg_core):
                continue
            if seg_core in _TMSH_KEYWORDS:
                continue
            if seg_core in _BUILTIN_PROFILE_LEAVES:
                continue
            # Plain TMSH attribute words (no digit/_/-) — skip.
            if not any(c.isdigit() or c in "_-" for c in seg_core):
                continue
            # Compute the offset of the offending segment inside the match.
            seg_off = m.start() + text.find(seg)
            _add(report, flagged, LeakKind.IDENTIFIER_PATH, seg,
                 seg_off, line_starts,
                 "non-placeholder sub-segment under safe partition")
            break


def _scan_barewords(
    s: str, line_starts: list[int], report: LeakReport,
    flagged: set[tuple[int, int]],
) -> None:
    for m in _BAREWORD_CANDIDATE_RE.finditer(s):
        word = m.group(0)
        if not _is_identifier_shaped(word):
            continue
        # Skip if the offset already overlaps a previously-flagged span
        # (e.g. an internal FQDN or MAC sub-component).
        if _offset_overlaps(flagged, m.start(), len(word)):
            continue
        _add(report, flagged, LeakKind.IDENTIFIER_BAREWORD, word,
             m.start(), line_starts, "identifier-shaped bareword")


def _is_identifier_shaped(word: str) -> bool:
    """Heuristic — return True if ``word`` looks like a customer identifier.

    Filters out pure keywords (``enabled``, ``description``) and demands
    *some* structural signal: an embedded digit, underscore, or hyphen.
    Placeholders (``POOL_0001``) and TMSH vocabulary are exempt.
    """
    if _PLACEHOLDER_RE.match(word):
        return False
    if word in _TMSH_KEYWORDS:
        return False
    if word.lower() in _TMSH_KEYWORDS:
        return False
    if word in _BUILTIN_PROFILE_LEAVES:
        return False
    has_digit = any(c.isdigit() for c in word)
    has_under = "_" in word
    has_hyphen = "-" in word
    # Pure alphabetic bareword (no structural signal) — too noisy; skip.
    if not (has_digit or has_under or has_hyphen):
        return False
    return True


def _offset_overlaps(
    flagged: set[tuple[int, int]], offset: int, length: int,
) -> bool:
    end = offset + length
    for f_off, f_len in flagged:
        if f_off <= offset < f_off + f_len:
            return True
        if offset <= f_off < end:
            return True
    return False
