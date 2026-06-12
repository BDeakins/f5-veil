"""Pass 1.5 — bare IP literal discovery.

Walks the token stream after pass-1 scanner but before ledger freeze,
discovering every WORD token whose value is (or contains a prefix of) an
IPv4 or IPv6 address literal. Each unique IP is interned via
:meth:`veil.ledger.Ledger.intern_ipaddr`. Source ``/24`` / ``/64``
structure is preserved by the ledger's allocator.

Token forms in scope (mirroring path-piece machinery in
:mod:`veil.substitute`):

- Bare IPv4 / IPv6: ``10.0.0.42`` / ``fc00::1``
- IPv4 with port: ``10.0.0.42:80``
- IPv4 with route domain: ``10.0.0.42%rd0`` / ``10.0.0.42%rd0:80``
- IPv4 CIDR: ``10.0.0.0/24``
- IPv6 with port (dot form): ``fc00::1.80`` (TMSH dot-port)
- IPv6 with route domain: ``fc00::1%rd0``
- IPv6 bracketed with port: ``[fc00::1]:80``

Wildcards skipped (NOT customer-identifying):
- ``0.0.0.0``, ``::``, ``::0``
- TMSH literal keywords ``any``, ``any6`` (not IP-shaped — skipped by
  regex, but explicit for clarity)

Netmasks skipped (NOT customer-identifying):
- Any IPv4 whose bit pattern is contiguous-high-bits 1...10...0
  (``255.255.255.0``, ``255.255.0.0``, ``255.0.0.0``, etc.)

Out of scope (per ANVIL spec):
- IPs inside QSTRING content — surfaced via ``qstring_contains_identifier``
- IPs inside ``description`` values — surfaced via ``unredacted_description``
- IPs inside iRule Tcl strings / comments — deferred to Tcl-lexer PR
"""

from __future__ import annotations

import ipaddress
import re

from .diagnostics import Diagnostics
from .ledger import Kind, Ledger, Ref
from .tokenizer import TokKind, tokenize

# Prefix patterns to peel an IP literal off the head of a WORD token.
# Each must include a terminating boundary (end of string OR a
# non-word-char suffix like ``:``, ``%``, ``.`` followed by digits).
# We extract the IP-shape *prefix*; the suffix is preserved by pass-2's
# longest-prefix-match logic.

# Bracketed IPv6 with port: ``[fc00::1]:80``. We strip the brackets and
# return the inner IPv6 portion.
_IPV6_BRACKETED_RE = re.compile(
    r"^\[(?P<addr>[0-9A-Fa-f:]+)\](?::\d+)?$"
)
# IPv6 with route domain or dot-port: ``fc00::1%rd0`` / ``fc00::1.80``.
_IPV6_WITH_SUFFIX_RE = re.compile(
    r"^(?P<addr>[0-9A-Fa-f:]+)(?:%[A-Za-z0-9_]+)?(?:\.\d+)?$"
)
# IPv4 with optional suffix: ``10.0.0.42[:80][%rd0]`` or CIDR ``/24``.
_IPV4_WITH_SUFFIX_RE = re.compile(
    r"^(?P<addr>\d{1,3}(?:\.\d{1,3}){3})"
    r"(?:/\d{1,2})?(?:%[A-Za-z0-9_]+)?(?::\d+)?$"
)

# Exclusion: TMSH wildcard keywords. These are bareword tokens, not IPs,
# but explicit to short-circuit before regex matching.
_WILDCARD_WORDS = frozenset({"any", "any6", "all"})


def discover_ip_literals(
    src: str,
    ledger: Ledger,
    diagnostics: Diagnostics,
) -> None:
    """Pass 1.5 — walk ``src`` and intern every bare IP literal into the
    ledger. Must be called between pass-1 ``scan()`` and ledger freeze.

    Side effects:
    - New ``Kind.IPADDR`` entries in ``ledger``.
    - ``diagnostics.ipv4_subnet_collapsed`` populated if more than 3
      source ``/24``s appear (RFC 5737 pool is 3 ``/24``s).
    """
    if ledger.frozen:
        raise RuntimeError(
            "ip_discovery must run before ledger.freeze()"
        )
    for tok in tokenize(src):
        if tok.kind != TokKind.WORD:
            continue
        if tok.value in _WILDCARD_WORDS:
            continue
        addr_str = _extract_ip_prefix(tok.value)
        if addr_str is None:
            continue
        try:
            addr = ipaddress.ip_address(addr_str)
        except ValueError:
            continue
        if _is_wildcard(addr):
            continue
        if isinstance(addr, ipaddress.IPv4Address) and _is_netmask(addr):
            continue
        ref = Ref(
            byte_offset=tok.offset,
            length=len(addr_str),
            line=tok.line,
        )
        ledger.intern_ipaddr(addr_str, ref)
    # Surface any subnet collapse to diagnostics so callers can decide
    # whether to fail closed or accept reduced structural fidelity.
    for src_net in sorted(ledger.ipv4_collapsed_source_nets, key=str):
        diagnostics.ipv4_subnet_collapsed.append(str(src_net))


def _extract_ip_prefix(word: str) -> str | None:
    """Return the IP-shape prefix of ``word`` (just the address, no port,
    no route domain, no CIDR mask), or ``None`` if ``word`` does not lead
    with an IP literal."""
    if not word:
        return None
    if word[0] == "[":
        m = _IPV6_BRACKETED_RE.match(word)
        if m:
            return m.group("addr")
        return None
    if "." in word and ":" not in word.split(".")[0]:
        # IPv4-shaped lead: first dot-separated component is digits-only.
        m = _IPV4_WITH_SUFFIX_RE.match(word)
        if m:
            return m.group("addr")
        return None
    if ":" in word:
        # IPv6-shaped lead.
        m = _IPV6_WITH_SUFFIX_RE.match(word)
        if m:
            addr = m.group("addr")
            # Reject degenerate ``::`` (handled by wildcard check too).
            if addr in ("", "::"):
                return addr if addr == "::" else None
            return addr
    return None


def _is_wildcard(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # ``0.0.0.0`` and ``::`` only. ``::1`` is loopback — IS a leak; let
    # it be interned and rendered into a docs-range address.
    return int(addr) == 0


def _is_netmask(addr: ipaddress.IPv4Address) -> bool:
    """True if ``addr`` bit pattern is contiguous high bits: ``1...10...0``.

    Catches ``255.255.255.0``, ``255.255.0.0``, ``255.0.0.0``,
    ``255.255.255.255``, ``128.0.0.0``, etc. Also returns True for
    ``0.0.0.0`` (treated as wildcard upstream, but defensively safe)."""
    val = int(addr)
    if val == 0:
        return True
    inverted = (~val) & 0xFFFFFFFF
    # inverted is 0...01...1 form; +1 turns it into 1<<k. Power-of-two
    # check is ``x & (x-1) == 0`` for x>0; here we need the post-+1 form.
    return (inverted & (inverted + 1)) == 0
