"""Pass 1.85i.1 — AD ``query-attrname`` non-standard attribute walker
(v1.2.1 T3A).

Walks ``query-attrname { attr1 attr2 ... }`` braced bareword lists
inside LDAP-flavoured top-level blocks (``apm aaa
active-directory``, ``auth active-directory``, ``apm aaa ldap``,
etc.) and interns any attribute name NOT in the standard AD
schema allowlist as ``Kind.AD_ATTR``.

Why this exists
---------------
Real-world configs frequently extend ``query-attrname`` with
non-standard attrs that fingerprint the directory schema and
adjacent infrastructure:

- ``homeMDB`` — Exchange mailbox database pointer (reveals on-prem
  Exchange deployment).
- ``msDS-ResultantPSO`` — Fine-grained password policy attr
  (reveals AD functional level + password-policy posture).
- ``extensionAttribute1`` ... ``extensionAttribute15`` — generic
  customer-extended attrs whose presence + index reveals custom
  schema use.

Standard AD attrs (``sAMAccountName``, ``mail``, ``memberOf``, ...)
ship with every Windows AD install and don't reveal anything
customer-specific; allowlist passes them through verbatim.

Scope (v1.2.1 T3A)
------------------
- Context-gated to the same LDAP-flavoured header set as
  ``ldap_filter_discovery`` (shares the rationale — only inside
  LDAP blocks does ``query-attrname`` carry directory schema
  semantics).
- Only walks the braced list directly attached to a
  ``query-attrname`` field; nested braces inside the list are
  unexpected but tolerated (depth-bounded).
- Allowlist comparison is case-insensitive (LDAP attr names are
  case-insensitive per RFC 4512), but the interned ``original``
  preserves the source casing so byte-exact round-trip holds.
- Attrs <4 chars are skipped even if non-allowlist — substring-sub
  on very short literals over-fires globally (T7 class). The
  standard short attrs (``cn``, ``sn``, ``l``, ``st``, ``co``,
  ``mail``) are all in the allowlist, so the floor doesn't sacrifice
  real coverage.
"""

from __future__ import annotations

from .ledger import Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize


# LDAP-flavoured top-level block headers whose body may contain a
# ``query-attrname`` field. Two families:
#
# 1. AAA-config blocks (``apm aaa active-directory /Common/name { ... }``)
#    — server-connection configs.
# 2. Policy-agent blocks (``apm policy agent aaa-active-directory
#    /Common/name { ... }``) — the actual surface in real corpora,
#    where ``query-attrname`` lists the AD attributes the agent
#    fetches during policy evaluation.
#
# Shares the AAA-config allowlist with ``ldap_filter_discovery`` but
# adds the policy-agent variant since that's where ``query-attrname``
# concretely appears in observed configs.
_LDAP_HEADERS: tuple[tuple[int, tuple[str, ...]], ...] = (
    # AAA-config blocks
    (3, ("apm", "aaa", "ldap")),
    (3, ("apm", "aaa", "active-directory")),
    (2, ("auth", "ldap")),
    (2, ("auth", "active-directory")),
    (3, ("ltm", "monitor", "ldap")),
    # Policy-agent blocks — the real-corpus surface for query-attrname
    (4, ("apm", "policy", "agent", "aaa-active-directory")),
    (4, ("apm", "policy", "agent", "aaa-ldap")),
)


# Standard AD schema attributes that pass through verbatim. Case-
# insensitive lookup; entries here in canonical AD casing for
# readability. Includes the universally-present user/group/auth
# attrs plus common HR-sourced fields (employeeID, etc.) that are
# standard enough to allow.
_STANDARD_AD_ATTRS: frozenset[str] = frozenset(
    a.lower() for a in (
        # Core identity / naming
        "sAMAccountName", "userPrincipalName", "cn", "distinguishedName",
        "displayName", "givenName", "sn", "name",
        # Contact
        "mail", "telephoneNumber", "mobile", "facsimileTelephoneNumber",
        "streetAddress", "l", "st", "postalCode", "co", "c",
        # Org
        "company", "department", "title", "manager", "employeeID",
        "employeeNumber", "employeeType", "physicalDeliveryOfficeName",
        # Membership / group
        "memberOf", "member", "primaryGroupID",
        # Security identifiers
        "objectGUID", "objectSid", "objectClass", "objectCategory",
        # Lifecycle / state
        "whenCreated", "whenChanged", "accountExpires", "pwdLastSet",
        "lastLogon", "lastLogonTimestamp", "logonCount",
        "userAccountControl", "badPwdCount",
        # Description / misc
        "description", "info", "homeDirectory", "homeDrive",
        "profilePath", "scriptPath",
    )
)


# Minimum attr length for non-allowlist interning. Below this floor
# the substring-sub at pass-2 will over-fire on incidental matches
# anywhere in the source (the T7 over-fire class). All standard
# short attrs are in the allowlist, so this floor doesn't reduce
# real coverage.
_MIN_NON_ALLOWLIST_LEN = 4


def discover_ad_query_attrnames(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Walk the token stream, find every LDAP-flavoured top-level
    block, descend into its body looking for ``query-attrname {
    ... }`` braced lists, and intern each non-allowlist attr as
    ``Kind.AD_ATTR``. Must run before ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "ad_query_attrname_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        consumed = _try_match_ldap_header(tokens, i)
        if consumed > 0:
            j = i + consumed
            while j < n and tokens[j].kind == TokKind.WORD:
                j += 1
            if j < n and tokens[j].kind == TokKind.LBRACE:
                i = _walk_ldap_block_body(tokens, j + 1, ledger)
                continue
        i += 1


def _try_match_ldap_header(tokens: list[Token], i: int) -> int:
    """Return the number of WORD tokens consumed if ``tokens[i:]``
    matches an LDAP-flavoured block header, else 0."""
    for length, words in _LDAP_HEADERS:
        if i + length > len(tokens):
            continue
        ok = True
        for k, w in enumerate(words):
            t = tokens[i + k]
            if t.kind != TokKind.WORD or t.value != w:
                ok = False
                break
        if ok:
            return length
    return 0


def _walk_ldap_block_body(
    tokens: list[Token],
    start: int,
    ledger: Ledger,
) -> int:
    """Walk an LDAP-block body from ``start`` (token after the
    opening ``{``). Find every ``query-attrname { ... }`` braced
    list at any depth and intern the non-allowlist attrs inside.
    Returns the index just past the matching RBRACE that closes
    the outer block (depth 0)."""
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
        if (
            tk.kind == TokKind.WORD
            and tk.value == "query-attrname"
            and i + 1 < n
            and tokens[i + 1].kind == TokKind.LBRACE
        ):
            i = _walk_query_attrname_list(tokens, i + 2, ledger)
            continue
        i += 1
    return i


def _walk_query_attrname_list(
    tokens: list[Token],
    start: int,
    ledger: Ledger,
) -> int:
    """Walk a ``query-attrname { ... }`` list body from ``start``
    (token after the opening ``{``). Each WORD token inside is an
    attribute name candidate; non-allowlist names are interned as
    ``Kind.AD_ATTR``. Returns the index just past the matching
    RBRACE."""
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
            _maybe_intern_attr(tk, ledger)
        i += 1
    return i


def _maybe_intern_attr(tok: Token, ledger: Ledger) -> None:
    """Intern ``tok.value`` as ``Kind.AD_ATTR`` unless it is in the
    standard allowlist or below the substring-sub length floor."""
    name = tok.value
    if not name:
        return
    if name.lower() in _STANDARD_AD_ATTRS:
        return
    if len(name) < _MIN_NON_ALLOWLIST_LEN:
        return
    if (Kind.AD_ATTR, name) in ledger.by_original:
        return
    ref = Ref(
        byte_offset=tok.offset,
        length=tok.length,
        line=tok.line,
    )
    ledger.intern(Kind.AD_ATTR, name, ref, partition=None)
