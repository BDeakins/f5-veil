"""Pass 1.9 — LDAP / AD distinguished-name discovery inside QSTRINGs.

Walks the token stream after pass-1.8 (iRule ``#`` comments) but before
ledger freeze. For every QSTRING token, regex-scans the content for
distinguished-name substrings of the form
``(CN|cn|...)=value,(CN|OU|DC|O|...)=value,...`` (RFC 4514 LDAP DN
shape) and interns each unique match as ``Kind.AD_GROUP_DN``.

Scope (locked v0.0.13)
----------------------
- ANY QSTRING anywhere in the source. Two main surfaces in real BIG-IP
  configs: ``auth remote-role role-info <name> { attribute "memberOf=CN=...,
  DC=..." }`` (verbatim DN attribute), and APM access-policy
  ``expression "...string tolower \\"CN=Group,DC=corp,DC=example,DC=com\\"..."``
  (DN embedded in a Tcl-shaped policy expression QSTRING). Other less
  common surfaces (SAML cert subject DNs in
  ``apm aaa saml-idp-connector``) are caught by the same regex.
- The interned ``original`` is the bare DN — no quotes, no preceding
  ``memberOf=`` / ``memberOF=`` attribute label, no surrounding policy
  expression syntax. This keeps the substitution placement crisp and
  the answer file legible.
- Round-trip is byte-exact: pass-2 substring-substitutes ``original``
  with ``AD_GROUP_DN_NNNN`` in place; the reverse pass restores by the
  reverse substring map.

Regex notes
-----------
- RDN value characters: anything except ``,``, ``"``, ``\\``, ``+``,
  ``;`` (the RFC 4514 separators), so we can lex stop reliably.
- Attribute names match the common LDAP set
  ``CN|OU|DC|O|L|C|ST|UID|emailAddress`` case-insensitively.
- Whitespace around the DN's interior commas is permitted but rare in
  BIG-IP configs.
- At least one ``CN=`` plus at least one ``DC=`` is required to qualify
  — single-RDN strings (``CN=foo``) aren't customer-identifying enough
  to justify the false-positive risk against random ``key=value`` text.

Tcl-escape handling
-------------------
APM expression QSTRINGs contain ``\\"`` to wrap inner Tcl strings:
``... string tolower \\"CN=Group,DC=corp\\" ...``. The DN regex matches
the DN itself; the surrounding ``\\"`` chars are part of the larger
QSTRING and pass through. Substring substitution in pass-2 will preserve
those escape sequences because they're not part of the matched
``original``.
"""

from __future__ import annotations

import re

from .ledger import Kind, Ledger, Ref
from .tokenizer import TokKind, tokenize

# RDN value: greedy run of chars that aren't the RFC 4514 separator
# punctuation or QSTRING-incompatible chars. Greedy is important: a
# non-greedy ``+?`` lets the regex stop after the first
# ``(?:,RDN)+`` iteration with a 1-char value, truncating the DN
# mid-RDN. The value also excludes ``=`` because the next RDN starts
# with an attribute key followed by ``=``, and we never want a value
# to eat into a following RDN.
_RDN_VAL = r"[^,\"\\+;=]+"
_RDN_KEY = r"(?:CN|OU|DC|O|L|C|ST|UID|emailAddress)"

# Full DN: one leading RDN + at least one following RDN, with the
# overall shape requiring at least one ``CN=`` and at least one ``DC=``.
# We enforce the qualifier via a follow-up check rather than baking it
# into the regex (keeps the regex tractable + greedy-safe).
_DN_RE = re.compile(
    rf"(?i)"  # case-insensitive on attribute names
    rf"(?<![A-Za-z0-9_])"  # left boundary: not an identifier-char
    rf"{_RDN_KEY}\s*=\s*{_RDN_VAL}"
    rf"(?:\s*,\s*{_RDN_KEY}\s*=\s*{_RDN_VAL})+"
)


def discover_ad_dns(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Pass 1.9 — intern every distinct AD / LDAP DN substring found
    inside any QSTRING. Must run before ``ledger.freeze()``.

    ``diagnostics`` is accepted for signature symmetry; no current failure
    mode warrants a diagnostic field (DNs missed by the regex would
    surface via the post-substitution leak detector if it grows
    DN-shape awareness, otherwise via the existing identifier-shaped
    leaks)."""
    if ledger.frozen:
        raise RuntimeError(
            "ad_dn_discovery must run before ledger.freeze()"
        )
    for tok in tokenize(src):
        if tok.kind != TokKind.QSTRING:
            continue
        # Skip QSTRINGs that pass-1.7 already interned as descriptions —
        # pass-2 will substitute the entire description to ``"DESC_NNNN"``,
        # so any DN inside it is covered by the DESC round-trip. Interning
        # it separately as AD_GROUP_DN would produce a zero-reference
        # orphan diagnostic.
        if (Kind.DESC, tok.value) in ledger.by_original:
            continue
        # Strip the wrapping quotes; the regex would also match inside
        # them but starting from the inner content keeps offsets clean.
        if len(tok.value) < 2:
            continue
        content = tok.value[1:-1]
        content_start = tok.offset + 1
        for match in _DN_RE.finditer(content):
            dn = match.group(0)
            if not _qualifies_as_ad_dn(dn):
                continue
            ref = Ref(
                byte_offset=content_start + match.start(),
                length=len(dn),
                line=tok.line,
            )
            ledger.intern(Kind.AD_GROUP_DN, dn, ref, partition=None)


def _qualifies_as_ad_dn(dn: str) -> bool:
    """Require at least one ``CN=`` and at least one ``DC=`` RDN to
    qualify — this filters out random ``key=value,key=value`` strings
    (HTTP header parameters, SQL fragments, etc.) that share the
    syntactic shape but aren't AD DNs."""
    upper = dn.upper()
    return "CN=" in upper and "DC=" in upper
