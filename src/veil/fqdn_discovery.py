"""Pass 2.0 — internal FQDN discovery.

Walks the token stream after pass-1.9 (AD DN) but before ledger freeze.
For every WORD and QSTRING token, regex-scans the value for FQDN-shaped
substrings whose top label is one of a small set of internal / private
domain suffixes (``.local``, ``.corp``, ``.lan``, ``.internal``,
``.intranet``, ``.home.arpa``, ``.private``). Each unique match is
interned as ``Kind.FQDN``.

Why a fixed suffix list
-----------------------
Public-internet FQDNs like ``vendor.example.com`` are NOT
customer-identifying — they pass through verbatim. Internal-only
suffixes (the ones above) are what reveals the customer's AD domain
or homelab namespace, so the regex narrows to those. This mirrors
``leak_detector._INTERNAL_FQDN_RE`` (which flags survivors), but
inverts the role: pass-2.0 PREVENTS the leak; the leak detector is
the safety net for anything missed.

Real-world shapes
-----------------
- Standalone TMSH bareword: ``domain example.local``
- Compound URL bareword: ``application-uri https://idp01.example.local/saml/idp``
- Embedded in policy expression QSTRING: ``expression "... example.local ..."``

For all three, the existing v0.0.14 (QSTRING) and v1.1 (BAREWORD)
substring substitution machinery handles the actual mutation — pass-2.0
just needs to intern the FQDN so the substitution map has an entry to
match against. Word-boundary protection on both sides (already in the
substring walker) keeps ``example.local`` inside ``newexample.localfoo``
from false-matching.

Skip rules
----------
- Description QSTRINGs (pass-1.7 already covers them via DESC).
- DESC bareword form (single token redacted as DESC).
- The same suppression keeps an FQDN from interning twice and orphaning
  the second entry, just like ad_dn_discovery.
"""

from __future__ import annotations

import re

from .ledger import Kind, Ledger, Ref
from .tokenizer import TokKind, tokenize

# Internal / private domain suffixes. Order matters: multi-component
# suffixes first so a match against ``foo.lan.local`` captures the
# full ``lan.local`` rather than the trailing ``local``.
_INTERNAL_SUFFIXES = (
    r"lan\.local",
    r"home\.arpa",
    r"intranet",
    r"internal",
    r"private",
    r"local",
    r"corp",
    r"lan",
)

# An FQDN of the form ``label1.label2.<internal-suffix>``. Boundary
# checks use a character-class lookaround so the regex doesn't false-
# match the substring ``foo.local`` inside ``newfoo.localdomain`` — the
# left boundary requires the char immediately before to not be an
# identifier char; the right boundary likewise.
_FQDN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"(?P<fqdn>"
    r"[A-Za-z0-9][A-Za-z0-9-]{0,62}"
    r"(?:\.[A-Za-z0-9][A-Za-z0-9-]{0,62})*"
    r"\.(?:" + "|".join(_INTERNAL_SUFFIXES) + r")"
    r")"
    r"(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)


def discover_fqdns(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Pass 2.0 — intern every distinct internal-FQDN substring found
    inside any WORD or QSTRING token. Must run before ``ledger.freeze()``.
    """
    if ledger.frozen:
        raise RuntimeError(
            "fqdn_discovery must run before ledger.freeze()"
        )
    for tok in tokenize(src):
        if tok.kind not in (TokKind.WORD, TokKind.QSTRING):
            continue
        # Skip description QSTRINGs (already covered by DESC redaction).
        if tok.kind == TokKind.QSTRING and (Kind.DESC, tok.value) in ledger.by_original:
            continue
        # Skip bareword-form description tokens. The DESC entry for a
        # bareword description has the bareword itself as ``original``;
        # if we re-intern an FQDN substring of it under Kind.FQDN, both
        # entries fight for substitution and one orphans.
        if tok.kind == TokKind.WORD and (Kind.DESC, tok.value) in ledger.by_original:
            continue
        for match in _FQDN_RE.finditer(tok.value):
            fqdn = match.group("fqdn")
            ref = Ref(
                byte_offset=tok.offset + match.start("fqdn"),
                length=len(fqdn),
                line=tok.line,
            )
            ledger.intern(Kind.FQDN, fqdn, ref, partition=None)
