"""Pass 1.85h — Kerberos realm walker.

Scans the token stream for ``realm <VALUE>`` field pairs where
``VALUE`` matches the ALL-UPPERCASE dot-delimited Kerberos realm
shape (``BABYLON.LOCAL``, ``BOGUS.COM``, ``EXAMPLE.NET``).

Why a separate walker
---------------------
The FQDN walker (pass-2.0) catches realms whose top label is one of
the internal-suffix allowlist (``.local``, ``.corp``, ``.lan``,
``.internal``, etc.) regardless of case. But realms with public-TLD
top labels (``.COM``, ``.NET``, ``.ORG``) are skipped by FQDN by
design (the public-DNS false-positive risk is too high to redact
globally). For values appearing as the operand of a ``realm`` field
inside ``apm sso kerberos`` / ``apm aaa kerberos``, we KNOW the
value is a Kerberos realm and can safely redact regardless of TLD.

Field-name gating
-----------------
Only ``realm`` matches. The walker is global — it does not check
the enclosing block context because ``realm`` is rarely used outside
Kerberos contexts in TMSH, and the all-uppercase shape requirement
sharply gates false positives. (If a future TMSH dialect uses
``realm`` for some non-Kerberos setting with an upper-case value,
gate to specific parent contexts.)

Value-shape regex
-----------------
``^[A-Z][A-Z0-9.-]*\\.[A-Z][A-Z0-9]+$`` — must start with a letter,
contain at least one dot, top label is at least two characters of
uppercase letters / digits. Rejects ``any``, ``none``, ``default``
(lowercase). Rejects ``ACME`` (no dot).

Dedup with FQDN walker
----------------------
If the realm value is already in the ledger under another kind
(typically ``Kind.FQDN`` from pass-2.0 because the suffix is
internal-allowlisted and the FQDN walker is case-insensitive), the
KRB_REALM walker short-circuits to avoid minting a duplicate
placeholder for the same original string.
"""

from __future__ import annotations

import re

from .ledger import Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize


_REALM_RE = re.compile(r"^[A-Z][A-Z0-9.-]*\.[A-Z][A-Z0-9]+$")


def discover_krb_realms(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Walk the token stream, find every ``realm <UPPER.CASE>`` pair,
    and intern the value as ``Kind.KRB_REALM``. Must run before
    ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "krb_realm_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        tk = tokens[i]
        if (
            tk.kind == TokKind.WORD
            and tk.value == "realm"
            and i + 1 < n
            and tokens[i + 1].kind == TokKind.WORD
        ):
            _maybe_intern(tokens[i + 1], ledger)
            i += 2
            continue
        i += 1


def _maybe_intern(value_tok: Token, ledger: Ledger) -> None:
    v = value_tok.value
    if not _REALM_RE.match(v):
        return
    if _already_registered_elsewhere(ledger, v):
        return
    ref = Ref(
        byte_offset=value_tok.offset,
        length=value_tok.length,
        line=value_tok.line,
    )
    ledger.intern(Kind.KRB_REALM, v, ref, partition=None)


def _already_registered_elsewhere(ledger: Ledger, value: str) -> bool:
    """Skip interning if the value is already registered under
    another kind (typically ``Kind.FQDN`` for internal-suffix
    realms caught by pass-2.0)."""
    for kind in Kind:
        if kind == Kind.KRB_REALM:
            continue
        if (kind, value) in ledger.by_original:
            return True
    return False
