"""Pass 1.85j — SAML / OAuth identifier field walker.

Scans the token stream for SAML and OAuth identifier field names
and interns the value as a dedicated kind. The user has explicitly
called out that customer entity-IDs / URIs may be NON-FQDN-shaped
opaque strings, so the FQDN walker's incidental coverage is not
sufficient — dedicated kinds catch the WHOLE value.

Field-name → Kind map:
- ``entity-id``                       → ``Kind.SAML_ENTITY_ID``
- ``sso-uri``                         → ``Kind.SAML_SSO_URI``
- ``single-logout-uri``               → ``Kind.SAML_SLO_URI``
- ``single-logout-response-uri``      → ``Kind.SAML_SLO_RESPONSE_URI``
- ``audience``                        → ``Kind.OAUTH_AUDIENCE``
- ``issuer``                          → ``Kind.OAUTH_ISSUER``

Audience braced list
--------------------
The ``audience`` field uses a braced list shape in TMSH:

    audience { https://aud1.example.com https://aud2.example.com }

The walker detects this shape and interns each list element. The
single-bareword ``audience <value>`` form is also supported as a
fallback.

Order of operations
-------------------
This walker runs BEFORE the FQDN walker (pass-2.0). Both may detect
overlapping content (the FQDN walker finds inner FQDNs of the
URLs interned here). At substitution time, the substring-sub
machinery uses longest-match-first, so the full-URL SAML entry wins
for the field's own occurrence. The FQDN entry remains valid for
other occurrences of the same FQDN elsewhere in the config (e.g.
``sp-certificate /Common/<fqdn>``).

Skip rules
----------
- Empty values skipped.
- TMSH literal-keyword values (``none``, ``default``) skipped.
- Path-shaped values (``/Common/...``) skipped — handled by other
  walkers.
"""

from __future__ import annotations

from .ledger import Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize


_FIELD_TO_KIND = {
    "entity-id": Kind.SAML_ENTITY_ID,
    "sso-uri": Kind.SAML_SSO_URI,
    "single-logout-uri": Kind.SAML_SLO_URI,
    "single-logout-response-uri": Kind.SAML_SLO_RESPONSE_URI,
    "issuer": Kind.OAUTH_ISSUER,
    "key-id": Kind.OAUTH_KEY_ID,
}

# ``audience`` handled specially because of its braced-list shape.

_SKIP_VALUES = frozenset({
    "none", "default", "any", "all", "auto",
    "enabled", "disabled",
})


def discover_saml_oauth(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Walk the token stream globally, find each
    ``<saml-or-oauth-field> <value>`` (or
    ``audience { v1 v2 ... }``), and intern the value(s) as the
    field's dedicated kind. Must run before ``ledger.freeze()`` AND
    before the FQDN walker (so the dedup of inner FQDNs in URLs is
    consistent with longest-match-first substring sub)."""
    if ledger.frozen:
        raise RuntimeError(
            "saml_oauth_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        tk = tokens[i]
        if tk.kind == TokKind.WORD and i + 1 < n:
            # ``audience { v1 v2 ... }`` — braced list form.
            if tk.value == "audience":
                next_tok = tokens[i + 1]
                if next_tok.kind == TokKind.LBRACE:
                    i = _walk_audience_list(tokens, i + 2, ledger)
                    continue
                # Fallback: single bareword/QSTRING value.
                _intern_value(next_tok, ledger, Kind.OAUTH_AUDIENCE)
                i += 2
                continue
            # Simple ``<field> <value>`` shapes.
            kind = _FIELD_TO_KIND.get(tk.value)
            if kind is not None:
                _intern_value(tokens[i + 1], ledger, kind)
                i += 2
                continue
        i += 1


def _walk_audience_list(
    tokens: list[Token],
    start: int,
    ledger: Ledger,
) -> int:
    """Walk an ``audience { ... }`` body from ``start`` (token
    immediately after the opening ``{``). At depth 1 inside the
    block, every WORD or QSTRING value gets interned as
    ``Kind.OAUTH_AUDIENCE``. Returns the index just past the
    matching RBRACE."""
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
        if depth == 1 and tk.kind in (TokKind.WORD, TokKind.QSTRING):
            _intern_value(tk, ledger, Kind.OAUTH_AUDIENCE)
        i += 1
    return i


def _intern_value(value_tok: Token, ledger: Ledger, kind: Kind) -> None:
    """Intern a SAML/OAuth field value (QSTRING or WORD) as
    ``kind`` with ``partition=None``. TMSH literal keywords and
    path-shaped values skipped."""
    if value_tok.kind == TokKind.QSTRING:
        if len(value_tok.value) < 2:
            return
        content = value_tok.value[1:-1]
        if not content or content in _SKIP_VALUES:
            return
        if content.startswith("/"):
            return
        if (kind, content) in ledger.by_original:
            return
        ref = Ref(
            byte_offset=value_tok.offset + 1,
            length=len(content),
            line=value_tok.line,
        )
        ledger.intern(kind, content, ref, partition=None)
        return
    if value_tok.kind == TokKind.WORD:
        v = value_tok.value
        if not v or v in _SKIP_VALUES:
            return
        if v.startswith("/"):
            return
        if (kind, v) in ledger.by_original:
            return
        ref = Ref(
            byte_offset=value_tok.offset,
            length=value_tok.length,
            line=value_tok.line,
        )
        ledger.intern(kind, v, ref, partition=None)
