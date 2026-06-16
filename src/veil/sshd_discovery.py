"""Pass 1.85d — ``sys sshd`` banner walker.

Pass-1's main loop hands ``sys sshd`` off to
``_record_unknown_top_level`` because it isn't on the registered
top-level-kinds list, and the body is then brace-skipped. That leaves
the SSH login banner text leaking verbatim — frequently a
multi-line free-text value that embeds company name, legal
jurisdiction, operations contact info, or other
customer-identifying content.

This pass walks the token stream a second time, finds
``sys sshd { ... }`` shapes, and interns the value of each of
``banner-text`` / ``pre-login-banner`` / ``post-login-banner`` as
``Kind.SSHD_BANNER``. Values are typically multi-line QSTRINGs; the
tokenizer captures the full multi-line span as a single QSTRING
token (verified). The substring-sub machinery in pass-2 finds the
bare content (no surrounding quotes) inside any QSTRING and
substitutes with ``SSHD_BANNER_NNNN``.

Field-name list rationale
-------------------------
- ``banner-text`` — the F5 v17 TMSH spelling (observed in real
  corpus). Single field for the login banner displayed before
  authentication.
- ``pre-login-banner`` / ``post-login-banner`` — alternate spellings
  used by older / other TMSH variants. Documented here for forward
  compatibility; if neither appears the field-walker is a no-op.

Other sub-fields of ``sys sshd`` (``include`` for ssh-config text,
``inactivity-timeout``, ``port``) are not walked — none carry
customer-identifying content. The ``include`` field commonly holds
multi-line ssh-config text (cipher / MAC / kex algorithm lists);
that text is generic SSH protocol config, not customer data.

Scope (v1.2)
------------
- Only QSTRING-form values are interned. Bareword-form would be a
  single-token banner, which is unusual but supported (same code
  path as ``sys-contact`` bareword).
- Multiple ``sys sshd`` blocks are handled (each walked
  independently). Real configs have one.
- Empty banner values (zero-length QSTRING content) are skipped.
"""

from __future__ import annotations

from .ledger import Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize


_BANNER_FIELDS = frozenset({
    "banner-text",
    "pre-login-banner",
    "post-login-banner",
})


def discover_sshd_banners(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Walk the token stream, find every ``sys sshd { ... }`` shape,
    and intern each banner-field QSTRING / WORD value as
    ``Kind.SSHD_BANNER``. Must run before ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "sshd_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        if not _starts_sys_sshd(tokens, i):
            i += 1
            continue
        i = _walk_sys_sshd_body(tokens, i + 3, ledger)
    return


def _starts_sys_sshd(tokens: list[Token], i: int) -> bool:
    if i + 2 >= len(tokens):
        return False
    return (
        tokens[i].kind == TokKind.WORD
        and tokens[i].value == "sys"
        and tokens[i + 1].kind == TokKind.WORD
        and tokens[i + 1].value == "sshd"
        and tokens[i + 2].kind == TokKind.LBRACE
    )


def _walk_sys_sshd_body(
    tokens: list[Token],
    start: int,
    ledger: Ledger,
) -> int:
    """Walk a ``sys sshd { ... }`` body from ``start`` (token
    immediately after the opening ``{``). At depth 1, intern the
    value of any banner-flavoured field. Returns the index just past
    the matching RBRACE."""
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
            depth == 1
            and tk.kind == TokKind.WORD
            and tk.value in _BANNER_FIELDS
            and i + 1 < n
        ):
            _intern_banner_value(tokens[i + 1], ledger)
            i += 2
            continue
        i += 1
    return i


def _intern_banner_value(value_tok: Token, ledger: Ledger) -> None:
    """Intern a banner field value (QSTRING or WORD) as
    ``Kind.SSHD_BANNER`` with ``partition=None``. QSTRING contents
    are stored without the surrounding double quotes so the
    substring-sub machinery finds the bare text inside any token.
    Empty values are skipped."""
    if value_tok.kind == TokKind.QSTRING:
        if len(value_tok.value) < 2:
            return
        content = value_tok.value[1:-1]
        if not content:
            return
        ref = Ref(
            byte_offset=value_tok.offset + 1,
            length=len(content),
            line=value_tok.line,
        )
        ledger.intern(Kind.SSHD_BANNER, content, ref, partition=None)
        return
    if value_tok.kind == TokKind.WORD:
        if not value_tok.value:
            return
        ref = Ref(
            byte_offset=value_tok.offset,
            length=value_tok.length,
            line=value_tok.line,
        )
        ledger.intern(
            Kind.SSHD_BANNER, value_tok.value, ref, partition=None,
        )
