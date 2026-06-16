"""Pass 1.85g — identity / hostname field walker.

Scans the token stream globally for an allowlist of field names that
always carry username, account-name, or hostname values:

- ``admin-name`` — the human / service-account name of an admin
- ``basic-auth-username`` — basic-auth credential username
- ``user`` — used in ``apm report favorite-report`` and similar to
  identify the favoriting user
- ``account-name`` — AD service-account name
- ``server-name`` — hostname / SNI-name for monitors and virtuals

Each matching ``<field> <value>`` pair interns ``<value>`` as
``Kind.USERNAME``. The substring-sub machinery in pass-2 then finds
the bare value inside any QSTRING / WORD content and replaces with
bare-placeholder ``USERNAME_NNNN``.

Skip rules
----------
- TMSH literal keywords (``none``, ``default``, ``any``, ``all``,
  ``auto``, ``enabled``, ``disabled``, ``true``, ``false``, ``yes``,
  ``no``) are skipped to avoid corrupting structural keywords that
  happen to follow a username-flavoured field name.
- Path-shaped values (``/Common/foo``) are skipped — those are
  handled by the path-shape walkers (``POOL``, ``PROFILE``, etc.).
- Empty values are skipped.

Risk note
---------
``user`` is the most generic field name in the allowlist. False
positives are possible if a future TMSH dialect uses ``user`` as a
non-username setting field. Mitigation is the SKIP_VALUES filter
plus the path-shape skip. If a future real-config surfaces a leak
caused by false-positive substitution, gate ``user`` to specific
parent contexts (e.g. only inside ``apm`` / ``auth`` blocks).
"""

from __future__ import annotations

from .ledger import Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize


_USERNAME_FIELDS = frozenset({
    "admin-name",
    "basic-auth-username",
    "user",
    "account-name",
    "server-name",
})

_SKIP_VALUES = frozenset({
    "none", "default", "any", "all", "auto",
    "enabled", "disabled",
    "true", "false", "yes", "no",
})


def discover_usernames(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Walk the token stream, find every ``<username-field> <value>``
    pair, and intern the value as ``Kind.USERNAME``. Must run before
    ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "username_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        tk = tokens[i]
        if (
            tk.kind == TokKind.WORD
            and tk.value in _USERNAME_FIELDS
            and i + 1 < n
        ):
            _intern_value(tokens[i + 1], ledger)
            i += 2
            continue
        i += 1


def _intern_value(value_tok: Token, ledger: Ledger) -> None:
    """Intern a username field value (QSTRING or WORD) as
    ``Kind.USERNAME`` with ``partition=None``. Empty values, TMSH
    literal keywords, and path-shaped values are skipped."""
    if value_tok.kind == TokKind.QSTRING:
        if len(value_tok.value) < 2:
            return
        content = value_tok.value[1:-1]
        if not content or content in _SKIP_VALUES:
            return
        if content.startswith("/"):
            return
        ref = Ref(
            byte_offset=value_tok.offset + 1,
            length=len(content),
            line=value_tok.line,
        )
        ledger.intern(Kind.USERNAME, content, ref, partition=None)
        return
    if value_tok.kind == TokKind.WORD:
        v = value_tok.value
        if not v or v in _SKIP_VALUES:
            return
        if v.startswith("/"):
            return
        ref = Ref(
            byte_offset=value_tok.offset,
            length=value_tok.length,
            line=value_tok.line,
        )
        ledger.intern(Kind.USERNAME, v, ref, partition=None)
