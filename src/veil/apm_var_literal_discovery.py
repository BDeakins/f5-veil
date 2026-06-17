"""Pass 1.85m — APM variable-assign expression literal walker.

APM ``policy agent variable-assign`` blocks contain
``variables { ... }`` lists where each entry has the shape:

    {
        expression "return {LITERAL}"
        varname session.foo.bar
    }

The Tcl ``return {x}`` syntax returns the literal value ``x`` —
which is what gets assigned to the named session variable. Real-
world corpus has these literals being:

- AD domain names (``return {acme}``)
- Usernames (``return {admin}``)
- Plaintext passwords (``return {Pa$$w0rd}``) — F5's ``secure true``
  flag does NOT encrypt this in the source config, only affects
  runtime session rendering. This is a MAJOR pre-AI-handoff leak.

Walker behaviour
----------------
Scans globally for ``expression <QSTRING>`` pairs. For each QSTRING
matching the ``return {LITERAL}`` regex, interns LITERAL as
``Kind.APM_VAR_LITERAL``. Other expression shapes (complex Tcl
manipulating session variables) pass through verbatim — they don't
contain hard-coded customer literals.

The walker is field-name-gated (``expression`` field) but not
context-gated to ``apm policy agent variable-assign``; ``expression``
is rare enough outside this context that a regex shape gate on the
QSTRING content is sufficient.

Skip rules
----------
- Empty or whitespace-only literals skipped.
- TMSH literal keywords skipped (defensive — unlikely to appear here).
"""

from __future__ import annotations

import re

from .ledger import Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize


# ``return {LITERAL}`` — captures the value inside the braces. The
# inner pattern allows anything except a literal ``}`` (Tcl-quoted
# literals don't nest balanced braces in this context — F5's
# variable-assign UI generates flat values). Optional surrounding
# whitespace handled.
_RETURN_LITERAL_RE = re.compile(r"^\s*return\s+\{([^}]+)\}\s*$")

_SKIP_VALUES = frozenset({
    "none", "default", "any", "all", "auto",
    "enabled", "disabled",
})


def discover_apm_var_literals(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Walk the token stream, find every
    ``expression "return {LITERAL}"`` pair, and intern LITERAL as
    ``Kind.APM_VAR_LITERAL``. Must run before ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "apm_var_literal_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        tk = tokens[i]
        if (
            tk.kind == TokKind.WORD
            and tk.value == "expression"
            and i + 1 < n
            and tokens[i + 1].kind == TokKind.QSTRING
        ):
            _maybe_intern(tokens[i + 1], ledger)
            i += 2
            continue
        i += 1


def _maybe_intern(qstring_tok: Token, ledger: Ledger) -> None:
    """If the QSTRING value matches ``return {LITERAL}``, intern the
    LITERAL as ``Kind.APM_VAR_LITERAL``."""
    if len(qstring_tok.value) < 2:
        return
    content = qstring_tok.value[1:-1]
    m = _RETURN_LITERAL_RE.match(content)
    if not m:
        return
    literal = m.group(1).strip()
    if not literal or literal in _SKIP_VALUES:
        return
    if (Kind.APM_VAR_LITERAL, literal) in ledger.by_original:
        return
    # Compute the byte offset of the literal inside the QSTRING content.
    # qstring_tok.offset points to the opening ``"``; +1 skips it.
    # Locate the literal substring within the content.
    inner_off = qstring_tok.value.find(m.group(1))
    if inner_off < 0:
        return
    ref = Ref(
        byte_offset=qstring_tok.offset + inner_off,
        length=len(literal),
        line=qstring_tok.line,
    )
    ledger.intern(Kind.APM_VAR_LITERAL, literal, ref, partition=None)
