"""Pass 1.85k — Monitor ``recv`` field walker.

Scans the token stream globally for ``recv <VALUE>`` pairs where the
field-name token is EXACTLY ``recv`` (not ``recv-disable``,
``recv-row``, etc.). The value is the expected-response substring
that an LTM/GTM monitor matches against and frequently embeds
product names, HTML titles, or customer-specific UI strings.

Why global scan
---------------
The ``recv`` field exclusively appears inside ``ltm monitor`` and
``gtm monitor`` blocks in standard TMSH. Context gating would be
redundant — the exact-match field name is unique enough.

Skip rules
----------
- Empty values skipped.
- TMSH literal-keyword values (``none``, ``default``) skipped — a
  ``recv none`` line means "no expected response" and isn't
  identifying.
- The matching ``send`` field is NOT walked here (deferred — its
  values commonly embed already-redactable IPs and FQDNs that
  other walkers handle, with the remaining literal HTTP scaffolding
  not customer-identifying).
"""

from __future__ import annotations

from .ledger import Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize


_SKIP_VALUES = frozenset({
    "none", "default", "any", "all", "auto",
    "enabled", "disabled",
})


def discover_monitor_recv(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Walk the token stream, find every ``recv <value>`` pair, and
    intern the value as ``Kind.MONITOR_RECV``. Must run before
    ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "monitor_recv_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        tk = tokens[i]
        if (
            tk.kind == TokKind.WORD
            and tk.value == "recv"
            and i + 1 < n
        ):
            _intern_value(tokens[i + 1], ledger)
            i += 2
            continue
        i += 1


def _intern_value(value_tok: Token, ledger: Ledger) -> None:
    """Intern a monitor recv value (QSTRING or WORD) as
    ``Kind.MONITOR_RECV`` with ``partition=None``."""
    if value_tok.kind == TokKind.QSTRING:
        if len(value_tok.value) < 2:
            return
        content = value_tok.value[1:-1]
        if not content or content in _SKIP_VALUES:
            return
        if (Kind.MONITOR_RECV, content) in ledger.by_original:
            return
        ref = Ref(
            byte_offset=value_tok.offset + 1,
            length=len(content),
            line=value_tok.line,
        )
        ledger.intern(Kind.MONITOR_RECV, content, ref, partition=None)
        return
    if value_tok.kind == TokKind.WORD:
        v = value_tok.value
        if not v or v in _SKIP_VALUES:
            return
        if (Kind.MONITOR_RECV, v) in ledger.by_original:
            return
        ref = Ref(
            byte_offset=value_tok.offset,
            length=value_tok.length,
            line=value_tok.line,
        )
        ledger.intern(Kind.MONITOR_RECV, v, ref, partition=None)
