"""Pass 1.85n — Timestamp year-coarsening walker (v1.2.1 T3B).

Scans for ``creation-time`` and ``last-modified-time`` field values
inside any block body. Interns each unique value as
``Kind.TIMESTAMP`` with a year-coarsened rendered form
(``YYYY-01-01:00:00:00``) so the year is preserved (low-fidelity
operational metadata, useful for "is this config from 2018 or
2025?") but the month / day / time portion is generalized.

Why this exists
---------------
Real BIG-IP configs persist exact timestamps for every persistent
object — pool, profile, policy, even auto-generated factory
objects. The aggregate timestamp population reveals:

- Initial config age (oldest ``creation-time``)
- Active maintenance cadence (clusters of ``last-modified-time``)
- Specific incident dates (sharp spikes correlate to outages,
  migrations, audits)
- Operator working hours (HH:MM clusters)

Year-coarsening keeps just enough signal to convey "this is a 6-
year-old config that's been actively maintained" without leaking
specific dates that fingerprint operational events.

Format preservation
-------------------
TMSH timestamp format is ``YYYY-MM-DD:HH:MM:SS``. The rendered
output preserves the structure so any downstream parser still
accepts the value. Year preserved verbatim; everything else
canonicalized to start-of-year.
"""

from __future__ import annotations

import re

from .ledger import Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize


# Match TMSH timestamp: ``YYYY-MM-DD:HH:MM:SS``. Year 1900-2099,
# month 01-12, day 01-31, hours 00-23, minutes/seconds 00-59 —
# allow looser bounds for robustness (real configs may have weird
# values; the regex doesn't need to validate, just shape-match).
_TIMESTAMP_RE = re.compile(
    r"^(?P<year>\d{4})-\d{2}-\d{2}:\d{2}:\d{2}:\d{2}$"
)


_FIELD_NAMES = frozenset({
    "creation-time",
    "last-modified-time",
})


def discover_timestamps(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Walk the token stream, find every ``creation-time <ts>`` /
    ``last-modified-time <ts>`` pair, intern the timestamp as
    ``Kind.TIMESTAMP`` with a year-coarsened rendered form. Must run
    before ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "timestamp_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        tk = tokens[i]
        if (
            tk.kind == TokKind.WORD
            and tk.value in _FIELD_NAMES
            and i + 1 < n
        ):
            _maybe_intern_timestamp(tokens[i + 1], ledger)
            i += 2
            continue
        i += 1


def _maybe_intern_timestamp(value_tok: Token, ledger: Ledger) -> None:
    """If ``value_tok`` is a TMSH-shape timestamp, intern with year-
    coarsened rendered form."""
    if value_tok.kind != TokKind.WORD:
        return
    v = value_tok.value
    m = _TIMESTAMP_RE.match(v)
    if m is None:
        return
    if (Kind.TIMESTAMP, v) in ledger.by_original:
        return
    rendered = f"{m.group('year')}-01-01:00:00:00"
    # If the original IS already the coarsened form (i.e. no
    # information to leak), skip — interning would just create an
    # identity entry with no effect, and the substring-sub map's
    # short-literal filter might exclude it anyway.
    if rendered == v:
        return
    ref = Ref(
        byte_offset=value_tok.offset,
        length=value_tok.length,
        line=value_tok.line,
    )
    ledger.intern_timestamp(v, rendered, ref)
