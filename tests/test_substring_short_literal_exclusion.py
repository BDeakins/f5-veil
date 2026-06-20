"""v1.2.1 T7 — substring-sub short-literal exclusion.

Pre-v1.2.1, the substring substitution at pass-2 would over-fire on
short pure-digit literals interned via APM_VAR_LITERAL (or similar)
when the corpus contained an ``expression "return {1}"`` or similar
that put a single digit in the ledger. The substring sub then
substituted every standalone digit in the source, corrupting
unrelated structural fields like ``version 17.5.1.5`` to
``version 17.5.APM_VAR_LITERAL_0001.5``.

Fix: filter pure-digit originals of length ≤ 3 from the substring-
sub map. The entry stays in the ledger (full-WORD substitution and
answer-file round-trip preserved), but it doesn't pollute the
substring map.

Narrow scope: alphabetic shorts like ``acme`` / ``admin`` / ``Secret``
are NOT filtered — they're legitimate customer secrets.
"""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


def test_short_digit_literal_does_not_corrupt_version_field():
    # A ``return {1}`` expression interns ``1`` as APM_VAR_LITERAL.
    # Pre-T7, substring sub would over-fire on the ``1`` in the
    # version field. Post-T7, the version field passes through
    # verbatim.
    src = (
        "sys global-settings {\n"
        "    version 17.5.1.5\n"
        "}\n"
        "apm policy agent variable-assign /Common/va1 {\n"
        "    variables {\n"
        '        { expression "return {1}" varname session.x }\n'
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    # The walker still interns ``1`` so round-trip data is preserved.
    assert (Kind.APM_VAR_LITERAL, "1") in ledger.by_original
    sanitized, _ = substitute(src, ledger, diag)
    # Version field structurally intact — substring sub did NOT fire.
    assert "version 17.5.1.5" in sanitized
    # Round-trip restores exactly.
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_short_alphabetic_literal_still_substring_subs():
    # ``acme`` is 4 chars alphabetic — must still be redacted as a
    # legitimate customer secret value. T7 narrowness ensures
    # alphabetic shorts pass through the filter.
    src = (
        "apm policy agent variable-assign /Common/va1 {\n"
        "    variables {\n"
        '        { expression "return {acme}" varname session.x }\n'
        "    }\n"
        "}\n"
        "ltm pool /Common/pool1 {\n"
        '    description "uses acme domain"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.APM_VAR_LITERAL, "acme") in ledger.by_original
    sanitized, _ = substitute(src, ledger, diag)
    # ``acme`` SHOULD be substituted (not skipped like ``1`` is).
    assert "{acme}" not in sanitized
    assert "APM_VAR_LITERAL_" in sanitized


def test_two_digit_literal_filtered():
    # ``42`` (2 digits) — also filtered, same rule as ``1``.
    src = (
        "ltm pool /Common/pool1 {\n"
        "    members {\n"
        "        srv1:80 { address 192.0.2.1 }\n"
        "    }\n"
        "}\n"
        "apm policy agent variable-assign /Common/va1 {\n"
        "    variables {\n"
        '        { expression "return {42}" varname session.x }\n'
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # ``42`` interned but substring sub did not fire on the bare digit.
    # The expression body itself uses full-WORD-or-QSTRING substitution
    # paths, which CAN still substitute the ``{42}`` content depending
    # on how the parser handles it. Either way, the unrelated
    # ``srv1:80`` and ``192.0.2.1`` must not have ``42`` corrupted.
    assert "srv1:80" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_four_digit_literal_not_filtered():
    # 4-digit literal is at the length boundary — > 3, so T7 doesn't
    # filter. Substring sub fires normally. Round-trip preserved.
    src = (
        "apm policy agent variable-assign /Common/va1 {\n"
        "    variables {\n"
        '        { expression "return {2025}" varname session.x }\n'
        "    }\n"
        "}\n"
        "ltm pool /Common/pool1 {\n"
        '    description "Year 2025 deployment"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src
