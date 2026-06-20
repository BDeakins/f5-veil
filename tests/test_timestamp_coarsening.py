"""v1.2.1 T3B — Timestamp year-coarsening.

Trigger: real configs persist exact ``creation-time`` /
``last-modified-time`` per object — leaking config age, maintenance
cadence, specific incident dates. T3B preserves the year (low-
fidelity operational signal) and canonicalizes month / day / time
to start-of-year.
"""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


def test_creation_time_year_coarsened():
    src = (
        "ltm pool /Common/p1 {\n"
        "    creation-time 2020-04-08:08:06:00\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "2020-04-08:08:06:00" not in sanitized
    assert "2020-01-01:00:00:00" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_last_modified_time_year_coarsened():
    src = (
        "ltm pool /Common/p1 {\n"
        "    last-modified-time 2026-03-29:00:33:37\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "2026-03-29:00:33:37" not in sanitized
    assert "2026-01-01:00:00:00" in sanitized


def test_two_distinct_dates_same_year_disambiguated():
    src = (
        "ltm pool /Common/p1 {\n"
        "    creation-time 2020-04-08:08:06:00\n"
        "    last-modified-time 2020-11-15:14:30:45\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # Both coarsen to 2020-01-01:00:00:??; the second gets a
    # seconds-slot disambiguation so the round-trip stays unique.
    assert "2020-04-08:08:06:00" not in sanitized
    assert "2020-11-15:14:30:45" not in sanitized
    assert "2020-01-01:00:00:00" in sanitized
    assert "2020-01-01:00:00:01" in sanitized
    # Round-trip preserves both distinct originals.
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_duplicate_timestamp_interns_once():
    src = (
        "ltm pool /Common/p1 { creation-time 2020-04-08:08:06:00 }\n"
        "ltm pool /Common/p2 { creation-time 2020-04-08:08:06:00 }\n"
    )
    ledger, diag = scan(src)
    assert (Kind.TIMESTAMP, "2020-04-08:08:06:00") in ledger.by_original
    assert ledger.counters.get(Kind.TIMESTAMP, 0) == 1
    sanitized, _ = substitute(src, ledger, diag)
    assert sanitized.count("2020-01-01:00:00:00") == 2


def test_non_timestamp_value_passthrough():
    # Field name matches but value isn't TMSH-shape timestamp — skip.
    src = (
        "ltm pool /Common/p1 {\n"
        "    creation-time none\n"
        "}\n"
    )
    ledger, _ = scan(src)
    assert (Kind.TIMESTAMP, "none") not in ledger.by_original


def test_timestamp_format_preserved():
    # Output must still be a valid TMSH timestamp shape.
    src = (
        "ltm pool /Common/p1 {\n"
        "    creation-time 1999-12-31:23:59:59\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "1999-01-01:00:00:00" in sanitized
