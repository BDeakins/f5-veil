"""v1.2 Phase 3a-bis — IP literal walker exclusion for version fields.

Finding 19: pass-1.5 was treating ``version 17.5.1.5`` as a 4-octet
IPv4 address and substituting the version string with a docs-range IP.
The fix is a field-name allowlist that skips IP-shaped values
immediately following ``version`` / ``tmsh-version`` /
``software-version`` etc.
"""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


def test_version_value_not_treated_as_ip():
    src = (
        "sys global-settings {\n"
        "    version 17.5.1.5\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    # The version string should NOT have been interned as an IP.
    ipaddr_hits = [
        e for e in ledger.entries.values()
        if e.kind == Kind.IPADDR and e.original == "17.5.1.5"
    ]
    assert ipaddr_hits == []


def test_tmsh_version_value_not_treated_as_ip():
    src = (
        "sys global-settings {\n"
        "    tmsh-version 17.5.1.5\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    ipaddr_hits = [
        e for e in ledger.entries.values()
        if e.kind == Kind.IPADDR and e.original == "17.5.1.5"
    ]
    assert ipaddr_hits == []


def test_software_version_value_not_treated_as_ip():
    src = "ltm something /Common/x {\n    software-version 1.2.3.4\n}\n"
    ledger, _diag = scan(src)
    ipaddr_hits = [
        e for e in ledger.entries.values()
        if e.kind == Kind.IPADDR and e.original == "1.2.3.4"
    ]
    assert ipaddr_hits == []


def test_bios_version_value_not_treated_as_ip():
    src = "sys hardware {\n    bios-version 1.2.3.4\n}\n"
    ledger, _diag = scan(src)
    ipaddr_hits = [
        e for e in ledger.entries.values()
        if e.kind == Kind.IPADDR and e.original == "1.2.3.4"
    ]
    assert ipaddr_hits == []


def test_version_pass_through_in_substitute():
    """Round-trip: version string must remain byte-identical in the
    sanitized output."""
    src = (
        "sys global-settings {\n"
        "    version 17.5.1.5\n"
        "    description \"sys settings\"\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _diag = substitute(src, ledger, diag)
    assert "17.5.1.5" in sanitized  # unchanged
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_legitimate_ip_after_non_version_field_still_caught():
    """Sanity check — the field-name exclusion is conservative and
    only fires for the version allowlist. An IP after ``destination``
    (a common LTM field) still gets caught."""
    src = (
        "ltm virtual /Common/v {\n"
        "    destination 192.0.2.99\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    ipaddr_hits = [
        e for e in ledger.entries.values()
        if e.kind == Kind.IPADDR and e.original == "192.0.2.99"
    ]
    assert len(ipaddr_hits) == 1


def test_field_adjacency_broken_by_lbrace():
    """The version exclusion only fires when ``version`` is the
    immediately-preceding WORD token. An LBRACE between them breaks
    the adjacency."""
    src = (
        "sys global-settings {\n"
        "    not-version-anymore { 10.0.0.42 }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    # 10.0.0.42 SHOULD be interned because no version field directly
    # precedes it (LBRACE intervenes).
    ipaddr_hits = [
        e for e in ledger.entries.values()
        if e.kind == Kind.IPADDR and e.original == "10.0.0.42"
    ]
    assert len(ipaddr_hits) == 1
