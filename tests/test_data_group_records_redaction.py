"""v1.2 Phase 2i — Data-group records walker."""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ---------- internal data-group FQDN records ----------


def test_internal_data_group_fqdn_records_redacted():
    src = (
        "ltm data-group internal /Common/APM_Citrix {\n"
        "    records {\n"
        "        storefront.acme.com { }\n"
        "        store.bigco.org {\n"
        "            data /Citrix/Store/PNAgent/config.xml\n"
        "        }\n"
        "    }\n"
        "    type string\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.DATA_GROUP_RECORD, "storefront.acme.com") in ledger.by_original
    assert (Kind.DATA_GROUP_RECORD, "store.bigco.org") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for v in ("storefront.acme.com", "store.bigco.org"):
        assert v not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- public-TLD records caught (vs FQDN walker skip-by-design) ----------


def test_public_tld_records_caught():
    """The whole point of finding 15's mitigation: records with
    public TLDs that the global FQDN walker (rightly) skips by
    design are caught here via context gating."""
    src = (
        "ltm data-group internal /Common/dg {\n"
        "    records {\n"
        "        www.google.com { }\n"
        "        myapps.delaware.gov { }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.DATA_GROUP_RECORD, "www.google.com") in ledger.by_original
    assert (Kind.DATA_GROUP_RECORD, "myapps.delaware.gov") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for v in ("www.google.com", "myapps.delaware.gov"):
        assert v not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- URL records ----------


def test_url_records_caught():
    src = (
        "ltm data-group internal /Common/dg {\n"
        "    records {\n"
        "        https://www.google.com { }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.DATA_GROUP_RECORD, "https://www.google.com") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "https://www.google.com" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- non-data-group ``records`` left alone ----------


def test_non_data_group_records_not_redacted():
    """``records`` is a generic keyword; in non-data-group contexts
    (e.g. some monitor blocks have a records sub-field) it should
    NOT be redacted by this walker."""
    src = (
        "ltm monitor dns /Common/m {\n"
        "    records {\n"
        "        some.host.com { }\n"
        "    }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    dgr_hits = [
        e for e in ledger.entries.values()
        if e.kind == Kind.DATA_GROUP_RECORD
    ]
    assert dgr_hits == []


# ---------- empty data-group records body ----------


def test_empty_records_body_no_op():
    src = (
        "ltm data-group internal /Common/dg {\n"
        "    records { }\n"
        "    type string\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    dgr_hits = [
        e for e in ledger.entries.values()
        if e.kind == Kind.DATA_GROUP_RECORD
    ]
    assert dgr_hits == []


# ---------- path-shaped record names skipped ----------


def test_path_shaped_record_names_skipped():
    src = (
        "ltm data-group internal /Common/dg {\n"
        "    records {\n"
        "        /Common/something { }\n"
        "    }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    dgr_hits = [
        e for e in ledger.entries.values()
        if e.kind == Kind.DATA_GROUP_RECORD
    ]
    assert dgr_hits == []


# ---------- external data-group also walked ----------


def test_external_data_group_walked():
    src = (
        "ltm data-group external /Common/ext {\n"
        "    records {\n"
        "        foo.bar.example.com { }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.DATA_GROUP_RECORD, "foo.bar.example.com") in ledger.by_original


# ---------- multiple data-groups ----------


def test_multiple_data_groups_distinct():
    src = (
        "ltm data-group internal /Common/a {\n"
        "    records { rec.a.example.com { } }\n"
        "}\n"
        "ltm data-group internal /Common/b {\n"
        "    records { rec.b.example.com { } }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    for v in ("rec.a.example.com", "rec.b.example.com"):
        assert (Kind.DATA_GROUP_RECORD, v) in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for v in ("rec.a.example.com", "rec.b.example.com"):
        assert v not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src
