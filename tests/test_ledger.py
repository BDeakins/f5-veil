from veil.ledger import COMMON_PARTITION, Kind, Ledger, Ref


def _ref(line: int = 1, offset: int = 0, length: int = 1) -> Ref:
    return Ref(byte_offset=offset, length=length, line=line)


def test_intern_returns_zero_padded_four_digit_placeholder():
    ledger = Ledger()
    p = ledger.intern(Kind.POOL, "/Tenant_A/foo_pool", _ref(line=10), partition="Tenant_A")
    assert p == "POOL_0001"


def test_intern_is_idempotent_for_same_kind_and_original():
    ledger = Ledger()
    a = ledger.intern(Kind.POOL, "/Tenant_A/foo_pool", _ref(line=10), partition="Tenant_A")
    b = ledger.intern(Kind.POOL, "/Tenant_A/foo_pool", _ref(line=99), partition="Tenant_A")
    assert a == b
    assert len(ledger) == 1


def test_distinct_partitions_get_distinct_placeholders_for_same_leaf():
    ledger = Ledger()
    a = ledger.intern(Kind.POOL, "/Common/foo_pool", _ref(line=1), partition="Common")
    b = ledger.intern(Kind.POOL, "/Tenant_A/foo_pool", _ref(line=2), partition="Tenant_A")
    assert a != b
    assert (a, b) == ("POOL_0001", "POOL_0002")


def test_common_partition_is_exempt():
    ledger = Ledger()
    result = ledger.intern_partition(COMMON_PARTITION, _ref())
    assert result is None
    assert len(ledger) == 0


def test_non_common_partition_gets_placeholder():
    ledger = Ledger()
    p = ledger.intern_partition("Tenant_A", _ref(line=5))
    assert p == "PARTITION_0001"


def test_counter_is_independent_per_kind():
    ledger = Ledger()
    pool = ledger.intern(Kind.POOL, "/T/p", _ref(line=1), partition="T")
    vs = ledger.intern(Kind.VS, "/T/v", _ref(line=2), partition="T")
    assert pool == "POOL_0001"
    assert vs == "VS_0001"


def test_fresh_entry_has_empty_references_list():
    ledger = Ledger()
    p = ledger.intern(Kind.POOL, "/T/p", _ref(), partition="T")
    assert ledger.entries[p].references == []


def test_discovery_ref_is_captured_on_entry():
    ledger = Ledger()
    ref = Ref(byte_offset=42, length=13, line=7)
    p = ledger.intern(Kind.POOL, "/T/p", ref, partition="T")
    assert ledger.entries[p].discovery == ref


def test_record_reference_raises_for_unknown_placeholder():
    ledger = Ledger()
    try:
        ledger.record_reference("POOL_9999", _ref())
    except KeyError:
        return
    raise AssertionError("expected KeyError for unknown placeholder")


def test_freeze_blocks_new_interns():
    # CRUCIBLE C-3: pass 2 must not be able to renumber after the answer
    # file is persisted. Freeze enforces immutability.
    ledger = Ledger()
    ledger.intern(Kind.POOL, "/T/p", _ref(), partition="T")
    ledger.freeze()
    assert ledger.frozen is True
    try:
        ledger.intern(Kind.POOL, "/T/q", _ref(), partition="T")
    except RuntimeError:
        return
    raise AssertionError("expected RuntimeError on intern after freeze")


def test_freeze_is_idempotent():
    ledger = Ledger()
    ledger.freeze()
    ledger.freeze()
    assert ledger.frozen is True


def test_intern_existing_pair_works_after_freeze():
    # Looking up an already-interned (kind, original) must still work
    # after freeze — pass 2 needs to call intern() to resolve placeholders.
    ledger = Ledger()
    p = ledger.intern(Kind.POOL, "/T/p", _ref(), partition="T")
    ledger.freeze()
    p2 = ledger.intern(Kind.POOL, "/T/p", _ref(), partition="T")
    assert p == p2


def test_ledger_entry_repr_redacts_original():
    # CRUCIBLE C-4: never leak the un-sanitized customer identifier
    # via repr / logging / debug tools.
    ledger = Ledger()
    secret = "/Customer_Acme/internal_prod_pool_2024"
    ledger.intern(Kind.POOL, secret, _ref(), partition="Customer_Acme")
    entry_repr = repr(ledger.entries["POOL_0001"])
    assert secret not in entry_repr
    assert "<len=" in entry_repr


def test_ledger_repr_does_not_leak_originals():
    ledger = Ledger()
    secret = "/Customer_Acme/internal_prod_pool_2024"
    ledger.intern(Kind.POOL, secret, _ref(), partition="Customer_Acme")
    assert secret not in repr(ledger)


def test_dump_unsafe_does_expose_originals_by_design():
    # The escape hatch for answer-file serialization. Naming is
    # deliberately noisy so grep-audits find every call site.
    ledger = Ledger()
    secret = "/Customer_Acme/internal_prod_pool_2024"
    ledger.intern(Kind.POOL, secret, _ref(), partition="Customer_Acme")
    dump = ledger.dump_unsafe()
    assert dump[0]["original"] == secret
    assert dump[0]["placeholder"] == "POOL_0001"
