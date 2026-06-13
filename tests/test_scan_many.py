"""v1.2 — multi-file two-pass scanning (``scan_many``).

Real BIG-IP exports are typically a pair: ``bigip_base.conf`` holds the
foundational layer (partitions, VLANs, self-IPs, route-domains, trunks)
and ``bigip.conf`` references those objects by name. Scanning either
file alone misses the cross-file relationship — main-file references to
a base-file VLAN don't get substituted because the VLAN wasn't
registered in the ledger when the main file was scanned.

``scan_many`` takes a list of ``(filename, content)`` pairs and chains
``scan()`` calls with a shared ledger. Pass 2 (``substitute``) then runs
once per file against the merged ledger, yielding sanitized output for
each.

Tests below exercise the cross-file flow with synthetic fixtures so
intent is explicit. Real-corpus integration against the STARGATE pair
lives in ``test_integration_real_configs.py``.
"""

from __future__ import annotations

from veil.ledger import Kind, Ledger
from veil.scanner import scan, scan_many
from veil.substitute import reverse_substitute, substitute


# ---------- base file objects register into shared ledger ----------


def test_base_file_vlan_registered_when_paired_with_main():
    base = (
        "net vlan /Common/vlan_internal {\n"
        "    tag 100\n"
        "}\n"
    )
    main = (
        "ltm pool /Common/app_pool {\n"
        "    members {\n"
        "        /Common/10.0.0.10:80 { address 10.0.0.10 }\n"
        "    }\n"
        "}\n"
    )
    ledger, _diag = scan_many([
        ("bigip_base.conf", base),
        ("bigip.conf", main),
    ])
    assert (Kind.VLAN, "/Common/vlan_internal") in ledger.by_original
    assert (Kind.POOL, "/Common/app_pool") in ledger.by_original


# ---------- main-file references resolve against base-file ledger ----------


def test_main_file_fullpath_vlan_reference_gets_substituted():
    """Canonical TMSH output references base-file objects by full path
    (``vlans { /Common/vlan_internal }``), not by leaf. Verified against
    the STARGATE corpus — 30 full-path VLAN refs, 0 leaf-only refs.

    Because base scanned first and registered the VLAN as
    ``Kind.VLAN`` with full path as ``original``, the WORD-token exact-
    match path in pass-2 rewrites the reference in the main file. This
    is the load-bearing cross-file flow."""
    base = (
        "net vlan /Common/vlan_internal {\n"
        "    tag 100\n"
        "}\n"
    )
    main = (
        "ltm virtual /Common/vs1 {\n"
        "    destination /Common/10.0.0.1:80\n"
        "    vlans { /Common/vlan_internal }\n"
        "    vlans-enabled\n"
        "}\n"
    )
    ledger, diag = scan_many([
        ("bigip_base.conf", base),
        ("bigip.conf", main),
    ])
    san_main, _diag = substitute(main, ledger, diag)
    # The base-file VLAN reference inside the main file should be gone.
    assert "vlan_internal" not in san_main
    assert "/Common/VLAN_0001" in san_main
    # Round-trip both files
    san_base, _ = substitute(base, ledger, diag)
    assert reverse_substitute(san_base, ledger) == base
    assert reverse_substitute(san_main, ledger) == main


def test_leaf_only_vlan_reference_known_gap():
    """Documented gap: leaf-only references (``vlans { vlan_internal }``,
    no ``/Common/`` prefix) are NOT substituted because the ledger keys
    on full path, and substring substitution scans for ledger originals
    AS substrings of token values — not the other way around. STARGATE
    corpus uses zero leaf-only refs, so this is a v2+ concern, but pin
    the behavior here so it's obvious if it ever changes."""
    base = "net vlan /Common/vlan_leafgap { tag 200 }\n"
    main = (
        "ltm virtual /Common/vs1 {\n"
        "    destination /Common/10.0.0.1:80\n"
        "    vlans { vlan_leafgap }\n"
        "}\n"
    )
    ledger, diag = scan_many([
        ("bigip_base.conf", base),
        ("bigip.conf", main),
    ])
    san_main, _ = substitute(main, ledger, diag)
    # Gap documented — leaf survives.
    assert "vlan_leafgap" in san_main
    # Round-trip still byte-exact because no substitution happened.
    assert reverse_substitute(san_main, ledger) == main


# ---------- partition defined in base, referenced in main ----------


def test_partition_from_base_substitutes_in_main():
    base = (
        "auth partition Tenant_A {\n"
        "    default-route-domain 0\n"
        "}\n"
    )
    main = (
        "ltm pool /Tenant_A/app_pool {\n"
        "    members {\n"
        "        /Tenant_A/10.0.0.10:80 { address 10.0.0.10 }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan_many([
        ("bigip_base.conf", base),
        ("bigip.conf", main),
    ])
    # Pool path scanning will also intern the partition; main-alone would
    # too. The point of this test: confirm scan_many produces one consistent
    # PARTITION entry shared across both files, not two.
    assert (Kind.PARTITION, "Tenant_A") in ledger.by_original
    part_entries = [e for e in ledger.entries.values()
                    if e.kind == Kind.PARTITION and e.original == "Tenant_A"]
    assert len(part_entries) == 1
    san_base, _ = substitute(base, ledger, diag)
    san_main, _ = substitute(main, ledger, diag)
    assert "Tenant_A" not in san_base
    assert "Tenant_A" not in san_main
    assert reverse_substitute(san_base, ledger) == base
    assert reverse_substitute(san_main, ledger) == main


# ---------- IPADDR /24 preservation across files ----------


def test_ipaddr_24_preserved_across_files():
    """The IPADDR allocator preserves source ``/24`` structure
    first-seen-first-allocated. Two files in the same source ``/24``
    must render into the same RFC 5737 ``/24``."""
    base = (
        "net self /Common/self_internal {\n"
        "    address 10.0.0.1/24\n"
        "}\n"
    )
    main = (
        "ltm pool /Common/p {\n"
        "    members {\n"
        "        /Common/10.0.0.42:80 { address 10.0.0.42 }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan_many([
        ("bigip_base.conf", base),
        ("bigip.conf", main),
    ])
    # Both IPs in the same /24 should render to the same RFC 5737 /24.
    ph_base = ledger.by_original[(Kind.IPADDR, "10.0.0.1")]
    ph_main = ledger.by_original[(Kind.IPADDR, "10.0.0.42")]
    # Strip last octet for /24 check
    base_24 = ".".join(ph_base.split(".")[:3])
    main_24 = ".".join(ph_main.split(".")[:3])
    assert base_24 == main_24, (
        f"IPADDR /24 not preserved across files: {ph_base=} {ph_main=}"
    )


# ---------- scan_many with one file == scan() ----------


def test_scan_many_single_source_matches_scan():
    src = (
        "ltm pool /Common/app_pool {\n"
        "    members {\n"
        "        /Common/10.0.0.10:80 { address 10.0.0.10 }\n"
        "    }\n"
        "}\n"
    )
    led_single, _ = scan(src)
    led_many, _ = scan_many([("bigip.conf", src)])
    # Same set of (kind, original) keys.
    assert set(led_single.by_original.keys()) == set(led_many.by_original.keys())
    # Same counters per kind.
    assert led_single.counters == led_many.counters


# ---------- order matters ----------


def test_order_independent_when_substitute_runs_after_all_scans():
    """``scan_many`` runs all scans to completion before the caller
    runs ``substitute``. So even with a wrong order (main before base),
    substitution sees the final merged ledger and rewrites references
    correctly. Order only matters when interning is path-dependent
    (the IPADDR allocator is the main case — see the dedicated
    /24-preservation test). For symbol references this is order-agnostic."""
    base = "net vlan /Common/vlan_x { tag 50 }\n"
    main = (
        "ltm virtual /Common/v {\n"
        "    destination /Common/10.0.0.1:80\n"
        "    vlans { /Common/vlan_x }\n"
        "}\n"
    )
    # WRONG order
    ledger_wrong, diag_wrong = scan_many([
        ("bigip.conf", main),
        ("bigip_base.conf", base),
    ])
    san_main_wrong, _ = substitute(main, ledger_wrong, diag_wrong)
    assert "vlan_x" not in san_main_wrong
    assert reverse_substitute(san_main_wrong, ledger_wrong) == main


# ---------- explicit ledger / diagnostics threading ----------


def test_scan_many_accepts_prebuilt_ledger():
    """Caller can pass an existing ledger to chain additional sources
    into an already-populated one."""
    src1 = "ltm pool /Common/p1 { members { } }\n"
    src2 = "ltm pool /Common/p2 { members { } }\n"
    led = Ledger()
    scan(src1, ledger=led)
    led2, _ = scan_many([("more.conf", src2)], ledger=led)
    assert led2 is led
    assert (Kind.POOL, "/Common/p1") in led.by_original
    assert (Kind.POOL, "/Common/p2") in led.by_original


# ---------- empty list ----------


def test_scan_many_empty_list_returns_fresh_ledger():
    led, diag = scan_many([])
    assert len(led) == 0
    assert diag.unknown_top_level == []


# ---------- v1.2 features still work in multi-file mode ----------


def test_remote_role_walker_runs_per_file_in_multi_file_mode():
    base = "auth partition Tenant_A { default-route-domain 0 }\n"
    main = (
        "auth remote-role {\n"
        "    role-info {\n"
        "        /Common/F5_Admins { role administrator }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan_many([
        ("bigip_base.conf", base),
        ("bigip.conf", main),
    ])
    assert (Kind.REMOTE_ROLE, "/Common/F5_Admins") in ledger.by_original
    san_main, _ = substitute(main, ledger, diag)
    assert "F5_Admins" not in san_main
    assert reverse_substitute(san_main, ledger) == main
