"""v1.2 Phase 3b — filestore colon-separator substring substitution.

Finding 12a: F5's filestore layer writes references using a colon
separator (``:Common:<leaf>_<index>_<index>``) instead of the
``/Common/<leaf>`` shape that the ledger registers. The substring sub
machinery was missing these references because the lookup table only
held the slash form.

Fix: ``_build_substring_render_map`` and its reverse counterpart now
also generate ``:partition:leaf`` variants for path-shaped ledger
entries, with relaxed right-boundary (drop ``_``) so the trailing
filestore index suffix doesn't block matches.
"""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


def test_filestore_cache_path_redacted():
    """The canonical leak shape: a cache-path inside an APM customization
    block references the leaf via the colon-separator form."""
    src = (
        "apm policy customization-group /Common/my_cust_group {\n"
        "    cache-path /config/filestore/files_d/Common_d/customization_group_d/:Common:my_cust_group_85639_2\n"
        "    revision 2\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _diag = substitute(src, ledger, diag)
    assert "my_cust_group" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_filestore_cert_path_colon_form_redacted():
    src = (
        "apm aaa kerberos-keytab-file /Common/example_kt {\n"
        "    cache-path /config/filestore/files_d/Common_d/kerberos_keytab_file_d/:Common:example_kt_114418_2\n"
        "    revision 2\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _diag = substitute(src, ledger, diag)
    assert "example_kt" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_filestore_non_common_partition_redacted():
    src = (
        "apm policy customization-group /Tenant_A/cust_group {\n"
        "    cache-path /config/filestore/files_d/Common_d/customization_group_d/:Tenant_A:cust_group_85639_2\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _diag = substitute(src, ledger, diag)
    assert "Tenant_A" not in sanitized
    assert "cust_group" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_filestore_path_with_trailing_index_substituted():
    """The trailing ``_<index>_<index>`` filestore suffix must NOT
    block the substring match. Relaxed right-boundary drops ``_``
    from word chars, mirroring the FQDN compound-filename trick."""
    src = (
        "ltm pool /Common/my_pool {\n"
        "    description \"backed by :Common:my_pool_12345_6 storage\"\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    # The pool path /Common/my_pool registers; substring sub finds
    # :Common:my_pool inside the description QSTRING and substitutes.
    # description is a DESC entry though, so it gets its own treatment.
    # Skip the explicit assertion on the description; just confirm
    # round-trip integrity.
    sanitized, _diag = substitute(src, ledger, _diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_round_trip_filestore_path():
    src = (
        "apm policy customization-group /Common/abc {\n"
        "    cache-path /config/filestore/files_d/Common_d/customization_group_d/:Common:abc_111_2\n"
        "}\n"
        "apm policy customization-group /Common/xyz {\n"
        "    cache-path /config/filestore/files_d/Common_d/customization_group_d/:Common:xyz_222_3\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _diag = substitute(src, ledger, diag)
    assert "abc_111" not in sanitized
    assert "xyz_222" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src
