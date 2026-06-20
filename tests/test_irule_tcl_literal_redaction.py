"""v1.2.1 T4+T5 — iRule TCL literal redaction.

Walker scope: QSTRING bodies inside ``ltm rule`` /
``apm policy customization{,-source}`` / ``apm policy agent``
block bodies, scanned for four shape classes:

1. NETBIOS domain prefix (``CORP\\``)
2. Permissive FQDN (any TLD, 3+ labels)
3. Email literal
4. UNC server\\share path

Triggers:
- v121_t1a round 2 — `corp\\\\` inside an ``apm policy agent
  variable-assign`` TCL expression
- v121_t2 round 3 — `api-ce04d788.duosecurity.com` inside an
  ``ltm rule`` TCL QSTRING (Duo SaaS tenant URL, public TLD —
  strict FQDN walker skipped it by design)
"""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ----- NETBIOS prefix ---------------------------------------------------


def test_netbios_prefix_single_escape_ltm_rule():
    src = (
        "ltm rule /Common/rule1 {\n"
        '    when CLIENT_ACCEPTED {\n'
        '        set domain "CORP\\\\username"\n'
        '    }\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "CORP" not in sanitized.replace("CORP_", "")  # don't trip on PARTITION-style
    assert "AD_NETBIOS_0001" in sanitized


def test_netbios_prefix_nested_escape_apm_variable_assign():
    # Real-corpus shape: TCL expression inside an apm-policy-agent
    # body. The literal ``corp\\`` (TCL) appears in the QSTRING
    # content as ``corp\\\\`` (TMSH-double-escaped).
    src = (
        "apm policy agent variable-assign /Common/va1 {\n"
        "    variables {\n"
        "        {\n"
        '            expression "set prefixuid \\"corp\\\\\\\\\\""\n'
        "            varname session.custom.foo.uid\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "corp" not in sanitized.lower().replace("corp_", "")
    assert "AD_NETBIOS_0001" in sanitized


def test_netbios_skip_tcl_keywords():
    # ``set\\`` is TCL line continuation, NOT a NETBIOS prefix.
    src = (
        "ltm rule /Common/rule1 {\n"
        '    when CLIENT_ACCEPTED {\n'
        '        set foo "set\\\\\n"\n'
        "    }\n"
        "}\n"
    )
    ledger, _ = scan(src)
    assert (Kind.AD_NETBIOS, "set") not in ledger.by_original


def test_netbios_outside_irule_passthrough():
    # ``CORP\\`` outside any iRule-context block should not trigger
    # the walker.
    src = (
        "ltm pool /Common/pool1 {\n"
        '    description "Pool with CORP\\\\foo in description"\n'
        "}\n"
    )
    ledger, _ = scan(src)
    assert (Kind.AD_NETBIOS, "CORP") not in ledger.by_original


# ----- Permissive FQDN --------------------------------------------------


def test_duo_saas_fqdn_in_ltm_rule():
    src = (
        "ltm rule /Common/rule1 {\n"
        "    when HTTP_REQUEST {\n"
        '        set aud "https://api-ce04d788.duosecurity.com/oauth/v1/token"\n'
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "duosecurity.com" not in sanitized
    assert "api-ce04d788" not in sanitized
    assert "FQDN_" in sanitized


def test_three_label_public_tld_inside_irule_redacted():
    src = (
        "ltm rule /Common/rule1 {\n"
        '    set u "https://vendor.example.com/api"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "vendor.example.com" not in sanitized
    assert "FQDN_" in sanitized


def test_two_label_filename_not_redacted():
    # ``index.html`` is 2-label — the 3-label requirement filters it.
    src = (
        "ltm rule /Common/rule1 {\n"
        '    set page "index.html"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "index.html" in sanitized


def test_numeric_tld_not_redacted_by_fqdn_walker():
    # IPv4-like dotted shapes shouldn't trigger the permissive FQDN
    # walker (TLD must be alphabetic). The IPv4 walker DOES catch
    # them now (final-round addition) since ``17.5.1.5`` is a valid
    # IPv4 address — interned and substituted to a docs-range IP.
    src = (
        "ltm rule /Common/rule1 {\n"
        '    set v "17.5.1.5"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # No FQDN entry created.
    assert (Kind.FQDN, "17.5.1.5") not in ledger.by_original
    # IPv4 walker catches it — docs-range substitution applies.
    assert (Kind.IPADDR, "17.5.1.5") in ledger.by_original
    assert "17.5.1.5" not in sanitized


def test_fqdn_outside_irule_strict_walker_skips_public_tld():
    # The strict (pass 2.0) FQDN walker only catches internal-suffix
    # FQDNs. A public-TLD FQDN at top level passes through; the iRule
    # T4 walker is scoped, so it doesn't fire either.
    src = (
        "ltm pool /Common/pool1 {\n"
        "    members {\n"
        "        vendor.example.com:443 {\n"
        "            address 192.0.2.1\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, _ = scan(src)
    assert (Kind.FQDN, "vendor.example.com") not in ledger.by_original


def test_internal_fqdn_dedup_with_strict_walker():
    # If T4 catches ``example.local`` inside an iRule QSTRING, the
    # strict (pass 2.0) FQDN walker should NOT double-intern it.
    src = (
        "ltm rule /Common/rule1 {\n"
        '    set u "https://idp.example.local/saml/idp"\n'
        "}\n"
        "ltm pool /Common/pool1 {\n"
        "    members {\n"
        "        idp.example.local:443 { address 192.0.2.1 }\n"
        "    }\n"
        "}\n"
    )
    ledger, _ = scan(src)
    # Exactly one ledger entry for the FQDN, not two.
    fqdn_entries = [
        e for e in ledger.entries.values()
        if e.kind == Kind.FQDN and e.original == "idp.example.local"
    ]
    assert len(fqdn_entries) == 1


# ----- Email literal ----------------------------------------------------


def test_email_in_irule_qstring():
    src = (
        "ltm rule /Common/rule1 {\n"
        '    set contact "ops-team@example.com"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "ops-team@example.com" not in sanitized
    assert "USERNAME_" in sanitized


# ----- UNC path ---------------------------------------------------------


def test_unc_path_in_irule_qstring():
    # ``\\\\server\\share`` shape — single-escape (4 backslashes
    # leading + 2 between server/share).
    src = (
        "ltm rule /Common/rule1 {\n"
        '    set path "\\\\\\\\fileserver01\\\\public_share"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "fileserver01" not in sanitized
    assert "public_share" not in sanitized
    assert "UNC_PATH_" in sanitized


# ----- Context gating ---------------------------------------------------


def test_apm_policy_customization_source_header_gates():
    src = (
        "apm policy customization-source /Common/cust1 {\n"
        '    inline "<div>Welcome to CORP\\\\domain</div>"\n'
        "}\n"
    )
    ledger, _ = scan(src)
    assert (Kind.AD_NETBIOS, "CORP") in ledger.by_original


def test_apm_policy_agent_irule_event_header_gates():
    src = (
        "apm policy agent irule-event /Common/ev1 {\n"
        '    irule-event-id "log local0. {hello from CORP\\\\foo}"\n'
        "}\n"
    )
    ledger, _ = scan(src)
    assert (Kind.AD_NETBIOS, "CORP") in ledger.by_original


# ----- Description QSTRING skip rule ------------------------------------


def test_description_qstring_skipped():
    # Description QSTRING is interned as DESC by pass 1.7; T4 walker
    # must skip it so the substring detector doesn't orphan.
    src = (
        "ltm rule /Common/rule1 {\n"
        '    description "Connects to api.foo.example.com"\n'
        '    set u "https://api.foo.example.com/x"\n'
        "}\n"
    )
    ledger, _ = scan(src)
    # The FQDN from the description must NOT be interned as FQDN —
    # DESC substitution handles the whole description body.
    desc_qstring = '"Connects to api.foo.example.com"'
    assert (Kind.DESC, desc_qstring) in ledger.by_original
    # The body QSTRING (the set u line) DOES intern the FQDN.
    assert (Kind.FQDN, "api.foo.example.com") in ledger.by_original


# ----- Round-trip -------------------------------------------------------


def test_roundtrip_byte_exact_mixed_shapes():
    src = (
        "ltm rule /Common/rule1 {\n"
        '    set aud "https://api-ce04d788.duosecurity.com/oauth/v1/token"\n'
        '    set domain "CORP\\\\username"\n'
        '    set contact "ops@example.com"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- T5: identifier-internal vendor word rewrite ----------------------


def test_t5_static_jwt_vendor_debug_rewrite():
    # T1B interns ``grafana -> foo`` via session.custom.grafana.* refs.
    # T5 then sees ``static::jwt_grafana_debug`` inside the iRule body
    # and rewrites it to ``static::jwt_foo_debug`` (the SESSION_NS
    # placeholder is the only published name for ``grafana`` and must
    # be used consistently inside identifier rewrites for round-trip).
    src = (
        "apm policy agent variable-assign /Common/va1 {\n"
        "    variables {\n"
        "        {\n"
        '            expression "return 1"\n'
        "            varname session.custom.grafana.userid\n"
        "        }\n"
        "    }\n"
        "}\n"
        "ltm rule /Common/rule1 {\n"
        "    when HTTP_REQUEST {\n"
        "        set static::jwt_grafana_debug 0\n"
        "        if {$static::jwt_grafana_debug} { log local0. \"x\" }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # The literal ``grafana`` must not survive inside the rewritten
    # identifier; the SESSION_NS placeholder takes its place.
    assert "grafana" not in sanitized
    # SESSION_NS placeholder for ``grafana`` (first vocab slot) is
    # ``foo`` unless pre-registered as unsafe — verify it's the one
    # being substituted into the identifier.
    grafana_ph = ledger.by_original[(Kind.SESSION_NS, "grafana")]
    assert grafana_ph in sanitized
    # Round-trip restore.
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_t5_no_session_ns_means_no_rewrite():
    # Without a SESSION_NS entry for ``vendor``, T5 should not touch
    # the identifier — leaves it literal.
    src = (
        "ltm rule /Common/rule1 {\n"
        "    set static::jwt_vendor_debug 0\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "static::jwt_vendor_debug" in sanitized
    assert (Kind.IRULE_IDENT, "static::jwt_vendor_debug") not in ledger.by_original


def test_t5_skips_alphanumeric_flanking():
    # ``staticgrafanadebug`` has alphanumeric flanks on the embedded
    # ``grafana`` — NOT an identifier-segment boundary. T5 must skip.
    src = (
        "apm policy agent variable-assign /Common/va1 {\n"
        "    variables {\n"
        "        {\n"
        '            expression "return 1"\n'
        "            varname session.custom.grafana.userid\n"
        "        }\n"
        "    }\n"
        "}\n"
        "ltm rule /Common/rule1 {\n"
        "    set staticgrafanadebug 0\n"
        "}\n"
    )
    ledger, _ = scan(src)
    assert (Kind.IRULE_IDENT, "staticgrafanadebug") not in ledger.by_original


def test_t5_skips_path_shaped_tokens():
    # ``/Common/grafana_foo`` is path-shaped — T5 must leave it to the
    # path walkers (REMOTE_ROLE / PROFILE / DG / etc.).
    src = (
        "apm policy agent variable-assign /Common/va1 {\n"
        "    variables {\n"
        "        {\n"
        '            expression "return 1"\n'
        "            varname session.custom.grafana.userid\n"
        "        }\n"
        "    }\n"
        "}\n"
        "ltm rule /Common/rule1 {\n"
        "    set x [HTTP::cookie /Common/grafana_foo]\n"
        "}\n"
    )
    ledger, _ = scan(src)
    assert (Kind.IRULE_IDENT, "/Common/grafana_foo") not in ledger.by_original


# ----- Ledger entry shape -----------------------------------------------


def test_ipv4_literal_in_irule_qstring_redacted():
    # Final-round red-team trigger: `175.45.176.0/22` (publicly-
    # routable customer-network range) survived inside an iRule
    # TCL ``expression`` QSTRING. The strict IP walker only scans
    # bare tokens, not QSTRING content.
    src = (
        "apm policy agent variable-assign /Common/va1 {\n"
        "    variables {\n"
        "        {\n"
        '            expression "expr {[IP::addr \\"175.45.176.42\\" equals \\"175.45.176.0/22\\"]}"\n'
        "            varname session.x\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "175.45.176" not in sanitized
    # CIDR suffix preserved (mask value isn't customer-identifying).
    assert "/22" in sanitized


def test_netbios_ledger_entry_shape():
    src = (
        "ltm rule /Common/rule1 {\n"
        '    set domain "ACMEDC\\\\user"\n'
        "}\n"
    )
    ledger, _ = scan(src)
    ph = ledger.by_original[(Kind.AD_NETBIOS, "ACMEDC")]
    e = ledger.entries[ph]
    assert e.kind == Kind.AD_NETBIOS
    assert e.partition is None
    assert e.original == "ACMEDC"
    assert e.placeholder == "AD_NETBIOS_0001"
