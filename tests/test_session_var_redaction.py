"""v1.2.1 T1B — APM session-variable custom-namespace tokenization.

Red-team finding: phase4c bigip.conf:8239-8324 leaked custom portal
name `cygnus` through `session.custom.cygnus.webui.userid` and 17
sibling references. v121_t1a red-team additionally surfaced
`session.custom.grafana.*`, `session.custom.owa.*`,
`session.custom.portainer.*`, `session.custom.pihole.*`.

Walker scope (option C, per user 2026-06-16):
- `session.custom.<word>.<rest>` → tokenize <word> as Kind.SESSION_NS
  with metasyntactic-vocab placeholder.
- `session.<word>.<rest>` where <word> is NOT in the F5 builtin
  allowlist → tokenize <word> (e.g. `session.tenants.acme.*`).
- `session.<builtin>.<rest>` → pass through verbatim.

Vocab: foo, bar, baz, qux, quux, corge, grault, garply, waldo,
fred, plugh, xyzzy, thud. Collisions with word-bounded source
content are pre-registered as unsafe so the reverse pass can't
corrupt round-trip.
"""

from __future__ import annotations

from veil.ledger import Kind, Ledger
from veil.scanner import scan, scan_many
from veil.substitute import reverse_substitute, substitute


# ----- the canonical leak (option-C arm 1) ----------------------------------


def test_custom_namespace_single_segment_redacted():
    """session.custom.<word>.<rest> — second segment tokenizes to vocab."""
    src = (
        'apm policy customization-source /Common/p1 {\n'
        '    something session.custom.cygnus.webui.userid\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "cygnus" not in sanitized
    assert "foo" in sanitized  # first vocab slot


def test_custom_namespace_stable_across_references():
    """Same custom word referenced multiple times → same vocab placeholder."""
    src = (
        'apm policy customization-source /Common/p1 {\n'
        '    a session.custom.cygnus.webui.userid\n'
        '    b session.custom.cygnus.rdp.pw\n'
        '    c session.custom.cygnus.role\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "cygnus" not in sanitized
    assert sanitized.count("foo") >= 3


def test_two_distinct_custom_words_get_distinct_vocab():
    """Two different custom words → two distinct vocab slots in order."""
    src = (
        'apm policy customization-source /Common/p1 {\n'
        '    a session.custom.cygnus.webui.userid\n'
        '    b session.custom.grafana.role\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "cygnus" not in sanitized
    assert "grafana" not in sanitized
    # Both vocab slots present.
    assert "foo" in sanitized
    assert "bar" in sanitized


# ----- option-C arm 2: non-builtin first segment -----------------------------


def test_non_allowlist_first_segment_redacted():
    """session.<non-builtin>.<rest> — first segment tokenizes."""
    src = (
        'apm policy customization-source /Common/p1 {\n'
        '    a session.tenants.acmecorp.userid\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "tenants" not in sanitized
    # `acmecorp` (the second-position user value) is NOT covered by
    # option-C — it's a pass-through. (Other walkers may catch it.)


# ----- option-C arm 3: F5 builtin pass-through -------------------------------


def test_builtin_ad_namespace_pass_through():
    src = (
        'apm policy customization-source /Common/p1 {\n'
        '    a session.ad.last.actualdomain\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "session.ad.last.actualdomain" in sanitized


def test_builtin_saml_namespace_pass_through():
    src = (
        'apm policy customization-source /Common/p1 {\n'
        '    a session.saml.last.attr.name.email\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "session.saml.last.attr.name.email" in sanitized


def test_builtin_sso_namespace_pass_through():
    src = (
        'apm policy customization-source /Common/p1 {\n'
        '    a session.sso.token.last.code\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "session.sso.token.last.code" in sanitized


# ----- in-QSTRING and in-iRule TCL contexts ---------------------------------


def test_session_var_in_qstring_redacted():
    """`%{session.custom.<word>...}` inside a QSTRING — segment tokenizes."""
    src = (
        'apm oauth oauth-claim /Common/c1 {\n'
        '    claim-value "%{session.custom.cygnus.role}"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "cygnus" not in sanitized
    assert "foo" in sanitized


def test_session_var_in_irule_tcl_redacted():
    """Custom segment inside iRule TCL `ACCESS::session data get`."""
    src = (
        'ltm rule /Common/auth_rule {\n'
        '    when ACCESS_POLICY_AGENT_EVENT {\n'
        '        set ::user [ACCESS::session data get session.custom.cygnus.webui.userid]\n'
        '    }\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "cygnus" not in sanitized


# ----- round-trip byte-exact -------------------------------------------------


def test_round_trip_byte_exact_single_custom_word():
    src = (
        'apm policy customization-source /Common/p1 {\n'
        '    a session.custom.cygnus.webui.userid\n'
        '    b session.ad.last.actualdomain\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_round_trip_byte_exact_qstring_session_var():
    src = (
        'apm oauth oauth-claim /Common/c1 {\n'
        '    claim-value "%{session.custom.cygnus.role}"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_round_trip_byte_exact_irule_tcl_session_var():
    src = (
        'ltm rule /Common/auth_rule {\n'
        '    when ACCESS_POLICY_AGENT_EVENT {\n'
        '        set ::user [ACCESS::session data get session.custom.cygnus.webui.userid]\n'
        '    }\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- vocab-collision pre-scan (round-trip safety) -------------------------


def test_vocab_collision_skips_unsafe_slot():
    """If source contains the word `foo` (word-bounded), the vocab
    allocator must skip `foo` and use `bar` for the first SESSION_NS
    intern — otherwise reverse-sub would corrupt the original `foo`."""
    src = (
        'apm policy customization-source /Common/p1 {\n'
        '    a session.custom.cygnus.webui.userid\n'
        '    b "literal foo lives here"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # cygnus should redact to `bar`, NOT `foo`.
    assert "cygnus" not in sanitized
    assert "bar" in sanitized
    # And the original `foo` word must survive untouched.
    assert "foo lives here" in sanitized
    # Round-trip preserves the original `foo`.
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_scan_many_pre_registers_collisions_across_files():
    """Multi-file scan: file A has only session.custom.cygnus, file B
    has the literal word `foo`. Allocator must skip `foo` because B's
    pre-scan ran BEFORE A's walker."""
    file_a = (
        'apm policy customization-source /Common/p1 {\n'
        '    a session.custom.cygnus.webui.userid\n'
        '}\n'
    )
    file_b = (
        'ltm pool /Common/legitfoo {\n'
        '    description "no session vars here"\n'
        '    members { foo.bar.example.local:80 { } }\n'
        '}\n'
    )
    ledger, diag = scan_many([("a.conf", file_a), ("b.conf", file_b)])
    # The placeholder for cygnus must NOT be `foo` — file B has
    # `foo.bar` in a pool member, and `foo` would word-match against
    # the leading label.
    placeholder = ledger.by_original.get((Kind.SESSION_NS, "cygnus"))
    assert placeholder is not None
    assert placeholder != "foo"


# ----- regression: existing walkers untouched -------------------------------


def test_pre_t1b_description_walker_still_works():
    """T1B walker registration must not have broken T1A or earlier."""
    src = 'ltm pool /Common/p1 {\n    description "primary cluster"\n}\n'
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "primary cluster" not in sanitized
    assert "DESC_0001" in sanitized
