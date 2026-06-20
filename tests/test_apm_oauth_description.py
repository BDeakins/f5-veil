"""v1.2.1 T1A — APM oauth-claim / oauth-scope description redaction.

Red-team finding: phase4c bigip.conf:992 leaked
`claim-description "Grafana Role sourced from incoming SAML Assertion"`
verbatim through the v1.2 sanitizer. Cause: the description-family
walker only visited `description` / `caption` / `service-name` and
did not cover `apm oauth oauth-claim` / `apm oauth oauth-scope`
free-text fields.

These tests verify that the four oauth free-text fields
(`claim-description`, `scope-description`, `claim-name`, `scope-name`)
now redact and round-trip via the existing `Kind.DESC` pipeline.
"""

from __future__ import annotations

from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ----- the canonical leak ---------------------------------------------------


def test_grafana_claim_description_redacted():
    """The exact red-team-flagged leak — third-party product name in a
    free-text claim-description — must redact."""
    src = (
        'apm oauth oauth-claim /Common/claim_role {\n'
        '    claim-description "Grafana Role sourced from incoming SAML Assertion"\n'
        '    claim-name role\n'
        '    claim-value "%{session.saml.last.attr.name.role}"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert "Grafana" not in sanitized
    assert "SAML Assertion" not in sanitized
    assert "DESC_" in sanitized
    assert diag.unredacted_description == []


def test_grafana_claim_description_round_trip():
    src = (
        'apm oauth oauth-claim /Common/claim_role {\n'
        '    claim-description "Grafana Role sourced from incoming SAML Assertion"\n'
        '    claim-name role\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- scope-description (also QSTRING form) --------------------------------


def test_scope_description_redacted():
    src = (
        'apm oauth oauth-scope /Common/email_scope {\n'
        '    scope-description "User Email Address"\n'
        '    scope-name email_scope\n'
        '    scope-value email\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert "User Email Address" not in sanitized
    assert "DESC_" in sanitized
    assert diag.unredacted_description == []


def test_scope_description_round_trip():
    src = (
        'apm oauth oauth-scope /Common/email_scope {\n'
        '    scope-description "User Email Address"\n'
        '    scope-name email_scope\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- bareword form: claim-name / scope-name -------------------------------


def test_claim_name_bareword_redacted():
    """`claim-name` carries a bareword value (e.g. `role`, `email`,
    `userID`). Over-redaction is acceptable per spec — the field is
    free-form."""
    src = (
        'apm oauth oauth-claim /Common/claim_userID {\n'
        '    claim-name userID\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    # Strip the partition label `claim_userID` (object name — not the
    # field value) from the search target so we're testing only the
    # `claim-name <value>` line.
    field_line = [
        ln for ln in sanitized.splitlines() if "claim-name " in ln
    ][0]
    assert "userID" not in field_line
    assert "DESC_" in field_line


def test_scope_name_bareword_redacted():
    src = (
        'apm oauth oauth-scope /Common/scope_profile {\n'
        '    scope-name profile_scope\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    field_line = [
        ln for ln in sanitized.splitlines() if "scope-name " in ln
    ][0]
    assert "profile_scope" not in field_line
    assert "DESC_" in field_line


def test_claim_name_bareword_round_trip():
    src = (
        'apm oauth oauth-claim /Common/claim_role {\n'
        '    claim-name role\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- multi-field combined node --------------------------------------------


def test_full_oauth_claim_block_round_trip():
    """Realistic block — all four redactable fields present plus a
    `claim-value` APM variable reference that must pass through this
    walker (T1B handles session.*)."""
    src = (
        'apm oauth oauth-claim /Common/claim_email {\n'
        '    claim-description "Email address sourced from incoming SAML assertion"\n'
        '    claim-name email\n'
        '    claim-value "%{session.saml.last.attr.name.email}"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert "Email address sourced" not in sanitized
    # claim-value content is a T1B concern, not T1A — it should still
    # appear in sanitized output until T1B lands.
    assert "session.saml.last.attr.name.email" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_full_oauth_scope_block_round_trip():
    src = (
        'apm oauth oauth-scope /Common/profile_scope {\n'
        '    customization-group /Common/APM_POLICY_001\n'
        '    scope-description "User Profile information"\n'
        '    scope-name profile_scope\n'
        '    scope-value profile\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert "User Profile information" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- regression: existing description fields still work -------------------


def test_existing_description_still_redacts():
    """Confirm the new oauth fields haven't broken the original
    `description` field handling."""
    src = 'ltm pool /Common/foo {\n    description "primary cluster"\n}\n'
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert "primary cluster" not in sanitized
    assert '"DESC_0001"' in sanitized
