"""v1.2.1 T2 + T8 — Monitor URL-path redaction.

Red-team finding: phase4c / v121_t1b leaked vendor / application
fingerprints through monitor ``send`` HTTP request lines and
``success-match-value`` fields. Example survivors:
- ``GET /NMC/<base64>/logon.htm HTTP/...`` (APC NMC web UI)
- ``GET /top.asp HTTP/...`` (classic ASP/IIS)
- ``GET /graph HTTP/...`` (Grafana endpoint)
- ``success-match-value /NMC/<base64>/home.htm``
- ``success-match-value /cs<hex>/home.htm`` (Citrix StoreFront)

Walker scope:
- Field gates: ``send`` (QSTRING containing HTTP request line),
  ``success-match-value`` (WORD or QSTRING with leading ``/``).
- Allowlist: ``/``, ``/index.html``, ``/login``, ``/health``, etc.
- Out of scope: ``recv`` body (handled by existing walker),
  non-URL ``success-match-value`` values (e.g. ``userStatus``,
  ``SID``).
"""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ----- send: HTTP request-line URL path -------------------------------------


def test_send_request_line_path_redacted():
    src = (
        'ltm monitor http /Common/mon1 {\n'
        '    send "GET /top.asp HTTP/1.1\\r\\n\\r\\n"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "/top.asp" not in sanitized
    assert "MONITOR_PATH_0001" in sanitized


def test_send_nmc_vendor_path_redacted():
    src = (
        'ltm monitor http /Common/mon1 {\n'
        '    send "GET /NMC/OeW4iiomTG03lfaDjC5+1g/logon.htm HTTP/1.1\\r\\n\\r\\n"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "/NMC/" not in sanitized
    assert "logon.htm" not in sanitized
    assert "MONITOR_PATH_0001" in sanitized


def test_send_vdesk_citrix_path_redacted():
    src = (
        'ltm monitor http /Common/mon1 {\n'
        '    send "GET /vdesk/hangup.php3 HTTP/1.1\\r\\n\\r\\n"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "/vdesk/" not in sanitized


def test_send_grafana_graph_path_redacted():
    src = (
        'ltm monitor http /Common/mon1 {\n'
        '    send "GET /graph HTTP/1.1\\r\\n\\r\\n"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "/graph" not in sanitized


def test_send_post_method_path_redacted():
    src = (
        'ltm monitor http /Common/mon1 {\n'
        '    send "POST /api/login HTTP/1.1\\r\\n\\r\\n"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "/api/login" not in sanitized


# ----- send: allowlist pass-through -----------------------------------------


def test_send_root_path_pass_through():
    src = (
        'ltm monitor http /Common/mon1 {\n'
        '    send "GET / HTTP/1.1\\r\\n\\r\\n"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "GET / HTTP" in sanitized
    assert (Kind.MONITOR_PATH, "/") not in ledger.by_original


def test_send_index_html_pass_through():
    src = (
        'ltm monitor http /Common/mon1 {\n'
        '    send "GET /index.html HTTP/1.1\\r\\n\\r\\n"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "GET /index.html HTTP" in sanitized
    assert (Kind.MONITOR_PATH, "/index.html") not in ledger.by_original


def test_send_login_pass_through():
    src = (
        'ltm monitor http /Common/mon1 {\n'
        '    send "GET /login HTTP/1.1\\r\\n\\r\\n"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "GET /login HTTP" in sanitized
    assert (Kind.MONITOR_PATH, "/login") not in ledger.by_original


# ----- success-match-value --------------------------------------------------


def test_success_match_value_url_qstring_redacted():
    src = (
        'ltm monitor http /Common/mon1 {\n'
        '    success-match-value "/NMC/FS1eVjFlS9Uu0RBmT1wn+A/home.htm"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "/NMC/" not in sanitized
    assert "home.htm" not in sanitized


def test_success_match_value_url_bareword_redacted():
    src = (
        'ltm monitor http /Common/mon1 {\n'
        '    success-match-value /cs8e0431b1/home.htm\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "/cs8e0431b1/" not in sanitized


def test_success_match_value_non_url_bareword_pass_through():
    """Bareword values that aren't URL-shaped (no leading /) are out
    of T2 scope — they may still be customer-specific, but they need
    their own walker class."""
    src = (
        'ltm monitor http /Common/mon1 {\n'
        '    success-match-value userStatus\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "userStatus" in sanitized
    assert (Kind.MONITOR_PATH, "userStatus") not in ledger.by_original


def test_success_match_value_root_pass_through():
    src = (
        'ltm monitor http /Common/mon1 {\n'
        '    success-match-value /\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "success-match-value /" in sanitized
    assert (Kind.MONITOR_PATH, "/") not in ledger.by_original


# ----- round-trip byte-exact -------------------------------------------------


def test_round_trip_send_request_line():
    src = (
        'ltm monitor http /Common/mon1 {\n'
        '    send "GET /top.asp HTTP/1.1\\r\\nHost: host01\\r\\n\\r\\n"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_round_trip_success_match_value_qstring():
    src = (
        'ltm monitor http /Common/mon1 {\n'
        '    success-match-value "/NMC/FS1eVjFlS9Uu0RBmT1wn+A/home.htm"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_round_trip_success_match_value_bareword():
    src = (
        'ltm monitor http /Common/mon1 {\n'
        '    success-match-value /cs8e0431b1/home.htm\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_round_trip_full_monitor_block_with_path_and_recv():
    """Realistic monitor block — both send path and recv together."""
    src = (
        'ltm monitor http /Common/mon1 {\n'
        '    recv "MyAppHealth-OK"\n'
        '    send "GET /top.asp HTTP/1.1\\r\\nHost: app01\\r\\n\\r\\n"\n'
        '    success-match-value /cs8e0431b1/home.htm\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- regression: existing monitor_recv walker still works -----------------


def test_recv_still_redacts():
    src = (
        'ltm monitor http /Common/mon1 {\n'
        '    recv "MyAppHealth-OK"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "MyAppHealth-OK" not in sanitized
    assert "MONITOR_RECV_0001" in sanitized


# ----- T8: non-monitor URL-bearing fields ---------------------------------


def test_t8_request_value_qstring_path_redacted():
    # phase4c bigip.conf:10832 — APM access-policy ``request-value
    # "/base/main_login.html"`` survived v1.2.
    src = (
        "apm policy access-policy /Common/p1 {\n"
        "    rules {\n"
        "        x {\n"
        '            request-value "/base/main_login.html"\n'
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "/base/main_login.html" not in sanitized
    assert "MONITOR_PATH_0001" in sanitized


def test_t8_uri_full_url_path_redacted():
    # phase4c bigip.conf:11883 — SAML IdP-connector ``uri
    # https://FQDN/zabbix/index_sso.php?acs`` — path survived after
    # FQDN was tokenized. T8 interns the FULL URL (host + path) so
    # substring-sub's strict left-boundary check passes.
    src = (
        "apm aaa saml-idp-connector /Common/idp1 {\n"
        "    uri https://idp.example.local/zabbix/index_sso.php?acs\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "/zabbix/index_sso.php" not in sanitized
    assert "idp.example.local" not in sanitized
    assert "MONITOR_PATH_" in sanitized


def test_t8_application_uri_path_redacted():
    src = (
        "ltm policy /Common/p1 {\n"
        "    rules {\n"
        "        r1 {\n"
        "            application-uri /citrix/store/PNAgent/config.xml\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "/citrix/store/PNAgent/config.xml" not in sanitized
    assert "MONITOR_PATH_" in sanitized


def test_t8_uri_value_not_url_shaped_passthrough():
    # ``uri`` is generic; if the value isn't URL-shaped, T8 must
    # pass it through verbatim (no MONITOR_PATH intern, no
    # over-tokenization).
    src = (
        "some unknown-block /Common/x {\n"
        "    uri none\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "uri none" in sanitized
    assert (Kind.MONITOR_PATH, "none") not in ledger.by_original


def test_t8_uri_allowlist_path_passthrough():
    src = (
        "ltm policy /Common/p1 {\n"
        "    rules {\n"
        "        r1 {\n"
        "            uri /login\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "uri /login" in sanitized


def test_t8_uri_already_interned_as_saml_skipped():
    # If the SAML/OAuth walker already interned a ``uri`` value as
    # SAML_ENTITY_ID (whole URL), T8 must NOT also intern the path
    # — would orphan the sub-entry.
    src = (
        "apm aaa saml-sp-connector /Common/sp1 {\n"
        "    entity-id https://sp.example.local/saml/sp\n"
        "}\n"
        "apm aaa saml-sp-connector /Common/sp2 {\n"
        "    uri https://sp.example.local/saml/sp\n"
        "}\n"
    )
    ledger, diag = scan(src)
    # SAML walker should have interned the URL as SAML_ENTITY_ID.
    assert (
        Kind.SAML_ENTITY_ID,
        "https://sp.example.local/saml/sp",
    ) in ledger.by_original
    # T8 should NOT have additionally interned ``/saml/sp`` as
    # MONITOR_PATH — would orphan because SAML's full-URL sub fires
    # first and the sub-path never appears standalone.
    assert (Kind.MONITOR_PATH, "/saml/sp") not in ledger.by_original


def test_t8_roundtrip():
    src = (
        "apm policy access-policy /Common/p1 {\n"
        '    request-value "/base/main_login.html"\n'
        "}\n"
        "apm aaa saml-idp-connector /Common/idp1 {\n"
        "    uri https://idp.example.local/zabbix/index_sso.php?acs\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src
