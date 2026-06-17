# Changelog

All notable changes to **f5-veil** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] — 2026-06-16

### Added — input-source expansions

- **Multi-file two-pass ingestion** for `bigip_base.conf` +
  `bigip.conf` pairs. The base file's objects (VLANs, self-IPs,
  route-domains, etc.) are registered in a shared ledger before the
  main file's references need to resolve. New `scan_many` API; new
  CLI `--input <path>` repeatable flag plus `--output-dir`.
- **UCS archive ingestion** (extract-only). CLI auto-detects `.ucs`
  input, extracts the allowlist members (`config/bigip_base.conf`,
  `config/bigip.conf`, optional `config/bigip_user.conf`),
  obfuscates each, writes to `--output-dir`. UCS is never modified
  or re-packed; allowlist excludes `bigip_script.conf` (deferred —
  iApp templates collide with the IP placeholder model; tracked for
  v1.3 / v2.0).

### Added — leak-coverage hardening (19 finding-groups + follow-ups)

Driven by real-corpus manual inspection. Approximately 28 new
`Kind` values across 12 new walkers.

- **Unknown top-level body walkers** — closes the brace-skip gap on
  blocks whose body content carries customer-identifying data:
  - `sys snmp` — community / trap bucket headers, plaintext
    community strings, `sys-contact`, `sys-location`
    (`SNMP_COMMUNITY`, `SNMP_TRAP`, `SNMP_COMMUNITY_SECRET`,
    `SYS_CONTACT`, `SYS_LOCATION`)
  - `sys syslog` — remote-server bucket headers (`SYSLOG_SERVER`)
  - `sys sshd` — banner text (multi-line QSTRING; `SSHD_BANNER`)
  - `auth remote-role role-info` — bucket-path discovery
    (`REMOTE_ROLE`)
- **Nested-bucket walkers inside known top-level kinds** — the
  enclosing kind's body is brace-skipped by the main loop, so
  nested-object bareword names leak:
  - `cert-key-chain` bucket names inside `ltm profile client-ssl`
    bodies (`CERT_KEY_CHAIN`)
  - `client-policy` bucket names inside APM profile bodies
    (`CLIENT_POLICY`)
- **Cross-cutting field walkers**:
  - Identity / hostname — `admin-name`, `basic-auth-username`,
    `basic-auth-realm`, `user`, `account-name`, `server-name` →
    `USERNAME`
  - Kerberos realm — `realm` field with uppercase value (catches
    public-TLD realms like `BOGUS.COM` that the FQDN walker by
    design skips) → `KRB_REALM`
  - LDAP filter — `filter` field inside LDAP-flavoured blocks →
    `LDAP_FILTER`
  - LDAP base-DN bareword — extends `AD_GROUP_DN` walker to catch
    bareword `DC=...,DC=...` values in `base-dn` /
    `search-base-dn` fields
  - SAML / OAuth identifiers — `entity-id`, `sso-uri`,
    `single-logout-uri`, `single-logout-response-uri`, `audience`
    (braced-list form), `issuer`, `key-id` as dedicated kinds so
    non-FQDN-shaped opaque values are caught (`SAML_ENTITY_ID`,
    `SAML_SSO_URI`, `SAML_SLO_URI`, `SAML_SLO_RESPONSE_URI`,
    `OAUTH_AUDIENCE`, `OAUTH_ISSUER`, `OAUTH_KEY_ID`)
  - `caption` and `service-name` folded into the `DESC` walker
  - Monitor `recv` strings — `MONITOR_RECV`
  - Data-group `records` bucket headers (context-gated, catches
    public-TLD entries that the global FQDN walker skips) —
    `DATA_GROUP_RECORD`
  - APM `expression "return {LITERAL}"` Tcl-literal pattern in
    `variable-assign` bodies — `APM_VAR_LITERAL`
- **Substring-substitution variants**:
  - F5 filestore colon-separator
    (`:Common:<leaf>_<index>_<index>`) — covers `cache-path`
    references that the slash-form substring sub missed
  - FQDN-shaped leaf form for path-shape entries whose leaf is
    public-TLD — covers `source-path /config/ssl/ssl.csr/<fqdn>.com`
    references
  - QSTRING-wrapped header path detection — catches bot-defense
    signature path shapes
  - Per-kind right-boundary protection (FQDN compound filenames)
- **Fixes**:
  - IP-walker version-field exclusion — `version 17.5.1.5` no
    longer gets substituted as if it were an IPv4 address
  - AD_GROUP_DN qualifier relaxation — drop CN= requirement so
    OU-prefix DNs (LDAP `base` values) are redacted as a whole,
    not just the DC suffix
  - Orphan-check substring-shadow exemption — FQDN entries
    intentionally shadowed by longer SAML/OAuth ledger entries
    don't trip the cross-reference integrity assertion

### Verification

Real-corpus canary count for the integration pair (homelab
AD-domain root-label, case-insensitive grep) went from **40 → 0**
across the v1.2 cycle. Full test suite: **503 → 660+** tests
passing, zero regressions, byte-exact round-trip preserved.

### Known gaps (documented, operator review required)

See [docs/architecture.md](docs/architecture.md) for the full
list. Highlights:

- iRule `varname` customer-name leaks
- Public-TLD FQDNs outside the dedicated walker / cert-path /
  source-path contexts
- Free-text Tcl expression literals (`expression "[mcget {...}]"`)
  without a recognised shape

## [1.1.1] — never published to PyPI

Corrective license swap — standard MIT + non-binding `DISCLAIMER.md`
replaces the prior "MIT-Modified Named-Party Exclusion" language.
PyPI republish was deferred; v1.1.1's content is included in v1.2.0.

## [1.1.0] — pushed 2026-06-13

### Added

- **BAREWORD infix substring substitution** — catches identifiers
  embedded in compound barewords. Examples:
  - `application-uri https://10.0.0.42/path` (IP inside URL)
  - `iRule references like /Common/web1:80` (path inside compound)
  - IP ranges like `10.0.0.1-10.0.0.50`
  - File-storage compound filenames `<fqdn>_<index>_<index>`
- Word-boundary protection prevents partial matches against longer
  numeric / identifier runs.

## [1.0.0] — pushed 2026-06-13

First stable release. Production-shaped against real BIG-IP
configurations from a controlled-environment lab corpus.

### Added

- **CLI**: `veil obfuscate` and `veil deobfuscate` commands. Exit
  codes 0 (success), 2 (CLI usage), 3 (input not readable),
  4 (diagnostics non-empty without `--allow-incomplete`),
  5 (leak detector tripped under `--strict`).
- **Answer file**: AES-256-GCM-encrypted, scrypt KDF, atomic
  writes.
- **Path-shape kinds**: pool, virtual server, node, monitor, iRule,
  partition (LTM); pool, wide-IP, server, datacenter, region (GTM);
  VLAN, route-domain, self-IP, trunk (net); policy, profile (APM);
  policy, rule-list, address-list, port-list (security firewall);
  data-group, SNAT, SNAT pool, virtual-address (LTM extras);
  profile (LTM, with factory built-in exemption); UNKNOWN
  best-effort registration for unrecognised top-level blocks.
- **IP literal handling**: bare IPv4 / IPv6 substituted into RFC
  5737 / RFC 3849 docs ranges, preserving source `/24` and `/64`
  structure first-seen-first-allocated.
- **Free-text**: description bodies (QSTRING, bareword, braced),
  Tcl `#` comments inside `ltm rule` bodies, LDAP / AD distinguished
  names (`CN=...,DC=...`) inside any QSTRING, internal-FQDN
  discovery (`*.local`, `*.corp`, `*.lan`, `*.internal`,
  `*.intranet`, `*.home.arpa`, `*.private`).
- **Leak detector**: post-substitution check that flags common
  patterns (RFC1918 / CGNAT / link-local IPs, internal FQDNs, MAC
  addresses, identifier-shaped barewords, paths with non-safe
  partitions).
- **Strict mode**: `--strict` aborts on any leak-detector warning.

## Pre-1.0

Versions 0.0.1 through 0.0.14 were development-cycle iterations.
The detailed history is captured in the git log; consult
`git log --oneline` for per-commit context.
