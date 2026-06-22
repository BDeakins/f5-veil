# Changelog

All notable changes to **f5-veil** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] — 2026-06-22

License change release. **No functional changes versus v1.2.2.**

### Changed

- **License: MIT → GNU Affero General Public License v3.0
  (AGPL-3.0-or-later).** Full license text in
  [LICENSE](LICENSE). Key implication: modified versions made
  available to users over a network must offer source code of the
  modified version under AGPL-3.0 on equal terms.
- Release artifacts at or below v1.2.2 (PyPI wheels, git commits,
  tags) remain governed by the MIT License under which they were
  originally published. AGPL-3.0 applies from v1.3.0 onward.
- [DISCLAIMER.md](DISCLAIMER.md) reframed for AGPL: notes the
  network-use source-disclosure obligation and the MIT cutover at
  v1.2.2. The personal statement of intent regarding the audience
  remains explicitly non-binding.
- `pyproject.toml`: `license = "AGPL-3.0-or-later"` (was `"MIT"`);
  `version = "1.3.0"`.
- README "Status" / "Roadmap" / "License" sections updated to
  reflect the license change and the resulting v1.3 / v1.4
  renumbering (v1.4 now carries the planned Docker wrapper).

### Unchanged

- Code surface — every module, walker, and test under `src/veil/`
  and `tests/` is byte-identical to v1.2.2.
- 759 tests passing. Real-corpus integration-pair byte-exact
  round-trip preserved.
- CLI flags, exit codes, answer-file format, AES-256-GCM + scrypt
  encryption scheme, multi-file / UCS ingestion behaviour.

## [1.2.2] — 2026-06-20

Patch release — single CRITICAL fix found in the post-v1.2.1
red-team round.

### Fixed

- **B5 — Real private IP surviving in monitor `send` / `recv`
  QSTRING bodies.** `Host: 192.168.100.1` (and similar embedded
  IPs in monitor HTTP request headers) survived through v1.2.1.
  Root cause: T2's `monitor_path_discovery` parsed the URL path
  out of the request line but didn't scan the QSTRING for IP
  literals; the strict pass-1.5 IP walker only scans bare WORD
  tokens, not QSTRING content. Fix: added `_intern_ipv4_in_qstring`
  to `monitor_path_discovery`, gated on `send` and `recv` field
  names. IP literals (with optional CIDR suffix) inside those
  QSTRINGs intern via `Ledger.intern_ipaddr` → RFC 5737 docs-range
  substitution. CIDR mask preserved literal.

### Test coverage

- 759 tests passing (755 → +4 B5 tests). Real-corpus integration
  pair byte-exact round-trip preserved. Final post-fix red-team
  pass on `_phase_verify/v121_final/`: zero in-scope CRITICAL
  findings remaining.

## [1.2.1] — 2026-06-20

Patch release — leak-coverage hardening cycle driven by a
cold-read red-team of the v1.2 sanitized output. Closes seven
walker gaps that survived v1.2's audit. Five new walker files +
two extensions of existing walkers; six new `Kind` values; one
substring-sub heuristic fix.

### Added — leak-coverage hardening (seven walker gaps closed)

- **T1A — APM OAuth claim / scope descriptions** —
  `description_discovery` extended to walk `apm oauth oauth-claim`
  and `apm oauth oauth-scope` blocks. Catches free-text `claim-name`,
  `claim-description`, `scope-name`, `scope-description` values
  that escaped the pre-v1.2.1 description walker.
- **T1B — APM session-variable user namespace tokenization** — new
  `apm_session_var_discovery` walker (pass 2.2). Catches
  `session.custom.<word>.<rest>` and `session.<non-builtin>.<rest>`
  user-chosen namespace segments. Placeholder vocab is the
  canonical 13-word metasyntactic set (`foo`, `bar`, `baz`, `qux`,
  `quux`, `corge`, `grault`, `garply`, `waldo`, `fred`, `plugh`,
  `xyzzy`, `thud`) — visually distinct from `KIND_NNNN` so reviewers
  spot org-namespace redactions at a glance. Overflow past 13
  reuses the vocab with `_NN` suffixes. New `Kind.SESSION_NS`.
- **T2 — Monitor URL-path walker** — new `monitor_path_discovery`
  (pass 1.85k.1) for `send` HTTP-request-line URLs and
  `success-match-value` URL-shaped values. Catches vendor /
  application fingerprints like `/NMC/...` (APC NMC), `/top.asp`
  (classic ASP/IIS), `/vdesk/...` (Citrix VDI), `/zabbix/...`.
  Small allowlist (`/`, `/index.html`, `/login`, `/health`, ...)
  passes through. New `Kind.MONITOR_PATH`.
- **T3A — AD `query-attrname` non-standard attribute walker** —
  new `ad_query_attrname_discovery` (pass 1.85i.1). Standard AD
  schema attrs (`sAMAccountName`, `mail`, `memberOf`, ...) pass
  through; non-standard attrs (`homeMDB`, `msDS-ResultantPSO`,
  `extensionAttribute1`) tokenize. Header allowlist covers both
  the AAA-config (`apm aaa active-directory`) and policy-agent
  (`apm policy agent aaa-active-directory`) shapes. New
  `Kind.AD_ATTR`.
- **T3B — Timestamp year-coarsening** — new
  `timestamp_discovery` (pass 1.85n). `creation-time` /
  `last-modified-time` values coarsen to `YYYY-01-01:00:00:00`
  (year preserved as low-fidelity operational signal, month / day
  / time generalized). Format-preserving so downstream TMSH
  parsers still accept. Collision disambiguation uses the seconds
  slot. New `Kind.TIMESTAMP`.
- **T4 — iRule TCL literal walker** — new
  `irule_tcl_literal_discovery` (pass 1.95). Scans QSTRING bodies
  inside `ltm rule` / `apm policy *` / `apm sso *` blocks for
  five shape classes:
  - NETBIOS domain prefix (`CORP\\`) — new `Kind.AD_NETBIOS`
  - Permissive FQDN (any TLD, 3+ labels) — catches SaaS tenant
    subdomains like `api-ce04d788.duosecurity.com` that the
    strict pass-2.0 walker skips
  - Email literal — routes to existing `Kind.USERNAME`
  - UNC `\\server\share` — new `Kind.UNC_PATH`
  - IPv4 literal (with optional CIDR) — catches IPs hardcoded
    inside TCL `expression` bodies that the bare-token IP walker
    misses
- **T5 — iRule TCL identifier rewrite** — same file as T4
  (pass 2.25). Scans WORD tokens inside iRule-context bodies for
  TCL identifiers that EMBED a SESSION_NS vendor word as an
  identifier-bounded substring (`static::jwt_grafana_debug` →
  `static::jwt_<vocab>_debug`, `grafana_logon_form` →
  `grault_logon_form`). New `Kind.IRULE_IDENT` registers the full
  identifier rewrite so the existing substring-sub machinery
  applies surgically without relaxing word-boundary protection
  globally.
- **T8 — Non-monitor URL-bearing fields** — `monitor_path_discovery`
  extended to handle `request-value`, `uri`, `application-uri`.
  Full URLs (`https://host/path`) intern as one MONITOR_PATH entry
  (host + path together) so substring-sub's strict left-boundary
  check passes. Skips values already interned by the SAML/OAuth
  walker (SAML_ENTITY_ID / SAML_SSO_URI / etc.) to avoid orphan
  sub-entries.

### Fixed

- **T7 — Substring-sub short-literal exclusion (v1.2 over-fire fix)** —
  filter pure-digit originals of length ≤ 3 from the substring-sub
  map. Pre-v1.2.1, an `expression "return {1}"` in the corpus
  interned `1` as `APM_VAR_LITERAL_0001`; the substring sub then
  over-fired on every standalone `1` in the source, corrupting
  fields like `version 17.5.1.5` to
  `version 17.5.APM_VAR_LITERAL_0001.5`. Filter is narrow on
  purpose — alphabetic shorts (`acme`, `admin`, `Secret`) still
  substring-sub because they're legitimate customer secrets.

### Test coverage

- 755 tests passing (660+ v1.2.0 baseline → 755 after the v1.2.1
  cycle; net +94 across T1A/T1B/T2/T3A/T3B/T4/T5/T7/T8).
- Real-corpus integration pair byte-exact round-trip preserved.
- Final red-team subagent pass on `_phase_verify/v121_final/`:
  zero CRITICAL findings in scope. Remaining advisory items (F5
  version comment, OESIS module version, factory-shipped Citrix
  data-groups, SSH cipher suites) are F5-stock metadata,
  dismissable per existing v1.2 triage rules.

### Deferred to v1.3

- **Q5 punt — vendor names in TCL identifiers without a
  `session.*` anchor.** T5 catches embedded vendor words only when
  they're already interned by T1B's SESSION_NS walker (via
  `session.custom.<vendor>.*`). Pure `static::<vendor>_*` variables
  whose vendor never appears in a session-namespace anchor (e.g.
  `static::damascus_*`) survive in v1.2.1.
- **Hardcoded TCL string literals / secrets.** High-entropy
  random-string tokens hardcoded in iRule `proc` return values
  (OAuth client IDs, signing secrets, magic SAML markers like
  `"Canary"`) aren't caught by any shape detector. New leak class
  flagged in v1.2.1 final red-team; walker design pending.
- **Common-word over-fire in `DATA_GROUP_RECORD` substring sub.**
  Geographic terms (`America`, `Central`, ...) interned by the
  data-group records walker cause cosmetic over-fire in unrelated
  fields (`time-zone America/Central`). Round-trip preserved;
  fix is a walker-level skip-list, not a substitute-time filter.

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
