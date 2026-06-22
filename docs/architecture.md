# f5-veil Architecture

License: AGPL-3.0-or-later from v1.3.0 onward — see [LICENSE](../LICENSE)
and [DISCLAIMER.md](../DISCLAIMER.md). v1.3.0 is a license-change-only
release with no functional changes versus v1.2.2; the pass structure
described below is unchanged. Release artifacts at or below v1.2.2
remain MIT.

Status: v1.2.2 — pass-1 (top-level path discovery) + pass-1.5 (IP
literal interning with field-name allowlist) + pass-1.7 (description
QSTRING / bareword / braced) + pass-1.8 (iRule `#` comment) + the
pass-1.85 family (v1.2 leak-coverage hardening — sys snmp / syslog /
sshd bodies, cert-key-chain / client-policy nested buckets, identity /
LDAP filter / SAML+OAuth / monitor recv / data-group records / APM
variable-assign literal field walkers) + the pass-1.85i.1 / 1.85k.1 /
1.85n / 1.95 / 2.0 / 2.2 / 2.25 family (v1.2.1 leak-coverage hardening
— AD non-standard `query-attrname`, non-monitor URL-bearing fields
(`uri`, `request-value`, `application-uri`) + `MONITOR_PATH` paths,
timestamp year-coarsening, iRule TCL QSTRING-literal shapes
(NETBIOS / FQDN / email / UNC / IPv4), APM `session.custom.<word>`
namespace tokenization, iRule TCL identifier rewrites embedding a
`SESSION_NS` vendor word) + pass-1.9 (AD / LDAP distinguished name) +
pass-2 substitution (full substring substitution applied to every
QSTRING AND every BAREWORD regardless of TMSH context, with the v1.2.1
T7 short-literal filter excluding pure-digit ≤ 3 originals) +
AES-256-GCM answer file + obfuscate/deobfuscate CLI + leak detector
with `--strict`. Object scope: LTM pool / virtual / node / monitor /
rule / partition / profile / data-group / snat / snatpool /
virtual-address, GTM pool / wideip / server / datacenter / region,
net vlan / route-domain / self / trunk, APM policy / profile /
oauth-claim / oauth-scope / session-namespace / variable-assign,
security firewall policy / rule-list / address-list / port-list;
bare IPv4/IPv6 literals (also inside monitor `send` / `recv` QSTRING
bodies from v1.2.2); **QSTRING, bareword AND braced descriptions**;
**Tcl `#` comments inside `ltm rule` bodies**; **identifier substring
substitution inside every QSTRING AND every BAREWORD** (paths, IPs,
partitions, AD DNs uniformly, including IPs embedded in compound URL-
shaped barewords and IP ranges like `10.0.0.1-10.0.0.50`). gtm
topology, net interface, security dos, full ASM coverage, and
QSTRING-wrapped header paths (bot-defense signatures) still pending —
v1.3+ scope.

## Goal

Replace every customer-identifying value in a BIG-IP configuration with a
typed placeholder, store the originals in an encrypted answer file, and
restore them on the reverse pass — so engineers can collaborate with
third-party AI tools without exfiltrating customer data.

## Pipeline

The obfuscator runs in three passes over `bigip.conf` (pass 1.5 is
embedded inside `scan()` and is invisible to callers):

### Pass 1 — discovery (`veil.scanner.scan`)

1. Tokenize the source byte-for-byte (`veil.tokenizer.tokenize`).
2. Walk the token stream at brace depth 0 looking for top-level object
   headers — `ltm pool`, `ltm virtual`, `ltm node`, `ltm monitor
   <subtype>`, `ltm rule` in v0.1.
3. For each recognised header, intern the full path (and its partition
   sub-span) into the `Ledger`. The byte offset of the discovered
   identifier is recorded in `LedgerEntry.discovery` so pass 2 can
   rewrite in place.
4. For each *unrecognised* top-level block (e.g. `gtm wideip`,
   `ltm dns`), or for malformed paths under recognised kinds (e.g.
   `ltm pool /Common/`), record a `Diagnostics` entry instead of
   silently dropping. Pass-2 callers must fail closed on non-empty
   diagnostics unless the operator explicitly opts in to partial
   obfuscation.
5. Freeze the ledger via `Ledger.freeze()`. Once frozen, no new
   placeholders can be minted — the answer file persisted from this
   state is authoritative for pass 2 and for deobfuscation.

### Pass 1.7 — description redaction (`veil.description_discovery.discover_descriptions`)

Called by `scan()` immediately after pass 1.5 and before
`ledger.freeze()`. Walks the token stream looking for the
`description` keyword followed by:

- A QSTRING — interned as `Kind.DESC` with the full quoted token as
  `original` (so reverse restores the exact quoted byte sequence).
  Pass-2 emits `"DESC_NNNN"` in its place.
- A bareword WORD — interned similarly. Pass-2 emits `DESC_NNNN`.
- An LBRACE (braced form) — deferred to v0.0.5; pass-2 falls back to
  the legacy verbatim emit + `unredacted_description` diagnostic.

Empty descriptions (`description ""`) are skipped — nothing to redact,
no diagnostic fires.

Dedup is by the full original token (including wrapping). Same
substantive text in different wrappings yields distinct placeholders so
each reverse path can restore byte-exactly.

### Pass 1.5 — IP-literal discovery (`veil.ip_discovery.discover_ip_literals`)

Called by `scan()` immediately before `ledger.freeze()`. Walks the same
token stream looking for WORD tokens that are (or lead with) an IPv4 or
IPv6 address literal. Each unique IP is interned as `Kind.IPADDR`. Token
forms covered: bare, `:port`, `%route-domain`, `%rd:port`, CIDR `/mask`.
Bracketed IPv6 `[fc00::1]:80` deferred to v0.0.4.

Skipped: TMSH wildcards (`0.0.0.0`, `::`, `any`, `any6`); IPv4 netmasks
(contiguous-high-bits pattern detection — covers `255.255.255.0`,
`255.255.0.0`, etc.); IPs inside QSTRINGs (out of scope — emitted
verbatim by pass 2 and surfaced via `qstring_contains_identifier`); IPs
inside `description` values (surfaced via `unredacted_description`).

v1.2 added a field-name allowlist exclusion: IP-shaped values that
immediately follow `version` / `tmsh-version` / `software-version` /
`bios-version` / `module-version` / `build-version` pass through
verbatim. Adjacency is broken by any non-WORD token, so
list-shape values still get IP-scanned correctly.

### Pass 1.85 family — v1.2 leak-coverage hardening passes

Each pass below runs between pass 1.5 and pass 2.0 (and before
ledger freeze). They share a structural pattern: walk the token
stream a second time, find specific named blocks or field-name
contexts whose contents the main pass-1 loop brace-skipped, and
intern their identifying values into the ledger so pass-2's
existing substitution machinery (full-match path-shape OR
substring sub) handles the mutation.

| Pass | File | Closes |
|------|------|--------|
| 1.85 | `remote_role_discovery.py` | `auth remote-role role-info` bucket headers (`Kind.REMOTE_ROLE`) |
| 1.85b | `snmp_discovery.py` | `sys snmp` bodies — communities / traps / sys-contact / sys-location |
| 1.85c | `syslog_discovery.py` | `sys syslog remote-servers` bucket headers |
| 1.85d | `sshd_discovery.py` | `sys sshd` banner-text / pre-login-banner / post-login-banner |
| 1.85e | `cert_keychain_discovery.py` | nested `cert-key-chain { <bucket> { ... } }` bareword bucket names inside `ltm profile client-ssl` |
| 1.85f | `client_policy_discovery.py` | nested `client-policy { <bucket> { ... } }` bareword bucket names inside APM profile bodies |
| 1.85g | `username_discovery.py` | identity / hostname field-name allowlist → `Kind.USERNAME` |
| 1.85h (pass 2.1) | `krb_realm_discovery.py` | uppercase Kerberos realm values that the FQDN walker skips by design (public TLDs) |
| 1.85i | `ldap_filter_discovery.py` | `filter` field inside LDAP-flavoured top-level blocks → `Kind.LDAP_FILTER` |
| 1.85j | `saml_oauth_discovery.py` | 6 SAML / OAuth identifier field names → dedicated kinds; runs BEFORE FQDN so longest-match-first picks the full-URL placeholder over inner FQDN |
| 1.85k | `monitor_recv_discovery.py` | `recv` field (exact match, not `recv-disable`) inside monitor blocks → `Kind.MONITOR_RECV` |
| 1.85l | `data_group_records_discovery.py` | `records` bucket headers inside `ltm data-group internal/external` — context-gated so public-TLD records get caught |
| 1.85m | `apm_var_literal_discovery.py` | `expression "return {LITERAL}"` Tcl pattern in APM `variable-assign` bodies |

Pass 1.7 (`description_discovery.py`) was extended in v1.2.1 (T1A)
to walk `apm oauth oauth-claim` and `apm oauth oauth-scope` block
bodies so `claim-description` / `scope-description` free-text
values intern as `Kind.DESC` rather than passing through.

Pass 1.9 (`ad_dn_discovery.py`, AD/LDAP DN extraction inside
QSTRINGs) and pass 2.0 (`fqdn_discovery.py`, internal-FQDN
discovery) predate v1.2 but were extended in v1.2: pass 1.9 added
a bareword pass-B for `base-dn` / `search-base-dn` / `search-dn`
fields and relaxed the qualifier to accept OU+DC-only DNs;
pass 2.0 collaborates with pass-1.85j via longest-match-first
during substring sub.

### v1.2.1 / v1.2.2 leak-coverage hardening passes

A second wave of walkers added across the v1.2.1 cycle, driven by
a cold-read red-team of the v1.2 sanitized output. Each walker
either extends an existing pass-1.85 walker file or introduces a
new one. Pass numbers are inserted into the existing 1.85 family
order so longest-match-first substring sub works correctly.

| Pass | Tier | File | Closes |
|------|------|------|--------|
| 1.85i.1 | T3A | `ad_query_attrname_discovery.py` (new) | non-standard AD `query-attrname` values inside `apm aaa active-directory` and `apm policy agent aaa-active-directory` blocks → `Kind.AD_ATTR` (standard schema attrs like `sAMAccountName`, `memberOf` allowlisted; length floor of 4 chars for non-allowlist attrs to keep substring-sub safe) |
| 1.85k.1 | T2 / T8 | `monitor_path_discovery.py` (new) | monitor `send` HTTP request-line URL paths, `success-match-value` URL-shaped values, plus the non-monitor URL-bearing fields `uri` / `request-value` / `application-uri` → `Kind.MONITOR_PATH`. Small allowlist (`/`, `/index.html`, `/login`, `/health`, ...) passes through. Full URLs (`https://host/path`) intern as ONE entry (host + path together) so substring sub's strict left-boundary check passes. Skips values already interned by the SAML/OAuth walker to avoid orphan sub-entries. **v1.2.2 extends this walker (`_intern_ipv4_in_qstring`) to scan QSTRING bodies for IPv4 literals (with optional CIDR) gated on `send` / `recv` field names — IPs intern via `Ledger.intern_ipaddr` → RFC 5737 docs-range substitution; CIDR mask preserved literal.** |
| 1.85n | T3B | `timestamp_discovery.py` (new) | `creation-time` / `last-modified-time` values coarsen to `YYYY-01-01:00:00:00` via `Ledger.intern_timestamp` → `Kind.TIMESTAMP`. Year preserved as low-fidelity operational signal; month/day/time generalized. Format-preserving so TMSH parsers still accept. Collision disambiguation uses the seconds slot. |
| 1.95 | T4 | `irule_tcl_literal_discovery.py` (new) | QSTRING bodies inside `ltm rule` / `apm policy *` / `apm sso *` blocks scanned for five shape classes: NETBIOS domain prefix (`CORP\\`) → `Kind.AD_NETBIOS`; permissive FQDN (any TLD, 3+ labels — catches SaaS tenant subdomains like `api-xxxxxxxx.duosecurity.com` that the strict pass-2.0 walker skips); email → `Kind.USERNAME`; UNC `\\server\share` → `Kind.UNC_PATH`; IPv4 literal with optional CIDR (catches IPs hardcoded inside TCL `expression` bodies that the bare-token IP walker misses). Runs BEFORE pass 2.0 FQDN. |
| 2.2 | T1B | `apm_session_var_discovery.py` (new) | `session.custom.<word>.<rest>` and `session.<non-builtin>.<rest>` user-chosen namespace segments → `Kind.SESSION_NS`. Placeholder vocab is the canonical 13-word metasyntactic set (`foo`, `bar`, `baz`, `qux`, `quux`, `corge`, `grault`, `garply`, `waldo`, `fred`, `plugh`, `xyzzy`, `thud`) — visually distinct from `KIND_NNNN` so reviewers spot org-namespace redactions at a glance. Overflow past 13 reuses the vocab with `_NN` suffixes. |
| 2.25 | T5 | `irule_tcl_literal_discovery.py` (shared file, separate pass) | WORD tokens inside iRule-context bodies scanned for TCL identifiers that EMBED a `SESSION_NS` vendor word as an identifier-bounded substring (`static::jwt_<vendor>_debug` → `static::jwt_<vocab>_debug`, `<vendor>_logon_form` → `<vocab>_logon_form`) → `Kind.IRULE_IDENT`. Custom render path: the placeholder IS the rewritten identifier text, not a `KIND_NNNN` token. Runs AFTER pass 2.2 so vendor words are interned first. iRule-context header allowlist: `ltm rule`, `apm policy <any-subtype>` (3-word generic), `apm policy agent <subtype>` (4-word matched BEFORE the 3-word generic so agent subtypes aren't shadowed), `apm sso <subtype>` (3-word). |

**T6 (APM customization-form child blocks)** auto-closed by T5 +
the `apm sso <subtype>` allowlist extension — no separate walker
needed.

**T7 (substring-sub short-literal exclusion, v1.2 over-fire fix)**
lives in `substitute.py`'s `_build_substring_render_map`: pure-digit
originals of length ≤ 3 are filtered from the substring-sub map.
Pre-v1.2.1, an `expression "return {1}"` interned `1` as
`APM_VAR_LITERAL_0001`, and the substring sub over-fired on every
standalone `1` in source, corrupting `version 17.5.1.5` to
`version 17.5.APM_VAR_LITERAL_0001.5`. Filter is narrow on
purpose — alphabetic shorts (`acme`, `admin`, `Secret`) still
substring-sub because they're legitimate customer secrets.

### Pass 2 — substitution (`veil.substitute.substitute`)

1. Walk the same token stream and emit each token's bytes verbatim,
   copying inter-token whitespace and comments from the source via
   cursor-tracking. WORD tokens whose value matches a ledger entry are
   rendered as path-piece placeholders (see below) instead.
2. Every substitution is recorded as a `Ref` on the corresponding
   `LedgerEntry.references`. Partition substitutions inside path
   renders record references on the PARTITION entry too.
3. Description values (`description "..."`, `description { ... }`,
   `description bareword`) pass through verbatim and surface in
   `Diagnostics.unredacted_description`. Dedicated DESC_NNNN minting is
   deferred to a 'pass 1.5: free-text discovery' PR.
4. QSTRING content (string literals) is emitted verbatim. If content
   contains a substring matching a ledger entry's original, surface in
   `Diagnostics.qstring_contains_identifier` so callers fail closed.
5. At end of substitute, check every entry has at least one reference;
   orphans surface in `Diagnostics.orphan_entries`.
6. Hard invariant: if a non-Common object claims a partition with no
   `PARTITION_NNNN` entry, `substitute` raises `RuntimeError` rather
   than fall back to the literal partition name (which would leak).
7. The leak detector (separate PR) runs over the sanitized output as
   the last line of defense.
8. **v1.2 substring-sub variants** — `_build_substring_render_map`
   (and reverse) generate two extra variants per path-shape entry:
   - **Colon-form** `:partition:leaf` covers F5 filestore references
     like `:Common:<leaf>_<index>_<index>` that the slash-form
     substring sub missed.
   - **FQDN-shaped leaf form** (when leaf is `host.example.com` and
     the FQDN walker hasn't already registered it — i.e. public-TLD
     leafs) covers bare leaf references in file paths like
     `source-path /config/ssl/ssl.csr/<fqdn>.com`. The bare
     placeholder `UNK_NNNN` substitutes; longer slash / colon forms
     still win in their own contexts via longest-match-first.

   Both variants use a relaxed right-boundary char set (drops `_`)
   so trailing F5 file-storage index suffixes don't block matches.
9. **Substring-shadow exemption** in the orphan check —
   `_check_orphan_entries` exempts ledger entries whose `original`
   is a strict substring of some REFERENCED entry's `original`. This
   covers the SAML/OAuth ↔ FQDN double-tokenization case: SAML
   walker registers the full URL, FQDN walker registers the inner
   FQDN, longest-match-first picks the SAML entry everywhere — the
   FQDN entry is intentionally orphan (not a parser gap).

#### Path-piece rendering

When a WORD token's value matches a ledger entry, substitute emits:

| Original path | Rendered placeholder |
|---------------|----------------------|
| `/Common/foo_pool` | `/Common/POOL_0001` |
| `/Tenant_A/foo_pool` | `/PARTITION_0001/POOL_0001` |
| `Tenant_A` (bare partition name in attributes) | `PARTITION_0001` |

`/Common/` is preserved literal as universal BIG-IP signal.

## Placeholder taxonomy

Type-prefixed counters, 4-digit zero-padded from v1.0:

| Kind | Placeholder | Example original |
|------|-------------|------------------|
| `POOL` | `POOL_0001` | `/Tenant_A/customer_app_pool` |
| `VS` | `VS_0001` | `/Common/vs_app_https` |
| `NODE` | `NODE_0001` | `/Common/10.0.0.42` or `/Tenant_A/2001:db8::1` |
| `MON` | `MON_0001` | `/Common/http_mon_app` |
| `IRULE` | `IRULE_0001` | `/Common/my_redirect_rule` |
| `PARTITION` | `PARTITION_0001` | `Tenant_A` (note: `Common` is exempt) |
| `IPADDR` | `203.0.113.42` (rendered docs IP, not `IPADDR_NNNN`) | `10.0.0.42` |
| `DESC` | `DESC_0001` — QSTRING and braced forms both emit `"DESC_0001"` (qstring-wrapped); bareword form emits bare `DESC_0001`. Reverse map distinguishes by stored `original` form. | `"customer prod pool"` (qstring) / `{ multi-line body }` (braced) / `single_word` (bareword) |
| `PROFILE` | `PROFILE_0001` | `/Tenant_A/my_custom_http_profile` (built-in `/Common/<name>` profiles like `/Common/http`, `/Common/clientssl` exempt as universal TMOS signal) |
| `GTM_POOL` | `GTM_POOL_0001` | `/Common/dns_app_pool` (gtm pool a/aaaa/mx/...) |
| `GTM_WIDEIP` | `GTM_WIDEIP_0001` | `/Common/www.customer.com` (gtm wideip a/aaaa/...) |
| `GTM_SERVER` | `GTM_SERVER_0001` | `/Common/east_bigip` |
| `GTM_DC` | `GTM_DC_0001` | `/Common/east_dc` (gtm datacenter) |
| `DG` | `DG_0001` | `/Common/customer_url_list` (`ltm data-group internal/external`) |
| `SNAT` | `SNAT_0001` | `/Common/customer_snat` |
| `SNATPOOL` | `SNATPOOL_0001` | `/Common/customer_snatpool` |
| `VADDR` | `VADDR_0001` | `/Common/customer_vs_addr` (`ltm virtual-address`; may shadow a NODE entry of the same IP path — see orphan note below) |
| `VLAN` | `VLAN_0001` | `/Common/customer_vlan` (`net vlan`) |
| `ROUTE_DOMAIN` | `ROUTE_DOMAIN_0001` | `/Common/customer_rd` (`net route-domain`) |
| `SELF_IP` | `SELF_IP_0001` | `/Common/self_ip` (`net self`) |
| `TRUNK` | `TRUNK_0001` | `/Common/customer_trunk` (`net trunk`) |
| `GTM_REGION` | `GTM_REGION_0001` | `/Common/customer_region` (`gtm region`) |
| `APM_POLICY` | `APM_POLICY_0001` | `/Common/customer_apm_policy` (`apm policy access-policy`, `apm policy customization-source`, etc.) |
| `APM_PROFILE` | `APM_PROFILE_0001` | `/Common/customer_apm_access` (`apm profile access`) |
| `FIREWALL_POLICY` | `FIREWALL_POLICY_0001` | `/Common/customer_fwp` (`security firewall policy`) |
| `FIREWALL_RULE_LIST` | `FIREWALL_RULE_LIST_0001` | `/Common/customer_rl` (`security firewall rule-list`) |
| `FIREWALL_ADDRESS_LIST` | `FIREWALL_ADDRESS_LIST_0001` | `/Common/customer_addrs` (`security firewall address-list`) |
| `FIREWALL_PORT_LIST` | `FIREWALL_PORT_LIST_0001` | `/Common/customer_ports` (`security firewall port-list`) |
| `UNK` | `UNK_0001` | `/Common/foo` for top-level blocks of unrecognised kinds (e.g. `sys file ssl-cert /Common/foo`) — best-effort registration so substring sub catches them in body references |

### Free-text kinds added v0.0.10 – v1.2

| Kind | Placeholder | Example original |
|------|-------------|------------------|
| `IRULE_COMMENT` | `IRULE_COMMENT_0001` (rendered as `# IRULE_COMMENT_0001` COMMENT token) | `# customer config note` inside `ltm rule` body |
| `AD_GROUP_DN` | `AD_GROUP_DN_0001` | `CN=Admins,DC=corp,DC=example,DC=com` (also `OU=...,DC=...` from v1.2) |
| `FQDN` | `FQDN_0001` | `host01.example.local` (internal-suffix only; public TLDs handled by dedicated kinds) |
| `REMOTE_ROLE` | `REMOTE_ROLE_0001` | `/Common/F5_Admins` inside `auth remote-role role-info` |

### v1.2 leak-coverage kinds

Added by the v1.2 leak-coverage hardening cycle. See `CHANGELOG.md`
for the per-walker rationale.

| Kind | Placeholder | Example original / context |
|------|-------------|------------------|
| `SNMP_COMMUNITY` | `SNMP_COMMUNITY_0001` | `/Common/iComm_1` bucket in `sys snmp { communities { ... } }` |
| `SNMP_TRAP` | `SNMP_TRAP_0001` | `/Common/iTrap_1` bucket in `sys snmp { traps { ... } }` |
| `SNMP_COMMUNITY_SECRET` | `SNMP_COMMUNITY_SECRET_0001` | plaintext community string from `community-name` (communities) or `community` (traps) fields |
| `SYS_CONTACT` | `SYS_CONTACT_0001` | value of `sys-contact` inside `sys snmp` |
| `SYS_LOCATION` | `SYS_LOCATION_0001` | value of `sys-location` inside `sys snmp` |
| `SYSLOG_SERVER` | `SYSLOG_SERVER_0001` | `/Common/loghost` bucket in `sys syslog { remote-servers { ... } }` |
| `SSHD_BANNER` | `SSHD_BANNER_0001` | `banner-text` / `pre-login-banner` / `post-login-banner` value inside `sys sshd` (multi-line QSTRING supported) |
| `CERT_KEY_CHAIN` | `CERT_KEY_CHAIN_0001` | bareword bucket inside `ltm profile client-ssl { cert-key-chain { <name> { ... } } }` |
| `CLIENT_POLICY` | `CLIENT_POLICY_0001` | bareword bucket inside `apm profile connectivity { client-policy { <name> { ... } } }` |
| `USERNAME` | `USERNAME_0001` | value of `admin-name`, `basic-auth-username`, `basic-auth-realm`, `user`, `account-name`, `server-name` |
| `KRB_REALM` | `KRB_REALM_0001` | uppercase realm value of `realm` field (e.g. `ACME.CORP`) — catches public-TLD realms the FQDN walker skips |
| `LDAP_FILTER` | `LDAP_FILTER_0001` | value of `filter` field inside LDAP-flavoured blocks |
| `SAML_ENTITY_ID` | `SAML_ENTITY_ID_0001` | value of `entity-id` field in SAML SP/IdP blocks |
| `SAML_SSO_URI` | `SAML_SSO_URI_0001` | value of `sso-uri` field |
| `SAML_SLO_URI` | `SAML_SLO_URI_0001` | value of `single-logout-uri` field |
| `SAML_SLO_RESPONSE_URI` | `SAML_SLO_RESPONSE_URI_0001` | value of `single-logout-response-uri` field |
| `OAUTH_AUDIENCE` | `OAUTH_AUDIENCE_0001` | value(s) of `audience` field (braced-list form supported) |
| `OAUTH_ISSUER` | `OAUTH_ISSUER_0001` | value of `issuer` field |
| `OAUTH_KEY_ID` | `OAUTH_KEY_ID_0001` | value of `key-id` field |
| `MONITOR_RECV` | `MONITOR_RECV_0001` | value of `recv` field inside `ltm monitor` blocks |
| `DATA_GROUP_RECORD` | `DATA_GROUP_RECORD_0001` | record bucket headers inside `ltm data-group internal/external` records bodies — operator-chosen lookup keys |
| `APM_VAR_LITERAL` | `APM_VAR_LITERAL_0001` | LITERAL extracted from `expression "return {LITERAL}"` Tcl pattern in `apm policy agent variable-assign` bodies |

### v1.2.1 / v1.2.2 leak-coverage kinds

Added by the v1.2.1 hardening cycle and the v1.2.2 monitor IPv4
patch. See `CHANGELOG.md` for the per-walker rationale.

| Kind | Placeholder | Example original / context |
|------|-------------|------------------|
| `AD_ATTR` | `AD_ATTR_0001` | non-standard AD attribute value of `query-attrname` (e.g. `homeMDB`, `msDS-ResultantPSO`, `extensionAttribute1`); standard schema attrs allowlisted |
| `AD_NETBIOS` | `AD_NETBIOS_0001` | NETBIOS domain prefix `CORP\\` inside iRule TCL QSTRINGs |
| `UNC_PATH` | `UNC_PATH_0001` | UNC path `\\server\share` inside iRule TCL QSTRINGs |
| `TIMESTAMP` | `YYYY-01-01:00:00:00` (custom rendered form, NOT `TIMESTAMP_NNNN`) | `creation-time 2024-03-17:14:32:08` → `2024-01-01:00:00:00`. Format-preserving for TMSH parsers. Collision disambiguation via seconds-slot increment. |
| `IRULE_IDENT` | rewritten identifier text (custom render path) | `static::jwt_grafana_debug` → `static::jwt_grault_debug`; `grafana_logon_form` → `grault_logon_form` (vendor word swapped for the SESSION_NS vocab token interned at pass 2.2) |
| `SESSION_NS` | one of the 13-word metasyntactic vocab (`foo`, `bar`, `baz`, `qux`, `quux`, `corge`, `grault`, `garply`, `waldo`, `fred`, `plugh`, `xyzzy`, `thud`); overflow uses `<word>_NN` | user-chosen segment in `session.custom.<word>.<rest>` or `session.<non-builtin>.<rest>` |
| `MONITOR_PATH` | `MONITOR_PATH_0001` | monitor `send` HTTP request-line URL path (`/NMC/...`, `/vdesk/...`, `/zabbix/...`); `success-match-value`, `uri`, `request-value`, `application-uri` values. Full URLs (`https://host/path`) intern as ONE entry (host+path) for substring-sub left-boundary correctness. v1.2.2: IPv4 literals inside `send` / `recv` QSTRING bodies additionally intern via `Ledger.intern_ipaddr` (RFC 5737 substitution, CIDR mask preserved literal). |

### Counter format

4-digit zero-padded (`POOL_0001`) from v1.0 onward. The extra digit is
free to pre-pay; renaming the ledger format after release would be a
forklift migration for cross-run consistency in v2.0.

## Collision and exemption policy

- **Distinct placeholders per `(kind, full-path)`.** `/Common/foo_pool`
  and `/Tenant_A/foo_pool` get different `POOL_NNNN` numbers — tenant
  labels are themselves customer-identifying, so sharing a placeholder
  would defeat the obfuscation contract.
- **`/Common/` partition is exempt.** The literal string `/Common/`
  survives into sanitized output. `Common` is universal BIG-IP signal,
  not customer identity. Only non-Common partition names receive
  `PARTITION_NNNN` placeholders.

## IP placeholders

- **IPv4**: RFC 5737 documentation ranges (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`). Source `/24` structure is
  preserved first-seen-first-allocated: the first source `/24`
  encountered maps to `192.0.2.0/24`, the second to `198.51.100.0/24`,
  the third to `203.0.113.0/24`. Host octets within a `/24` are
  preserved (`10.0.0.42` → `192.0.2.42` if `10.0.0.0/24` got the first
  slot).
- **IPv6**: RFC 3849 (`2001:db8::/32`). Source `/64` structure preserved
  by sequential allocation; pool holds 2^32 source `/64`s — exhaustion
  is not a real-world concern.

### Subnet-pool exhaustion (IPv4)

RFC 5737 provides only 3 `/24`s. Configurations spanning more than 3
source `/24`s collapse the 4th and later into the shared pool, packing
into whatever address slots aren't claimed by the first 3 preserved
mappings. Round-trip remains exact; only AI-side subnet co-location
signal is reduced. Collapsed source nets surface via
`Diagnostics.ipv4_subnet_collapsed` and the CLI prints them as an
informational warning (NOT a fail-closed trigger).

Hard exhaustion (768 host slots across all 3 `/24`s) raises
`RuntimeError`. Larger pools deferred to v0.0.4.

### IPADDR placeholder model

Unlike other kinds, `Kind.IPADDR` does **not** use opaque `KIND_NNNN`
placeholders. The `LedgerEntry.placeholder` field IS the rendered
docs-range address string (`203.0.113.42`), so sanitized output reads
as a normal IP for AI tooling. The reverse map keys on the rendered
form for round-trip.

### Coexistence with NODE

When a NODE path's leaf is itself an IP (e.g. `ltm node /Common/10.0.0.42`),
the path retains its `NODE_NNNN` placeholder (`/Common/NODE_0001`) for
path references. Bare IP literals in body context render via the IPADDR
mapping (`address 192.0.2.42`). The two forms coexist intentionally;
reverse substitution handles both. Future PR may unify NODE-leaf
rendering with IPADDR for visual consistency.

### Wildcards and netmasks

NOT substituted (NOT customer-identifying):
- `0.0.0.0`, `::` — TMSH wildcards
- IPv4 contiguous-high-bits masks: `255.255.255.0`, `255.255.0.0`,
  `255.0.0.0`, `255.255.255.255`, etc.

`::1` (IPv6 loopback) IS interned and substituted — it's a leak under
the v0.0.2 leak detector, not a wildcard.

### Out of scope for v0.0.3

- IPs inside `description "..."` bodies — emitted verbatim,
  `unredacted_description` fires.
- IPs inside arbitrary QSTRINGs — emitted verbatim; if the IP is also a
  ledger original (because it appears as a WORD elsewhere), the
  `qstring_contains_identifier` check fires.
- IPs inside iRule Tcl strings or `#` comments — deferred to Tcl-lexer PR.
- Bracketed IPv6 form `[fc00::1]:80` — deferred to v0.0.4.

## Answer file (`veil.answer_file`)

- Authenticated encryption: AES-256-GCM (12-byte random nonce per file).
- Key derivation: scrypt with OWASP-2024 interactive parameters
  (`n=2^17, r=8, p=1, length=32`, 16-byte random salt per file).
  Parameters are encoded in the envelope so changing defaults later
  does not break existing files.
- Envelope: versioned JSON wrapping base64'd ciphertext, salt, and
  nonce. Plaintext payload is a versioned JSON document containing
  `Ledger.dump_unsafe()` plus the Diagnostics struct (so post-hoc
  audit of past obfuscate runs is possible without re-scanning).
- Both layers use `json.dumps(..., sort_keys=True, indent=2)` for
  deterministic, diff-friendly output.
- **Single exception:** all failures (wrong passphrase, tampered file,
  unknown version, malformed envelope, OS I/O error) raise
  `AnswerFileError`. The decryption-failure path uses the generic
  message `"decryption failed"` so an attacker cannot distinguish
  wrong-passphrase from tampered-file via timing or message content.
- **Atomic write:** `<path>.tmp` first, then `os.replace`. Tmp is
  cleaned up on error. No fsync ceremony in v0.1.
- **Crash safety (CLI contract):** the CLI must write the answer file
  to disk *before* the sanitized output. A crash mid-pipeline must
  never leave a sanitized file orphaned from its key. The library
  doesn't enforce this — the CLI layer does.
- **Threat model:** see the `answer_file.py` docstring. The key
  invariants: any envelope tampering changes the derived key and
  breaks the GCM auth tag, so weakening-via-KDF-downgrade is
  ineffective.

## Cross-reference integrity

Every substitution pass 2 performs is logged as a `Ref` on the
corresponding `LedgerEntry.references`. At end of pass 2 the obfuscator
asserts: every `LedgerEntry` has at least its discovery offset in
`references` (i.e. nothing minted in pass 1 was *unused* in pass 2).
A mismatch indicates a parser/scanner gap — fail closed.

## Leak detector

Pure function over the sanitized output, runs between `substitute()` and
the disk-write step. Returns a `LeakReport`; the CLI surfaces leaks to
stderr and (under `--strict`) aborts with exit code 5 before any file
lands on disk.

### Flagged content

| Kind | Source | Reason label |
|------|--------|--------------|
| `RFC1918_IPV4` | `10/8`, `172.16/12`, `192.168/16` | RFC 1918 private |
| `CGNAT_IPV4` | `100.64/10` | RFC 6598 CGNAT |
| `LINKLOCAL_IPV4` | `169.254/16` | RFC 3927 link-local |
| `LOOPBACK_IPV4` | `127/8` | RFC 1122 loopback |
| `ULA_IPV6` | `fc00::/7` | RFC 4193 ULA |
| `LINKLOCAL_IPV6` | `fe80::/10` | RFC 4291 link-local |
| `LOOPBACK_IPV6` | `::1` | RFC 4291 loopback |
| `INTERNAL_FQDN` | `.local`, `.corp`, `.lan`, `.internal`, `.intranet`, `.lan.local`, `.home.arpa`, `.private` | `<suffix>` |
| `MAC_ADDRESS` | `xx:xx:...`, `xx-xx-...`, Cisco `xxxx.xxxx.xxxx` | MAC address |
| `IDENTIFIER_BAREWORD` | letter-led token with embedded digit/underscore/hyphen, not in TMSH keyword set, not a placeholder | identifier-shaped bareword |
| `IDENTIFIER_PATH` | path-shaped token whose partition piece isn't `/Common/` or `/PARTITION_NNNN/` | non-safe partition |

### Exemptions

- RFC 5737 IPv4 documentation ranges (`192.0.2/24`, `198.51.100/24`,
  `203.0.113/24`) — the obfuscator's IP placeholders.
- RFC 3849 IPv6 documentation range (`2001:db8::/32`).
- Literal `Common` — universal BIG-IP signal.
- Tokens matching `^(POOL|VS|NODE|MON|IRULE|PARTITION|UNK)_\d{4,}$`.
- A curated TMSH keyword set covers ordinary attribute words
  (`enabled`, `description`, `members`, profile names, etc.) so the
  bareword heuristic doesn't drown the operator.

### Behaviour

- Default mode: any leaks print to stderr as warnings; obfuscation
  proceeds; exit code 0. Output also hints `pass --strict to fail on this`.
- `--strict`: any non-empty `LeakReport` aborts with exit code 5 *before*
  the answer file or sanitized output is written. Same crash-safety
  guarantee as the diagnostics fail-closed path.
- `--dry-run`: the leak report appears in the dry-run summary regardless
  of `--strict`.

The detector is heuristic — clean reports are strong evidence,
non-empty reports require operator review. The IPv4 / IPv6 / MAC / FQDN
checks are deterministic; the `IDENTIFIER_BAREWORD` heuristic intentionally
errs toward noise rather than miss a real customer label.

## Module map (v1.2.2)

```
src/veil/
  __init__.py        package version (1.2.2)
  __main__.py        entry point — re-exports cli.main
  cli.py             argparse, obfuscate/deobfuscate commands, exit codes
  ledger.py          Kind, Ref, LedgerEntry, Ledger, COMMON_PARTITION,
                     intern_ipaddr / intern_timestamp / intern_irule_ident
  tokenizer.py       Token, TokKind, tokenize(src)
  diagnostics.py     Diagnostics (shared by scanner + substitute)
  scanner.py         scan(src) / scan_many(...) -> (Ledger, Diagnostics)
                     (drives pass 1 + dispatches pass 1.5 / 1.7 / 1.8 /
                     1.85.* / 1.9 / 1.95 / 2.0 / 2.1 / 2.2 / 2.25
                     before freeze)
  ip_discovery.py    discover_ip_literals (pass 1.5 — bare IP literal
                     interning, with version-field allowlist exclusion)
  description_discovery.py
                     discover_descriptions (pass 1.7 — QSTRING / bareword
                     / braced description redaction + v1.2.1 oauth-claim /
                     oauth-scope extension)
  irule_comment_discovery.py    pass 1.8 — Tcl `#` comments inside `ltm rule` bodies
  remote_role_discovery.py      pass 1.85 — auth remote-role role-info
  snmp_discovery.py             pass 1.85b — sys snmp body
  syslog_discovery.py           pass 1.85c — sys syslog remote-servers
  sshd_discovery.py             pass 1.85d — sys sshd banner-text
  cert_keychain_discovery.py    pass 1.85e — nested cert-key-chain buckets
  client_policy_discovery.py    pass 1.85f — nested client-policy buckets
  username_discovery.py         pass 1.85g — identity / hostname fields → USERNAME
  krb_realm_discovery.py        pass 1.85h / 2.1 — uppercase Kerberos realms
  ldap_filter_discovery.py      pass 1.85i — LDAP filter field
  ad_query_attrname_discovery.py
                                pass 1.85i.1 — AD non-standard query-attrname (v1.2.1, T3A)
  saml_oauth_discovery.py       pass 1.85j — SAML / OAuth identifier fields
  monitor_recv_discovery.py     pass 1.85k — monitor recv field
  monitor_path_discovery.py     pass 1.85k.1 — monitor send / URL-bearing field
                                paths (v1.2.1, T2 / T8) + IPv4-in-QSTRING
                                scan for send / recv (v1.2.2, B5)
  data_group_records_discovery.py
                                pass 1.85l — data-group records buckets
  apm_var_literal_discovery.py  pass 1.85m — APM variable-assign LITERAL pattern
  timestamp_discovery.py        pass 1.85n — creation-time / last-modified-time
                                year-coarsening (v1.2.1, T3B)
  ad_dn_discovery.py            pass 1.9 — AD/LDAP distinguished name extraction
  irule_tcl_literal_discovery.py
                                pass 1.95 / 2.25 — iRule TCL QSTRING shapes (T4)
                                + iRule TCL identifier rewrites (T5) (v1.2.1)
  fqdn_discovery.py             pass 2.0 — internal-FQDN discovery
  apm_session_var_discovery.py  pass 2.2 — APM session.custom.<word> namespace
                                tokenization → SESSION_NS (v1.2.1, T1B)
  substitute.py      substitute(src, ledger, diag), reverse_substitute(...);
                     `_build_substring_render_map` with T7 short-literal
                     filter (v1.2.1)
  answer_file.py     write_answer_file(...), read_answer_file(...),
                     AnswerFileError
  leak_detector.py   scan_leaks(sanitized) -> LeakReport,
                     LeakKind, Leak
  ucs_archive.py     UCS extract-only ingestion (v1.2)
```

## CLI semantics

- **Default is fail-closed.** Any non-empty Diagnostics field aborts
  obfuscation with exit code 1; no sanitized output and no answer file
  written. `--allow-incomplete` is the explicit opt-in to proceed.
- **`--strict`** runs the leak detector over the sanitized output and
  aborts with exit code 5 if any flagged content survived substitution.
- **Crash-safe ordering:** answer file lands on disk before sanitized
  output. A crash mid-pipeline never produces a sanitized file orphaned
  from its decryption key.
- **Passphrase precedence:** `--passphrase-file` > `VEIL_PASSPHRASE` env
  var > interactive prompt (`getpass`). Both non-interactive paths warn
  to stderr. Obfuscate prompts with confirmation; deobfuscate prompts once.
- **stdin/stdout** supported via `-` sentinel for `--input` / `--output`.
  Answer file always a real path.
- **Existing-file protection:** `--output` and `--answer-file` paths that
  already exist abort with exit code 2 unless `--force` is passed.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | fail-closed (diagnostics non-empty, no `--allow-incomplete`) |
| 2 | user / argument error (missing flag, file exists, etc.) |
| 3 | I/O error |
| 4 | decryption failed (wrong passphrase or tampered answer file) |
| 5 | leak detector tripped under `--strict` |

## UCS archive ingestion (`veil.ucs_archive`)

A BIG-IP UCS is a gzipped tarball with hundreds to thousands of
entries — every config + state file the appliance needs to restore
itself. v1.2 added UCS support as an **extract-only multi-file input
source**. We never recreate the archive.

### Threat model

- The CLI's baseline threat model is "engineer's own machine,
  customer data never crosses the wire in cleartext, the encrypted
  answer file is the only artifact that leaves." UCS adds a layer
  but keeps that property — we read the archive locally, extract
  the four allowlisted config-file members, sanitize them, and emit
  text files into `--output-dir`.
- **Nothing else leaves.** Non-allowlisted members are never read,
  never written, never named in output. The 496 MB of certs, keys,
  state DBs, licenses, and `.diffVersions/` snapshots in a real UCS
  pass through the extractor's `for member in tar:` loop without
  ever being opened.
- **No re-pack.** The operator keeps the original UCS, deobfuscates
  the four sanitized text files via the existing N-file flow, and
  if they want closed-loop they manually re-pack into the original
  UCS shape. Re-packing in code would mean the obfuscator wrote a
  binary artifact that mirrors the input's structure — a strictly
  larger trust boundary, and one we've deliberately kept out.

### Allowlist

Three canonical paths inside `config/`, matched by exact string
equality (no globbing, no path resolution, no symlink following):

| Member                          | Required | Typical size |
|---------------------------------|----------|--------------|
| `config/bigip_base.conf`        | yes      | 10s of KB    |
| `config/bigip.conf`             | yes      | 100s of KB to a few MB |
| `config/bigip_user.conf`        | no       | < 1 KB       |

Order is load-bearing: base first so `scan_many` sees the base
file's VLAN / SELF_IP / ROUTE_DOMAIN definitions before the main
file's references need to resolve. Optional members follow in
declared order if present.

`config/bigip_script.conf` is **deliberately excluded** from the
v1.2 allowlist. Its iApp template bodies routinely contain literal
RFC 5737 docs-range IPs (`192.0.2.7`, `192.0.2.10-192.0.2.19`,
`192.0.2.0/24`) inside user-facing example help text. These collide
with VEIL's IP placeholder model — customer IPs are substituted INTO
docs-range IPs (not into symbolic `IPADDR_NNNN` placeholders), and
reverse-substitute cannot distinguish a docs-range IP that was
allocated from a docs-range IP that was already present in the
source. Real-world round-trip breaks at script.conf scale (verified
on the v1.2 integration corpus: 8 lines / 2 bytes lost per 1.5 MB).
The architectural fix — reserve source-literal docs IPs from the
allocation pool before any allocation — is tracked for v1.3 / v2.0.
Operator workaround: hand `bigip_script.conf` to the LLM as a
separate plain-text file if iRule / iApp coverage is needed.

### What's NOT in the allowlist (and why)

- **`.diffVersions/config/...`** — frozen historical snapshots the
  appliance keeps for its own diffing. They contain stale copies of
  the live configs; the operator doesn't need them sanitized
  because they don't leave the appliance via this flow. Skipping
  them keeps the trust surface minimal.
- **`config/bigip.license`** and rotated licenses — non-sensitive,
  irrelevant to LLM analysis.
- **`config/BigDB.dat`** — appliance state database, binary, not a
  config the operator edits.
- **TLS keys / certs** — out of scope by policy. The operator
  should never be uploading those to an LLM regardless.
- **State files under `var/`, `etc/`, `home/`, `root/`, `SPEC-*`** —
  not configs.

### Defensive checks

The allowlist match is by exact-string equality, which already
blocks path traversal in member names — `../etc/passwd` can't equal
`config/bigip.conf`. The `_validate_member_shape` checks are
belt-and-braces for tarballs that ship a canonical-named member
with a malicious shape:

- Refuse symlinks / hardlinks (tar types `2` / `1`) on allowlisted
  members — a symlink with a canonical name could redirect content
  to `/etc/passwd` on extraction.
- Refuse directories on allowlisted member names.
- Refuse `..` segments or absolute / backslash paths even on the
  canonical names (impossible by allowlist equality, but the check
  exists so a future allowlist change doesn't silently weaken the
  contract).
- Per-member 50 MiB cap (`MAX_CONFIG_MEMBER_BYTES`) refuses
  oversized members. Real config files top out around 2 MB.
- Strict UTF-8 decoding — silent mangling of non-UTF-8 bytes would
  defeat round-trip exactness.

### CLI integration

`veil obfuscate --input device.ucs --output-dir sanitized/
--answer-file device.answers` auto-detects the UCS (by `.ucs`
extension + gzip magic), expands it into N virtual sources, and
runs them through the existing multi-file pipeline. UCS input
rejects:

- being mixed with plain `--input` files
- multiple UCS in one invocation
- stdin alongside UCS
- `--output` (UCS always produces N files; must use `--output-dir`)
- missing `--output-dir`
- `.ucs` extension with non-gzip content (renamed-plaintext mistake)

Deobfuscate is unchanged. The operator deobfuscates the four
sanitized text files via the standard N-file flow against the
recorded `sources` list in the answer file.

## Known gaps (deferred to follow-up PRs)

- **CLI wiring + answer file** — landed in v0.0.1.
- **Leak detector + `--strict`** — landed in v0.0.2.
- **Bare IP literal substitution in body context** — landed in v0.0.3.
- **QSTRING + bareword description redaction** — landed in v0.0.4.
- **LTM profile kind expansion** with factory built-in exemption —
  landed in v0.0.5.
- **GTM family kinds** (gtm pool / wideip / server / datacenter) —
  landed in v0.0.6. `gtm topology` / `gtm region` deferred.
- **LTM extras kinds** (data-group / snat / snatpool / virtual-address)
  + shadowed-duplicate orphan suppression — landed in v0.0.7.
- **Net family + GTM region** (vlan / route-domain / self / trunk /
  gtm region) — landed in v0.0.8. `net interface` and `gtm topology`
  deferred (unusual shapes — interface has no /partition prefix;
  topology has no path token at all).
- **APM + security firewall** (apm policy / profile, security firewall
  policy / rule-list / address-list / port-list) — landed in v0.0.9.
  `apm aaa/sso/acl` and `security dos` deferred.
- **Braced descriptions** — landed in v0.0.10. Full `{...}` span stored
  as the ledger original (including braces and inner whitespace) so
  reverse restores byte-exactly. Forward emit uses the QSTRING form
  (`description "DESC_NNNN"`) regardless of input form.
- **Tcl `#` comment redaction inside `ltm rule` bodies** — landed in
  v0.0.11 via pass-1.8 (`irule_comment_discovery`) + `Kind.IRULE_COMMENT`.
  Top-level COMMENT tokens (`#TMSH-VERSION:` etc.) are NOT discovered —
  universal BIG-IP signal. Dedup is by full COMMENT token text
  (including the leading `#`). Pass-2 emits `# IRULE_COMMENT_NNNN`,
  the tokenizer re-tokenizes this back to a single COMMENT token, and
  the reverse pass restores the original via a dedicated
  `comment_reverse_map`. Tcl `\<newline>` line-continuation inside
  comments is NOT folded — each physical line becomes its own
  placeholder; folding is a future refinement.
- **Braced description form** — v0.0.5 follow-up (needs per-reference
  inner-brace whitespace metadata for byte-exact round-trip).
- **Bracketed IPv6 form `[fc00::1]:80`** — v0.0.4 follow-up.
- **Larger IPv4 docs pool** for configs exceeding the RFC 5737 768-host
  cap — v0.0.4 follow-up.
- **`description` aggressive redaction.** Pass 2 emits descriptions
  verbatim plus an `unredacted_description` diagnostic. A 'pass 1.5:
  free-text discovery' PR will mint `DESC_NNNN` placeholders.
- **Tcl-string-aware substring substitution inside iRule bodies** —
  landed in v0.0.12. Pass-2 tracks `ltm rule /path { ... }` body entry
  via the same depth state machine as `irule_comment_discovery`;
  QSTRINGs inside an iRule body have their content scanned for
  substrings matching any non-DESC, non-IRULE_COMMENT ledger original,
  with each match substituted in place to the rendered placeholder.
  Word-boundary check on both sides prevents false matches (so
  `foo_pool_extra` stays verbatim when `foo_pool` is a ledger original).
  Reverse pass tracks the same state machine and substring-replaces
  rendered placeholders back to originals. Out-of-scope QSTRINGs
  (monitor send-strings, data-group records, anything else outside an
  `ltm rule` body) keep the legacy verbatim emit +
  `qstring_contains_identifier` diagnostic. Tcl `#` comments inside
  rule bodies are redacted via v0.0.11's `Kind.IRULE_COMMENT` path
  (see above).
- **AD / LDAP distinguished-name obfuscation** — landed in v0.0.13
  via pass-1.9 (`ad_dn_discovery`) + `Kind.AD_GROUP_DN`. Regex scans
  every QSTRING for the RFC 4514 DN shape (one CN= leading RDN, at
  least one DC= component) and interns each unique match. Pass-2
  substring-substitutes AD_GROUP_DN entries inside every QSTRING
  globally (both inside `ltm rule` bodies — via the same combined map
  v0.0.12 already uses — and outside, where prior to v0.0.13 only the
  `qstring_contains_identifier` diagnostic fired). Word-boundary
  protection applies on both sides. Descriptions skip pass-1.9 (already
  redacted by DESC) to avoid orphan AD_GROUP_DN entries. Real-world
  coverage validated against EXAMPLE_CORPUS: 10 distinct DNs interned, 0
  surviving DN substrings in sanitized output, byte-exact round-trip.
- **`auth remote-role role-info` header paths** — deferred to v0.0.14.
  The role bucket names (`/Common/F5_Admins`,
  `/Common/Domain_Admins`, etc.) are customer-defined identifiers that
  currently fall under the `Kind.UNKNOWN` best-effort path (because
  `auth remote-role` lands in `_record_unknown_top_level`). Real
  configs leak the bucket leaf via path-shape inside the `auth
  remote-role role-info` body. Needs either a new top-level kind
  (`Kind.REMOTE_ROLE`) or a body-walker that registers each role-info
  child path.
- **Profile, SNAT, data-group, ASM, GTM, VLAN, cert, route-domain
  kinds.** Each unknown top-level block surfaces as
  `unknown_top_level` diagnostic; pass-2 callers fail closed.
- **Folder semantics.** `/Common/folder/sub/leaf` collapses folder
  into the leaf placeholder; folder-as-own-kind (FOLDER_NNNN) deferred.
- **Member-port suffix handling.** ~~`/Common/web1:80` does not match
  the node `/Common/web1` (different bareword).~~ Closed by PR #6 via
  longest-prefix match with non-word boundary detection.
- **Unknown-block path leaks.** Closed by PR #6 — top-level blocks of
  unrecognised kinds (profiles, GTM, ASM, etc.) get their header path
  registered as `Kind.UNKNOWN` so pass-2 substitutes it. Best-effort
  only: UNK paths can still leak via substring inside longer
  non-header barewords. Safety-critical kinds
  (POOL/VS/NODE/MON/IRULE) remain strictly enforced.
- **`bigip_base.conf` multi-file two-pass** — landed in v1.2.
- **UCS archive ingestion** — landed in v1.2. Extract-only by
  design; see "UCS archive ingestion" section above for the
  threat model and allowlist rationale.
- **v1.2 leak-coverage hardening** — landed in v1.2 (Phases 1–4 of
  the leak fix plan, 19 finding-groups). Adds 26 new Kinds:
  - **Unknown-block body walkers** — `sys snmp` (5 kinds), `sys
    syslog`, `sys sshd` banner, `cert-key-chain` nested bucket,
    `client-policy` nested bucket.
  - **Cross-cutting field walkers** — identity/hostname
    (`admin-name`, `basic-auth-username`, `user`, `account-name`,
    `server-name` → USERNAME), Kerberos realm (`realm` upper-case
    → KRB_REALM), LDAP base-DN bareword (extends AD_GROUP_DN),
    LDAP filter, SAML/OAuth identifiers (entity-id, sso-uri,
    slo-uri, slo-response-uri, audience, issuer, key-id),
    description-family (caption, service-name folded into DESC),
    monitor recv, data-group records.
  - **Substring sub fixes** — IP-walker version-field exclusion
    (pass-1.5 skips `version 17.5.1.5` shape), filestore
    colon-separator variant (substring sub now catches
    `:Common:<leaf>_<index>_<index>` filestore references).
  - **Orphan check** — substring-shadow exemption so the FQDN
    walker's inner-FQDN entries shadowed by longer SAML/OAuth
    entries don't trip the cross-reference integrity assertion.
- **v1.2 documented gaps (status update from the v1.2.1 cycle):**
  - **iRule `varname` / variable name customer leak** —
    PARTIALLY CLOSED in v1.2.1 by T5 / `IRULE_IDENT` for the case
    where the vendor word also appears in a `session.custom.<vendor>.*`
    anchor (T1B / `SESSION_NS` interns the word, T5 rewrites every
    identifier that embeds it). Pure `static::<vendor>_*` variables
    whose vendor never appears in a session-namespace anchor still
    leak — tracked as a v1.3 gap below.
  - **Public-TLD FQDNs outside data-group records context.** The
    global FQDN walker still only catches internal-suffix FQDNs
    by design. v1.2.1's T4 (`irule_tcl_literal_discovery`) added
    permissive-FQDN coverage **inside iRule TCL QSTRINGs** (catches
    SaaS tenant subdomains like `api-xxxxxxxx.duosecurity.com`).
    Public-TLD FQDNs outside cert-path / SAML / iRule-TCL contexts
    still need operator review.
  - **Tcl expression literal customer-domain leak.** CLOSED for the
    `{LITERAL}` pattern shape by v1.2's `APM_VAR_LITERAL` walker.
    Free-text expression bodies (`expression "[mcget {...}]"`)
    without a recognized shape still pass through.
  - **`basic-auth-realm` bareword.** CLOSED in v1.2 — folded into
    the USERNAME walker's allowlist.

- **v1.2.1 documented gaps (NOT auto-redacted, operator review
  required, deferred to v1.3):**
  - **Vendor names in TCL identifiers without a `session.*`
    anchor.** T5 catches embedded vendor words only when they're
    already interned by T1B's `SESSION_NS` walker (via
    `session.custom.<vendor>.*` references). Pure `static::<vendor>_*`
    variables whose vendor never appears in a session-namespace
    anchor (e.g. `static::<vendor>_302_307_replacement_debug`)
    survive in v1.2.1. v1.3 candidate fixes: (A) hand-curated
    vendor-word list, or (B) extend T5 to harvest candidate vendor
    words from partition names / comment bodies / data-group key
    prefixes elsewhere in the config.
  - **Hardcoded TCL string literals / secrets in `proc` returns.**
    High-entropy alphanumeric tokens (OAuth `client_id` shapes),
    magic SAML markers (e.g. literal `"Canary"` strings), and other
    customer-specific hardcoded literals inside iRule `proc` bodies
    aren't caught by T4's shape detectors (not FQDN / IP / NETBIOS /
    email / UNC). New `Kind.IRULE_SECRET` candidate; walker design
    pending — likely a combination of field-gated scanning (`set
    <varname> "<literal>"` where varname matches `*_secret` /
    `*_token` / `*_key` / `*_id` / `*_password` patterns) plus an
    entropy-threshold catch-all for high-entropy strings of length
    > 12.
  - **`DATA_GROUP_RECORD` substring sub over-fires on common
    English / geographic terms.** Symptom: `time-zone
    DATA_GROUP_RECORD_0006/Central` and similar — the data-group
    records walker captured `America` as a record key, substring
    sub then fires on the unrelated `America` in the `time-zone`
    field. Round-trip preserved (reverse map restores), but
    sanitized output is structurally weird. Fix is at the walker
    level (skip-list of common English / geographic / operational
    terms — `America`, `Central`, `Eastern`, `Western`, `Pacific`,
    `Mountain`, `Atlantic`, `Indian`, `Africa`, `Asia`, `Europe`,
    `Australia`, `Antarctica`, ...) — `substitute.py` T7 path is
    too coarse for this class.
  - **Citrix product-paths in factory vs user-named data-groups.**
    v1.2 / v1.2.1 final-round subagent flagged `/Citrix/Store/PNAgent/...`
    records. Verdict depends on whether the parent data-group name is
    `/Common/__Citrix_*` factory-style (dismiss) or user-named
    (escalate). Triage in v1.3.

- **B5 CLOSED in v1.2.2 (2026-06-20).** Post-v1.2.1 red-team found
  `192.168.100.1` surviving inside a monitor `send` QSTRING:
  `send "GET / HTTP/1.1\r\nHost: 192.168.100.1\r\nConnection: Close\r\n\r\n"`.
  Cause: T2 `monitor_path_discovery` parsed the URL path but didn't
  scan QSTRING content for IPs; the strict pass-1.5 IP walker only
  scans bare WORD tokens. Fix: added `_intern_ipv4_in_qstring` to
  `monitor_path_discovery`, gated on `send` / `recv` field names.
  IPv4 literals (with optional CIDR) intern via
  `Ledger.intern_ipaddr` → RFC 5737 docs-range substitution. CIDR
  mask preserved literal. Verified on integration corpus.

- **B6 DISMISSED (2026-06-20).** Post-release red-team flagged 14
  public-TLD vendor FQDNs in `net dns-resolver` forward-zones and
  `security bot-defense signature` factory rules. Full triage:
  11 are F5 stock bot-detection signatures for legitimate search-
  engine crawlers (Google / Yahoo / Bing / Yandex / etc.) with
  `factory-rule $M$...` + `user-defined false` attributes —
  dismissable per the existing v1.2 bot-defense-factory rule;
  3 are F5 stock `/Common/f5-aws-dns` resolver entries
  (`amazonaws.com`, `idservice.net`, `shpapi.com`). The other
  dns-resolver block in the corpus is user-configured and its
  internal FQDN tokenizes correctly via the existing FQDN walker.
  Walker implication: any future `dns-resolver forward-zone` walker
  MUST exempt `f5-` prefixed resolver names (and any other F5-stock
  prefixes: `default-*`, `_sys_*`, `__*`) to avoid breaking stock
  data. Hold the walker until a corpus surfaces a user-created
  public-TLD forward-zone case.
- **Personal-use Docker + FastAPI web wrapper** (v1.3). See threat
  model below for why this is distinct from a hardened service.
- **Persistent cross-run identifier map** (v2.0).
- **Hardened multi-user web service** (v2.1 / v3.0). Shares design
  surface with v2.0.

## Web wrapper threat model (v1.3 and v2.1+)

The CLI's threat model is "engineer's own machine, customer data
never crosses the network in cleartext, encrypted answer file is the
only artifact that leaves." A network service in front of the
obfuscator fundamentally inverts this — customer configs cross the
wire, sit in server memory or disk briefly, and the passphrase has
to be communicated to the server somehow. Two distinct deployment
shapes:

### v1.3 — personal-use only

Hard rules — break ANY of these and you're in v2.1 territory:

- **Single-user, single-tenant.** Operator is the only consumer.
- **Private network only.** Bound to a non-internet-reachable
  interface (e.g. 10.0.0.x homelab subnet). No port-forward, no
  reverse proxy to the public internet, no Tailscale exit node, no
  Cloudflare Tunnel. The Dockerfile and compose file MUST default to
  binding `127.0.0.1` or a private bridge — never `0.0.0.0` on a
  public NIC.
- **No auth, by design.** Auth implies multi-user; multi-user implies
  v2.1 hardening. Don't bolt auth onto the v1.3 image — it gives a
  false sense of security.
- **RAM-only processing.** Configs are read into memory, processed,
  and the response is streamed back. No disk persistence of input,
  intermediate, or output state. The encrypted answer file is built
  in memory and returned with the sanitized output in the same
  response.
- **No logging of payload content.** Logs may contain HTTP status,
  byte counts, durations — never sanitized text, never originals,
  never anything resembling config content. Surface the leak detector
  summary as a structured count, never a list with snippets.
- **Threat model is "anyone with network access to the homelab".**
  That's the operator + family + anyone with the homelab VPN. If that
  set is acceptable for the operator's own customer data, v1.3 is
  fine. If teammates or other engineers might want access — v2.1.

### v2.1 / v3.0 — hardened multi-user service

The piece that turns this from "engineer's-own toy" into a real
product. Adds (non-exhaustive):

- mTLS or OAuth (SSO via existing identity provider).
- HTTPS only, HSTS, modern TLS profile.
- Per-user audit log of WHEN configs were processed (not WHAT —
  never log payload content) and WHO downloaded the answer file.
- Hard ephemerality: server process should ideally not have
  filesystem write access to anywhere outside `/tmp` mounted as
  tmpfs; process exit MUST clear memory.
- Rate limiting + payload size caps.
- A documented secret-storage model for the encryption keys (if the
  server retains any cross-session state, which v2.0 will require).
- Threat model write-up that names specific adversaries: malicious
  authenticated user, network MITM, server compromise, side-channel,
  prompt-injection-via-config-content if the AI uses sanitized output
  as input to anything that re-renders.

The two deployment shapes share NO code beyond the underlying veil
library API. The v1.3 image MUST NOT be the foundation for v2.1 —
write v2.1 from scratch.
