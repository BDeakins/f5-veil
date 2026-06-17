# f5-veil

F5 BIG-IP config obfuscator / de-obfuscator — sanitize customer configs
for safe AI analysis, then restore identifiers byte-exactly after the
AI is done.

## Status

**v1.2** — production-shaped against real BIG-IP configurations.

Covers ~50 object kinds across LTM, GTM, net, APM, sys, security
firewall, and SAML/OAuth/Kerberos/SNMP/syslog/SSHD bodies. Bare
IPv4 / IPv6 literals substituted to RFC 5737 / RFC 3849 docs ranges
with `/24` and `/64` source-subnet preservation. All three
description body forms (QSTRING, bareword, braced) plus `caption`
and `service-name` fields redacted. Tcl `#` comments inside `ltm
rule` bodies redacted. Identifier substring substitution inside
every QSTRING **and every BAREWORD** (catches monitor send/recv
strings, APM policy expressions, bot-defense signatures, URL-shaped
barewords, IP ranges, F5 filestore colon-separator paths
(`:Common:<leaf>_<index>_<index>`), public-TLD FQDN leafs in
source-paths). LDAP / AD distinguished names embedded in any
QSTRING **and** as bareword `base-dn` / `search-base-dn` values.
Kerberos realms (uppercase form, public-TLD support). SAML / OAuth
identifier fields (entity-id, sso-uri, slo-uri, audience, issuer,
key-id) as dedicated kinds — non-FQDN-shaped opaque values are
caught. APM `expression "return {LITERAL}"` Tcl-literal patterns
catch hard-coded session-variable values (domains, usernames,
occasionally credentials). Multi-file two-pass ingestion
(`bigip_base.conf` + `bigip.conf`). UCS archive ingestion
(extract-only). AES-256-GCM-encrypted answer file with scrypt KDF.
Round-trip is byte-exact for every shape the parser covers.

Real-corpus canary count for the v1.2 integration pair went from
40 → 0 across the v1.2 leak-coverage cycle (19 finding-groups
discovered via manual inspection plus post-sign-off follow-ups).
660+ tests pass with byte-exact round-trip preserved.

Documented gaps (see [docs/architecture.md](docs/architecture.md)
"Known gaps"): iRule `varname` customer leaks, public-TLD FQDNs
outside cert/path/SAML contexts, free-text Tcl expression literals
without recognised shape.

## The Problem

F5 engineers want to use AI tools (Claude, ChatGPT, Copilot, etc.) to
analyze configurations, write iRules, and troubleshoot issues. But
customer configurations contain identifying information — IPs,
hostnames, pool names, virtual server names, monitor names, AD group
DNs, partition labels — that cannot legally or contractually be sent
to a third-party AI under most customer NDAs and employer policies.
The penalty for leaking customer data to an AI is often immediate
termination.

## What VEIL does

```
veil obfuscate   →   sanitized.conf + answers.enc (encrypted)
                 →   safe to paste into AI

[engineer collaborates with AI on the sanitized config]

veil deobfuscate →   restored.conf (real identifiers reinstated,
                     including in any new content the AI generated)
```

Every customer-identifying value gets a typed placeholder
(`POOL_0001`, `VS_0001`, `NODE_0001`, `IRULE_0001`, `DESC_0001`,
`AD_GROUP_DN_0001`, `SAML_ENTITY_ID_0001`, `SNMP_COMMUNITY_SECRET_0001`,
`SSHD_BANNER_0001`, `USERNAME_0001`, `APM_VAR_LITERAL_0001`, etc.),
the original bytes go into an encrypted answer file, and the
de-obfuscator restores everything byte-exactly — including any
placeholder text the AI produced in new content it wrote.

## Safety warnings

> **VEIL is a safety net, not a guarantee.**
> A parser miss = customer data leaked to an LLM = potential
> career-ending incident. Always review the sanitized output before
> sending it anywhere.

- Read the sanitized file end-to-end before sending it to AI.
- The leak detector flags common patterns (RFC1918 IPs, `.local` /
  `.corp` / `.lan` / `.internal` domains, MAC addresses,
  identifier-shaped barewords, paths with non-safe partitions). It is
  heuristic — a clean run is strong evidence, not proof.
- Use `--strict` mode to abort on any leak-detector warning.
- Use `--allow-incomplete` only when you understand exactly which kinds
  the parser doesn't yet recognise.
- Protect the answer file as you would a UCS archive. Anyone with the
  file and the passphrase can recover the original configuration.
- Never commit `*.answers.enc` or `*.sanitized.conf` to a repo. The
  shipped `.gitignore` blocks both — keep it that way.
- VEIL does not attempt to obfuscate inside binary blobs, base64-encoded
  archives, or compiled artifacts. Strip those before obfuscation.

## Installation

```bash
pip install f5-veil
```

Or from source:

```bash
git clone https://github.com/BDeakins/f5-veil
cd f5-veil
pip install -e .
```

Requires Python 3.10 or newer.

## Usage

```bash
# Obfuscate a single bigip.conf
veil obfuscate --input bigip.conf \
               --output bigip.sanitized.conf \
               --answer-file bigip.answers.enc

# De-obfuscate (AI may have introduced new content; placeholders inside
# new content are restored too)
veil deobfuscate --input bigip.modified.conf \
                 --output bigip.restored.conf \
                 --answer-file bigip.answers.enc

# Dry-run obfuscation — report what would change, write nothing
veil obfuscate --input bigip.conf --dry-run

# Strict mode — abort if the leak detector finds anything suspicious
veil obfuscate --input bigip.conf --strict ...

# Allow-incomplete mode — proceed even with unhandled top-level blocks
# (e.g. ltm dns, security dos). Use only when you've reviewed the
# diagnostics and understand the residual leak surface.
veil obfuscate --input bigip.conf --allow-incomplete ...
```

### Multi-file mode (`bigip_base.conf` + `bigip.conf`)

```bash
# Pass both files; base file first so its objects (VLANs, self-IPs,
# route domains) land in the ledger before the main file's references
# need to resolve. Output goes to a directory keyed by basename.
veil obfuscate --input bigip_base.conf \
               --input bigip.conf \
               --output-dir sanitized/ \
               --answer-file device.answers.enc

veil deobfuscate --input sanitized/bigip_base.conf \
                 --input sanitized/bigip.conf \
                 --output-dir restored/ \
                 --answer-file device.answers.enc
```

`--input` order on the deobfuscate side must match the order recorded
in the answer file at obfuscation time. Reordering is a hard error,
not a silent miscorrelation.

### UCS archive mode (`device.ucs`)

```bash
# Hand VEIL the UCS directly. It extracts the allowlisted config-file
# members (config/bigip_base.conf, config/bigip.conf, and the
# optional config/bigip_user.conf), obfuscates each, and writes them
# as separate text files into --output-dir. Everything else in the
# UCS (bigip_script.conf, certs, keys, licenses, binaries, state
# files, .diffVersions snapshots) is ignored — never read, never
# written.
veil obfuscate --input device.ucs \
               --output-dir sanitized/ \
               --answer-file device.answers.enc

# Deobfuscate the sanitized text files via the standard multi-file
# flow. VEIL does NOT recreate the UCS — if you need a closed-loop
# UCS for restore, re-pack the restored files into the original
# archive yourself (e.g. with tar).
veil deobfuscate --input sanitized/bigip_base.conf \
                 --input sanitized/bigip.conf \
                 --input sanitized/bigip_user.conf \
                 --output-dir restored/ \
                 --answer-file device.answers.enc
```

**Note on `bigip_script.conf`:** the file containing iRules and
iApp templates is intentionally NOT in the v1.2 UCS allowlist —
its iApp template bodies contain literal RFC 5737 docs-range IPs
in user-facing help text that collide with VEIL's IP placeholder
model. See `docs/architecture.md` ("UCS archive ingestion") for the
threat model, allowlist rationale, and the architectural fix
planned for v1.3 / v2.0. If you need iRule / iApp coverage today,
hand `bigip_script.conf` to the LLM as a separate plain-text file.

Exit codes: 0 success, 2 CLI usage error, 3 input not readable, 4
diagnostics non-empty without `--allow-incomplete`, 5 leak detector
tripped under `--strict`.

## Identifier scope

**Obfuscated by VEIL (v1.2):**

- **LTM:** pool, virtual server, node, monitor, iRule, partition,
  profile (custom — built-ins like `/Common/http` pass through as
  universal BIG-IP signal), data-group name, data-group **records**
  (operator-chosen lookup keys, even public-TLD ones), SNAT, SNAT
  pool, virtual-address
- **GTM:** pool, wide-IP, server, datacenter, region
- **Net:** VLAN, route-domain, self-IP, trunk
- **APM:** policy, profile, `cert-key-chain` and `client-policy`
  nested bucket names, `expression "return {LITERAL}"` Tcl literals
  in `variable-assign` blocks
- **SAML / OAuth:** entity-id, sso-uri, single-logout-uri,
  single-logout-response-uri, audience, issuer, key-id — dedicated
  kinds so non-FQDN-shaped opaque values are caught (the FQDN
  walker alone wouldn't catch URN entity-IDs or public-TLD URLs)
- **Identity / field walkers:** `admin-name`, `basic-auth-username`,
  `basic-auth-realm`, `user`, `account-name`, `server-name` →
  `USERNAME`; LDAP `filter` field; LDAP `base-dn` / `search-base-dn`
  bareword DC=...,DC=... shapes
- **Sys family:** `sys snmp` body (community / trap bucket headers,
  plaintext community strings, `sys-contact`, `sys-location`);
  `sys syslog` remote-server bucket headers; `sys sshd` banner
  text (multi-line QSTRING covered); `auth remote-role role-info`
  bucket headers
- **Kerberos:** uppercase realm values (`ACME.CORP`, public TLDs
  included — the FQDN walker by design only catches internal-suffix
  realms)
- **Security firewall:** policy, rule-list, address-list, port-list
- **Network literals:** bare IPv4 / IPv6 (substituted into RFC 5737 /
  RFC 3849 docs ranges, preserving source `/24` and `/64` structure
  first-seen-first-allocated); IP-walker skips version-field values
  (`version 17.5.1.5` no longer gets substituted as an IP)
- **Free-text:**
  - `description` / `caption` / `service-name` bodies — QSTRING,
    bareword, and braced forms all redacted to `DESC_NNNN`
  - Tcl `#` comments inside `ltm rule` bodies — redacted to
    `IRULE_COMMENT_NNNN`
  - LDAP / AD distinguished names (`CN=...,DC=...` AND
    `OU=...,DC=...`) anywhere inside any QSTRING — redacted to
    `AD_GROUP_DN_NNNN`
  - Internal-FQDN discovery (`*.local`, `*.corp`, `*.lan`,
    `*.internal`, `*.intranet`, `*.home.arpa`, `*.private`) inside
    any WORD or QSTRING — redacted to `FQDN_NNNN`
  - Monitor `recv` strings (HTML titles, product names) — redacted
    to `MONITOR_RECV_NNNN`
  - F5 filestore colon-separator paths
    (`:Common:<leaf>_<index>_<index>`) — caught via substring sub
    variant on path-shape entries
  - Any other ledger identifier appearing as a substring inside any
    QSTRING / BAREWORD (monitor send-strings, APM policy
    expressions, bot-defense signatures, URL-shaped barewords like
    `https://10.0.0.42/path`, IP ranges like `10.0.0.1-10.0.0.50`)
    — substring-substituted in place with word-boundary protection
  - Multi-file mode: `bigip_base.conf` + `bigip.conf` ingest as a
    shared ledger so base-file objects substitute correctly when
    referenced from the main file
  - UCS archive mode: extract-only, allowlists `config/bigip_base.conf`,
    `config/bigip.conf`, `config/bigip_user.conf`

**Documented gaps (operator review required):**

- iRule `varname` customer-name leaks — renaming would break
  positional Tcl refs, so VEIL does not auto-redact
- Public-TLD FQDNs outside the dedicated walker / cert-path /
  source-path contexts — the global FQDN walker only catches
  internal-suffix TLDs to avoid false positives on legitimate
  public DNS references
- Free-text Tcl expression literals (`expression "[mcget {...}]"`)
  without a recognised shape
- Persistent cross-run identifier map (deferred to v2.0)
- Folder-as-own-kind (`/Common/folder/sub/leaf` currently collapses
  folder into the leaf placeholder) — v1.3+

## Roadmap

- **v1.0** — `bigip.conf` only. Shipped.
- **v1.1** — BAREWORD infix substring substitution (catches URLs,
  IP ranges, compound barewords). Shipped.
- **v1.2** — `bigip_base.conf` multi-file two-pass discovery, UCS
  archive ingestion (extract-only), `auth remote-role role-info`
  bucket-path discovery, plus a 19-finding-group leak-coverage
  hardening cycle driven by real-corpus manual inspection:
  sys snmp / sys syslog / sys sshd body walkers, cert-key-chain and
  client-policy nested bucket walkers, identity / Kerberos realm /
  LDAP filter / SAML+OAuth / data-group-record / monitor recv /
  APM expression literal field walkers, filestore colon-separator
  substring sub, FQDN-shaped leaf substring sub. Real-corpus canary
  count for the integration pair: 40 → 0. Shipped.
- **v1.3** — Personal-use Docker image + thin FastAPI wrapper around
  the CLI (paste config in browser, get sanitized output and encrypted
  answer file out). RAM-only processing, no auth, **not for internet
  exposure**. CLI remains the canonical distribution. See the threat
  model in [docs/architecture.md](docs/architecture.md).
- **v2.0** — Persistent cross-run identifier map (same source
  identifier → same placeholder across runs, for ongoing engagements).
- **v2.1 / v3.0** — Hardened multi-user web service (auth, HTTPS,
  audit logging, hard ephemerality guarantees, rate limiting). Shares
  design surface with the v2.0 persistent map (auth + secret storage).

## License

MIT — see [LICENSE](LICENSE).

A personal statement of intent regarding the audience of this work is in
[DISCLAIMER.md](DISCLAIMER.md). It is not a license term.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting policy.
