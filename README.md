# f5-veil

F5 BIG-IP config obfuscator / de-obfuscator — sanitize customer configs
for safe AI analysis, then restore identifiers byte-exactly after the
AI is done.

## Status

**v1.0** — production-shaped against real BIG-IP configurations.

Covers ~25 object kinds across LTM, GTM, net, APM, and security
firewall; bare IPv4 / IPv6 literals (substituted to RFC 5737 / RFC 3849
documentation ranges with `/24` and `/64` source-subnet preservation);
all three description body forms (QSTRING, bareword, and braced); Tcl
`#` comments inside `ltm rule` bodies; identifier substring
substitution inside every QSTRING (catches monitor send-strings, APM
policy expressions, bot-defense signatures, etc.); and LDAP / AD
distinguished names embedded in any QSTRING. AES-256-GCM-encrypted
answer file with scrypt KDF. Round-trip is byte-exact for every shape
the parser covers.

Deferred to v1.1+ (see [docs/architecture.md](docs/architecture.md)):
`bigip_base.conf` multi-file ingestion, UCS archive ingestion,
internal-FQDN discovery, `gtm topology`, `net interface`, `security
dos`, `apm aaa`/`sso`/`acl`, full ASM, persistent cross-run identifier
map.

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
`AD_GROUP_DN_0001`, etc.), the original bytes go into an encrypted
answer file, and the de-obfuscator restores everything byte-exactly —
including any placeholder text the AI produced in new content it
wrote.

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
pip install f5-veil   # not yet published
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

Exit codes: 0 success, 2 CLI usage error, 3 input not readable, 4
diagnostics non-empty without `--allow-incomplete`, 5 leak detector
tripped under `--strict`.

## Identifier scope

**Obfuscated by VEIL (v1.0):**

- **LTM:** pool, virtual server, node, monitor, iRule, partition,
  profile (custom — built-ins like `/Common/http` pass through as
  universal BIG-IP signal), data-group name, SNAT, SNAT pool,
  virtual-address
- **GTM:** pool, wide-IP, server, datacenter, region
- **Net:** VLAN, route-domain, self-IP, trunk
- **APM:** policy, profile
- **Security firewall:** policy, rule-list, address-list, port-list
- **Network literals:** bare IPv4 / IPv6 (substituted into RFC 5737 /
  RFC 3849 docs ranges, preserving source `/24` and `/64` structure
  first-seen-first-allocated)
- **Free-text:**
  - `description` bodies — QSTRING, bareword, and braced forms all
    redacted to `DESC_NNNN`
  - Tcl `#` comments inside `ltm rule` bodies — redacted to
    `IRULE_COMMENT_NNNN`
  - LDAP / AD distinguished names (`CN=...,DC=...`) anywhere inside
    any QSTRING — redacted to `AD_GROUP_DN_NNNN`
  - Any other ledger identifier appearing as a substring inside any
    QSTRING (monitor send-strings, APM policy expressions, bot-defense
    signatures, data-group records, etc.) — substring-substituted in
    place with word-boundary protection

**Not yet handled (v1.1+):**

- Multi-file ingestion (`bigip_base.conf`) — v1.1
- UCS archive ingestion — v1.2
- Persistent cross-run identifier map — v2.0
- `gtm topology`, `net interface`, `security dos`, `apm aaa`/`sso`/`acl`,
  full ASM policy coverage — v1.1+
- `auth remote-role role-info` header paths (the customer-defined
  role-bucket names) — v1.1+
- Internal-FQDN discovery (`*.local`, `*.corp`, etc. free-text) — v1.1+
- BAREWORD substring substitution (catches IPs embedded in compound
  barewords like `application-uri https://10.0.0.42/path`) — v1.1+
- Folder-as-own-kind (`/Common/folder/sub/leaf` currently collapses
  the folder into the leaf placeholder) — v1.1+

## Roadmap

- **v1.0** — `bigip.conf` only. The scope above.
- **v1.1** — `bigip_base.conf` multi-file two-pass discovery; selected
  v1.1+ kinds from the list above.
- **v1.2** — UCS archive ingestion (tar.gz extract and recurse).
- **v2.0** — Persistent cross-run identifier map (same source identifier
  → same placeholder across runs, for ongoing engagements).

## License

**MIT-Modified — source-available with a named-party exclusion.**

This is NOT OSI-approved open source. See [LICENSE](LICENSE) for the
full text. The license is legally valid and enforceable; it simply does
not meet the OSI Open Source Definition (clause 5: no discrimination
against persons or groups).

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting policy.
