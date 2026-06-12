# f5-veil

F5 BIG-IP config obfuscator/de-obfuscator — sanitize customer configs for safe AI analysis.

## Status

v0.0.1 — tracer-bullet CLI functional. Supported objects: `ltm pool`,
`ltm virtual`, `ltm node`, `ltm monitor <subtype>`, `ltm rule`,
partition paths. Full LTM coverage, GTM, ASM, profiles, certs, and the
leak detector are next. See [docs/architecture.md](docs/architecture.md).

## The Problem

F5 engineers want to use AI tools (Claude, ChatGPT, Copilot, etc.) to analyze
configurations, write iRules, and troubleshoot issues. But customer
configurations contain identifying information — IPs, hostnames, pool names,
virtual server names, monitor names, certificate CNs, ASM policy names —
that cannot legally or contractually be sent to a third-party AI under most
customer NDAs and employer policies. The penalty for leaking customer data
to an AI is often immediate termination.

## What VEIL Does

```
veil obfuscate   →   sanitized.conf + answers.enc (encrypted)
                 →   safe to paste into AI

[engineer collaborates with AI on the sanitized config]

veil deobfuscate →   restored.conf (real identifiers reinstated,
                     including in any new content the AI generated)
```

VEIL replaces every customer-identifying value in a BIG-IP configuration
with a typed placeholder (`POOL_001`, `VS_001`, `NODE_001`, `MON_001`,
`IRULE_001`, etc.), storing the originals in an encrypted answer file.
After working with the AI, the de-obfuscator restores all identifiers —
including any placeholders that appear in new content the AI produced.

## Safety Warnings

> **VEIL is a safety net, not a guarantee.**
> A parser miss = customer data leaked to an LLM = career-ending incident.
> Always review the sanitized output before sending it anywhere.

- Read the sanitized file end-to-end before sending it to AI.
- The leak detector flags common patterns (RFC1918 IPs, `.local` /
  `.corp` / `.lan` / `.internal` domains, MAC addresses, identifier-shaped
  unknowns). It cannot catch every pattern.
- Use `--strict` mode to abort on any leak-detector warning.
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
```

## Roadmap

- **v1.0** — `bigip.conf` only. Core LTM objects, AES-256-GCM answer
  file, obfuscate / deobfuscate, leak detector.
- **v1.1** — `bigip_base.conf` support (multi-file two-pass discovery).
- **v1.2** — UCS archive ingestion (tar.gz extract and recurse).
- **v2.0** — Persistent cross-run identifier map (same source identifier
  → same placeholder across runs, for ongoing engagements).

## Identifier Scope

Obfuscated by VEIL:

- **LTM:** pool, virtual server, node, monitor, profile, iRule, partition
  and folder paths, SNAT pool, data-group name and values, ASM policy
  name, VLAN, self-IP, float IP, gateway, route domain, certificate CN
  and SAN, certificate and key file content
- **GTM:** GTM pool, GTM data center, Wide-IP
- **Network:** IPv4 and IPv6 (mapped to RFC 5737 / RFC 3849 documentation
  ranges), FQDN, hostname
- **Free-text:** `description` fields, comments inside iRule bodies, APM
  session-variable names containing customer-identifying strings

## License

**MIT-Modified — source-available with a named-party exclusion.**

This is NOT OSI-approved open source. See [LICENSE](LICENSE) for the full
text. The license is legally valid and enforceable; it simply does not
meet the OSI Open Source Definition (clause 5: no discrimination against
persons or groups).

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting policy.
