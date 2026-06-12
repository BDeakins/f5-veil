# f5-veil Architecture

Status: v0.0.1 — pass-1 scanner + ledger landed; pass-2 substitution and
the CLI / answer-file layer not yet implemented.

## Goal

Replace every customer-identifying value in a BIG-IP configuration with a
typed placeholder, store the originals in an encrypted answer file, and
restore them on the reverse pass — so engineers can collaborate with
third-party AI tools without exfiltrating customer data.

## Two-pass pipeline

The obfuscator runs in two passes over `bigip.conf`:

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

### Pass 2 — substitution (NOT YET IMPLEMENTED)

1. Walk the original token stream and emit each token's bytes verbatim,
   except identifier tokens that match a ledger entry — those are
   replaced with the placeholder.
2. Inside iRule (Tcl) bodies, descriptions, and policy rules, do a
   second-tier substitution that is aware of Tcl strings, Tcl comments,
   and TMSH brace-quoted descriptions (these need lexers smarter than
   the v0.1 byte-level tokenizer).
3. Every substitution is recorded as a `Ref` on the corresponding
   `LedgerEntry.references` for cross-reference integrity auditing.
4. Run the leak detector over the sanitized output. By default warn
   on suspicious patterns; `--strict` aborts.

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

Future kinds in scope for v1.0: `DG`, `ASMPOL`, `GTM_POOL`, `GTM_DC`,
`WIP`, `VLAN`, `CERT_CN`, plus profile/SNAT/route-domain kinds.

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

- IPv4: RFC 5737 documentation ranges (`192.0.2/24`, `198.51.100/24`,
  `203.0.113/24`). Preserves IP shape and subnet masks for AI reasoning.
- IPv6: RFC 3849 (`2001:db8::/32`).

IP substitution is part of pass 2 and is not yet implemented.

## Answer file

- Format: AES-256-GCM authenticated encryption via the `cryptography`
  package; scrypt KDF over an operator-supplied passphrase.
- Schema: a JSON document containing the `Ledger.dump_unsafe()` output
  plus a format-version field and the salt/nonce parameters.
- **Crash safety:** the answer file is written to disk *before* the
  sanitized output. A crash mid-write must never leave a sanitized file
  orphaned from its key. Mirrors the homelab rotation-script pattern.

## Cross-reference integrity

Every substitution pass 2 performs is logged as a `Ref` on the
corresponding `LedgerEntry.references`. At end of pass 2 the obfuscator
asserts: every `LedgerEntry` has at least its discovery offset in
`references` (i.e. nothing minted in pass 1 was *unused* in pass 2).
A mismatch indicates a parser/scanner gap — fail closed.

## Leak detector

Post-obfuscation pass over the sanitized output. Flags:
- RFC1918 IPv4 addresses (`10/8`, `172.16/12`, `192.168/16`).
- Internal-shaped FQDNs (`.local`, `.corp`, `.lan`, `.internal`).
- MAC addresses.
- Identifier-shaped barewords that don't match a placeholder pattern.

Default: warn and continue. `--strict`: abort obfuscation.

## v0.1 module map

```
src/veil/
  __init__.py        package version
  __main__.py        CLI stub (functional CLI not yet implemented)
  ledger.py          Kind, Ref, LedgerEntry, Ledger, COMMON_PARTITION
  tokenizer.py       Token, TokKind, tokenize(src)
  scanner.py         Diagnostics, scan(src) -> (Ledger, Diagnostics)
```

## Known gaps (deferred to follow-up PRs)

- TMSH `description { brace-quoted string }` — parsed as LBRACE by the
  v0.1 tokenizer. Harmless for pass 1; pass 2 must handle.
- iRule body Tcl-aware lexing (strings, `#` comments, `\` escapes).
- Profile / SNAT / data-group / ASM / GTM / VLAN / cert kinds.
- Persistent cross-run identifier map (v2.0).
- `bigip_base.conf` multi-file two-pass (v1.1).
- UCS archive ingestion (v1.2).
