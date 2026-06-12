# f5-veil Architecture

Status: v0.0.1 — pass-1 scanner + ledger + pass-2 substitution + AES-256-GCM
answer file + `veil obfuscate` / `veil deobfuscate` CLI landed. Tracer-bullet
object scope only (pool, virtual, node, monitor, rule, partition). Description
redaction, full GTM/profile/ASM coverage, and leak detector still pending.

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
  __main__.py        entry point — re-exports cli.main
  cli.py             argparse, obfuscate/deobfuscate commands, exit codes
  ledger.py          Kind, Ref, LedgerEntry, Ledger, COMMON_PARTITION
  tokenizer.py       Token, TokKind, tokenize(src)
  diagnostics.py     Diagnostics (shared by scanner + substitute)
  scanner.py         scan(src) -> (Ledger, Diagnostics)
  substitute.py      substitute(src, ledger, diag), reverse_substitute(...)
  answer_file.py     write_answer_file(...), read_answer_file(...),
                     AnswerFileError
```

## CLI semantics

- **Default is fail-closed.** Any non-empty Diagnostics field aborts
  obfuscation with exit code 1; no sanitized output and no answer file
  written. `--allow-incomplete` is the explicit opt-in to proceed.
- **`--strict` reserved** for the future leak-detector PR.
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

## Known gaps (deferred to follow-up PRs)

- **CLI wiring + answer file** (next PR). The library functions exist
  but no `veil obfuscate` / `veil deobfuscate` subcommand is wired,
  and the AES-256-GCM answer file format is not yet implemented.
- **`description` aggressive redaction.** Pass 2 emits descriptions
  verbatim plus an `unredacted_description` diagnostic. A 'pass 1.5:
  free-text discovery' PR will mint `DESC_NNNN` placeholders.
- **Tcl-lexer-aware iRule body substitution.** Bare path-shaped
  barewords inside rule bodies substitute normally; paths embedded in
  Tcl strings only surface as `qstring_contains_identifier`. Tcl `#`
  comments inside rule bodies emit verbatim — locked architecture says
  these need redaction (same posture as `description`).
- **Profile, SNAT, data-group, ASM, GTM, VLAN, cert, route-domain
  kinds.** Each unknown top-level block surfaces as
  `unknown_top_level` diagnostic; pass-2 callers fail closed.
- **Folder semantics.** `/Common/folder/sub/leaf` collapses folder
  into the leaf placeholder; folder-as-own-kind (FOLDER_NNNN) deferred.
- **Member-port suffix handling.** `/Common/web1:80` does not match
  the node `/Common/web1` (different bareword). Member-port refs pass
  through verbatim; covered by a follow-up PR.
- **Persistent cross-run identifier map** (v2.0).
- **`bigip_base.conf` multi-file two-pass** (v1.1).
- **UCS archive ingestion** (v1.2).
