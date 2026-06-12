# f5-veil Architecture

Status: v0.0.8 — pass-1 + pass-1.5 (IP) + pass-1.7 (description) +
pass-2 substitution + AES-256-GCM answer file + obfuscate/deobfuscate
CLI + leak detector with `--strict`. Object scope: LTM pool / virtual
/ node / monitor / rule / partition / profile / data-group / snat /
snatpool / virtual-address, GTM pool / wideip / server / datacenter /
**region**, **net vlan / route-domain / self / trunk**; bare IPv4/IPv6
literals; QSTRING and bareword descriptions; built-in TMOS profile
names pass through literal. Shadowed-duplicate ledger entries
suppressed as orphans. Braced descriptions, gtm topology, net
interface, ASM still pending.

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
| `IPADDR` | `203.0.113.42` (rendered docs IP, not `IPADDR_NNNN`) | `10.0.0.42` |
| `DESC` | `DESC_0001` (emitted inside the original wrapping: `"DESC_0001"` for QSTRING form, bare `DESC_0001` for bareword form) | `"customer prod pool"` |
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
                     (drives pass 1 + invokes pass 1.5 before freeze)
  ip_discovery.py    discover_ip_literals(src, ledger, diag)
                     (pass 1.5 — bare IP literal interning)
  description_discovery.py
                     discover_descriptions(src, ledger, diag)
                     (pass 1.7 — QSTRING / bareword description redaction)
  substitute.py      substitute(src, ledger, diag), reverse_substitute(...)
  answer_file.py     write_answer_file(...), read_answer_file(...),
                     AnswerFileError
  leak_detector.py   scan_leaks(sanitized) -> LeakReport,
                     LeakKind, Leak
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
- **Braced description form** — v0.0.5 follow-up (needs per-reference
  inner-brace whitespace metadata for byte-exact round-trip).
- **Bracketed IPv6 form `[fc00::1]:80`** — v0.0.4 follow-up.
- **Larger IPv4 docs pool** for configs exceeding the RFC 5737 768-host
  cap — v0.0.4 follow-up.
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
- **Member-port suffix handling.** ~~`/Common/web1:80` does not match
  the node `/Common/web1` (different bareword).~~ Closed by PR #6 via
  longest-prefix match with non-word boundary detection.
- **Unknown-block path leaks.** Closed by PR #6 — top-level blocks of
  unrecognised kinds (profiles, GTM, ASM, etc.) get their header path
  registered as `Kind.UNKNOWN` so pass-2 substitutes it. Best-effort
  only: UNK paths can still leak via substring inside longer
  non-header barewords. Safety-critical kinds
  (POOL/VS/NODE/MON/IRULE) remain strictly enforced.
- **Persistent cross-run identifier map** (v2.0).
- **`bigip_base.conf` multi-file two-pass** (v1.1).
- **UCS archive ingestion** (v1.2).
