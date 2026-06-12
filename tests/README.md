# f5-veil tests

Unit tests run on every invocation. Integration tests in
`test_integration_real_configs.py` skip unless real BIG-IP configs are
present at `test_configs/customer/*.bigip.conf`. That directory is
gitignored so customer configs never get committed.

## Running

```
# Full suite (unit + integration if fixtures present)
pytest tests/ -q

# Unit tests only (skip integration)
pytest tests/ -q --ignore=tests/test_integration_real_configs.py

# Integration tests only, verbose
pytest tests/test_integration_real_configs.py -v -s
```

The `-s` flag prevents pytest from capturing the per-config aggregate
counts the integration tests print.

## Populating the integration fixture

Drop one or more `*.bigip.conf` files into `test_configs/customer/`:

```bash
mkdir -p test_configs/customer/
# WSL / Linux / macOS:
ssh user@bigip "cat /config/bigip.conf" > test_configs/customer/<hostname>.bigip.conf
# Or via scp:
scp user@bigip:/config/bigip.conf test_configs/customer/<hostname>.bigip.conf
```

The filename stem (everything before `.bigip.conf`) becomes the pytest
test ID, so each device gets its own parametrized test instance.

## Privacy invariants

Integration tests verify structural properties only — they never echo
specific identifier names. Failure messages report aggregate counts and
per-kind breakdowns so test logs are safe to share.

Specifically:

- **Scan succeeds without exception** and prints discovered-entry counts
  per kind plus diagnostic-category counts.
- **CLI round-trip is byte-identical** (`obfuscate` → `deobfuscate`
  restores the source exactly). On failure, only structural delta
  (length, diff-line count) is reported.
- **Path-bearing originals never leak** into sanitized output. Pool,
  virtual, node, monitor, and rule full paths are checked; partition
  bare names are excluded because they can legitimately appear in
  description/qstring bodies (known deferred-substitution gaps).
- **Cross-reference integrity**: every minted ledger entry is referenced
  at least once during pass-2 substitution.

## Why partition bare names are excluded from the anti-leak check

Partition placeholders render as `PARTITION_NNNN` and replace the bare
partition word wherever it appears as a TMSH token. But descriptions
(`description "for Tenant_A"`) and Tcl string literals contain free
text that v0.1 does not rewrite — those surface as
`Diagnostics.unredacted_description` and
`Diagnostics.qstring_contains_identifier` so callers can fail closed.
Asserting that `Tenant_A` never appears in sanitized output would
inappropriately fail on configs with any description containing a
partition name. Full description redaction is a follow-up PR.
