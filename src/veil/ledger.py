"""f5-veil placeholder ledger.

Maps customer-identifying values from a BIG-IP config to typed placeholders
(e.g. ``/Tenant_A/foo_pool`` -> ``POOL_0001``) and tracks where each
placeholder was seen. The ledger is the source of truth for both pass-2
substitution and de-obfuscation.

Architecture decisions (locked 2026-06-12):
- Distinct placeholders per ``(kind, full_path)`` — ``/Common/foo`` and
  ``/Tenant_A/foo`` never share a placeholder.
- ``/Common/`` partition is exempt — never assigned a ``PARTITION_*``
  placeholder (universal BIG-IP signal, not customer identity).
- 4-digit zero-padded counter from v1.0 (no forklift rename at the
  thousandth object).
- In-memory only in v1.0; data model is shaped so v2.0 can serialize and
  reload the same structure without an API break.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Kind(str, Enum):
    POOL = "POOL"
    VS = "VS"
    NODE = "NODE"
    MON = "MON"
    IRULE = "IRULE"
    PARTITION = "PARTITION"
    UNKNOWN = "UNK"  # top-level block of an unrecognized kind whose path
    # is still identifying. EXAMPLE_CORPUS integration surfaced cases where
    # an unknown block's header path (e.g. ``gtm pool /Common/x_servers``)
    # shares a prefix with a registered NODE — without substituting the
    # UNKNOWN path, the NODE's full path leaks via substring.


@dataclass(frozen=True)
class Ref:
    byte_offset: int
    length: int
    line: int


@dataclass
class LedgerEntry:
    placeholder: str
    original: str
    kind: Kind
    partition: str | None
    discovery: Ref
    references: list[Ref] = field(default_factory=list)

    def __repr__(self) -> str:
        """Redact ``original`` — never let the un-sanitized customer
        identifier hit stdout, logs, or repr-based debugging tools.
        Use :meth:`Ledger.dump_unsafe` if you really need the raw value."""
        return (
            f"LedgerEntry(placeholder={self.placeholder!r}, "
            f"kind={self.kind!r}, partition={self.partition!r}, "
            f"original=<len={len(self.original)}>, "
            f"discovery={self.discovery!r}, "
            f"references=<count={len(self.references)}>)"
        )


COMMON_PARTITION = "Common"


class Ledger:
    def __init__(self) -> None:
        self.entries: dict[str, LedgerEntry] = {}
        self.by_original: dict[tuple[Kind, str], str] = {}
        self.counters: dict[Kind, int] = {}
        self._frozen: bool = False

    def intern(
        self,
        kind: Kind,
        original: str,
        discovery: Ref,
        partition: str | None = None,
    ) -> str:
        """Return the placeholder for ``(kind, original)``, minting a new
        one if this is the first time we have seen the pair. ``discovery``
        is the byte span where the identifier was first found, captured
        so pass-2 substitution can rewrite in place without re-scanning.

        Raises :class:`RuntimeError` if the ledger has been frozen — pass
        2 must operate on a frozen ledger so the answer file persisted
        before substitution remains the authoritative key."""
        key = (kind, original)
        existing = self.by_original.get(key)
        if existing is not None:
            return existing
        if self._frozen:
            raise RuntimeError(
                "ledger is frozen; cannot mint a new placeholder for "
                f"{kind.value!s} during pass 2"
            )
        n = self.counters.get(kind, 0) + 1
        self.counters[kind] = n
        placeholder = f"{kind.value}_{n:04d}"
        self.entries[placeholder] = LedgerEntry(
            placeholder=placeholder,
            original=original,
            kind=kind,
            partition=partition,
            discovery=discovery,
        )
        self.by_original[key] = placeholder
        return placeholder

    def intern_partition(self, partition: str, discovery: Ref) -> str | None:
        """Intern a partition. ``/Common/`` returns ``None`` and is never
        added to the ledger — it is left literal in sanitized output."""
        if partition == COMMON_PARTITION:
            return None
        return self.intern(Kind.PARTITION, partition, discovery, partition=None)

    def record_reference(self, placeholder: str, ref: Ref) -> None:
        entry = self.entries.get(placeholder)
        if entry is None:
            raise KeyError(f"unknown placeholder: {placeholder}")
        entry.references.append(ref)

    def freeze(self) -> None:
        """Lock the ledger against further interns. Must be called after
        pass 1 and before the answer file is written. Idempotent."""
        self._frozen = True

    @property
    def frozen(self) -> bool:
        return self._frozen

    def dump_unsafe(self) -> list[dict[str, Any]]:
        """Return a list of dicts containing the **un-sanitized**
        ``original`` values. Intended for answer-file serialization only.
        Do not log, do not print, do not send anywhere except an encrypted
        sink. Name is deliberately noisy to make grep-audits trivial."""
        return [
            {
                "placeholder": e.placeholder,
                "kind": e.kind.value,
                "partition": e.partition,
                "original": e.original,
                "discovery": {
                    "byte_offset": e.discovery.byte_offset,
                    "length": e.discovery.length,
                    "line": e.discovery.line,
                },
            }
            for e in self.entries.values()
        ]

    def __len__(self) -> int:
        return len(self.entries)

    def __repr__(self) -> str:
        return (
            f"Ledger(entries={len(self.entries)}, "
            f"frozen={self._frozen}, kinds={sorted(self.counters)})"
        )
