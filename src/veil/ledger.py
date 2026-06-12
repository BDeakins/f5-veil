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

import ipaddress
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
    IPADDR = "IPADDR"  # bare IPv4/IPv6 literals encountered in pass 1.5.
    # IPADDR is special: ``placeholder`` is the rendered RFC 5737 (v4) or
    # RFC 3849 (v6) docs-range address rather than ``IPADDR_NNNN``. This
    # lets AI tools reason about IP-shaped values normally while keeping
    # the round-trip mapping inside the encrypted answer file.
    DESC = "DESC"  # description bodies redacted in pass 1.7. Dedup is by
    # (form, full_token_text) — same QSTRING body content always gets the
    # same ``DESC_NNNN``; mixing QSTRING and bareword forms for the same
    # text yields distinct placeholders so the reverse path can restore
    # the original wrapping. Braced form is deferred to v0.0.5.


_RFC5737_NETWORKS = (
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)
_RFC3849_NETWORK = ipaddress.IPv6Network("2001:db8::/32")


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
        self._ipv4_allocator = _IPv4DocsAllocator()
        self._ipv6_allocator = _IPv6DocsAllocator()

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

    def intern_ipaddr(self, original: str, discovery: Ref) -> str:
        """Intern a bare IP literal. Returns the rendered docs-range
        address (which IS the placeholder for IPADDR entries — unlike
        other kinds, IPADDR uses no opaque ``KIND_NNNN`` token because the
        sanitized output needs to read as a real IP for AI tooling).

        Source ``/24`` (v4) / ``/64`` (v6) structure is preserved
        first-seen-first-allocated. With only 3 RFC 5737 ``/24``s
        available, configurations spanning more than 3 source ``/24``s
        collapse extras into the global pool; collapsed source nets
        surface on the allocator and callers (scanner) record them in
        Diagnostics.
        """
        if self._frozen:
            raise RuntimeError(
                "ledger is frozen; cannot mint a new IPADDR placeholder"
            )
        existing = self.by_original.get((Kind.IPADDR, original))
        if existing is not None:
            return existing
        try:
            addr = ipaddress.ip_address(original)
        except ValueError as exc:
            raise ValueError(f"not a valid IP literal: {original!r}") from exc
        if isinstance(addr, ipaddress.IPv4Address):
            rendered = str(self._ipv4_allocator.allocate(addr))
        else:
            rendered = str(self._ipv6_allocator.allocate(addr))
        # Guard against the (unexpected) case where the rendered string
        # collides with an existing placeholder of another kind.
        if rendered in self.entries:
            raise RuntimeError(
                f"IPADDR rendering {rendered!r} collides with existing "
                f"ledger entry — investigate allocator state."
            )
        self.entries[rendered] = LedgerEntry(
            placeholder=rendered,
            original=original,
            kind=Kind.IPADDR,
            partition=None,
            discovery=discovery,
        )
        self.by_original[(Kind.IPADDR, original)] = rendered
        self.counters[Kind.IPADDR] = self.counters.get(Kind.IPADDR, 0) + 1
        return rendered

    @property
    def ipv4_collapsed_source_nets(self) -> frozenset[ipaddress.IPv4Network]:
        """Source ``/24``s that had to share the RFC 5737 pool because more
        than three distinct source ``/24``s appeared. Callers can surface
        this in Diagnostics."""
        return frozenset(self._ipv4_allocator.collapsed_sources)

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


class _IPv4DocsAllocator:
    """Allocate RFC 5737 documentation addresses while preserving source
    ``/24`` structure first-seen-first-allocated. Falls back to packing
    into the union space (192.0.2.0/24 ∪ 198.51.100.0/24 ∪ 203.0.113.0/24)
    when more than 3 distinct source ``/24``s appear; collapsed source
    nets are exposed to callers for diagnostics. Raises
    :class:`RuntimeError` if the entire 768-host pool is exhausted."""

    def __init__(self) -> None:
        self.subnet_map: dict[ipaddress.IPv4Network, ipaddress.IPv4Network] = {}
        self.next_subnet_idx = 0
        self.used: set[int] = set()
        self.collapsed_sources: set[ipaddress.IPv4Network] = set()

    def allocate(self, addr: ipaddress.IPv4Address) -> ipaddress.IPv4Address:
        src_net = ipaddress.IPv4Network(f"{addr}/24", strict=False)
        docs_net = self.subnet_map.get(src_net)
        if docs_net is None and self.next_subnet_idx < len(_RFC5737_NETWORKS):
            docs_net = _RFC5737_NETWORKS[self.next_subnet_idx]
            self.next_subnet_idx += 1
            self.subnet_map[src_net] = docs_net
        if docs_net is not None:
            host_offset = int(addr) - int(src_net.network_address)
            result_int = int(docs_net.network_address) + host_offset
            if result_int not in self.used:
                self.used.add(result_int)
                return ipaddress.IPv4Address(result_int)
            # Subnet allocated but this exact slot already used (means
            # another source IP rendered to it via fallback); collapse.
        self.collapsed_sources.add(src_net)
        return self._fallback()

    def _fallback(self) -> ipaddress.IPv4Address:
        for net in _RFC5737_NETWORKS:
            base = int(net.network_address)
            bcast = int(net.broadcast_address)
            for host_int in range(base, bcast + 1):
                if host_int not in self.used:
                    self.used.add(host_int)
                    return ipaddress.IPv4Address(host_int)
        raise RuntimeError(
            "RFC 5737 IPv4 documentation address pool exhausted "
            "(more than 768 unique source IPv4 addresses). "
            "Reduce config scope or wait for v0.0.4's larger pool."
        )


class _IPv6DocsAllocator:
    """Allocate RFC 3849 (2001:db8::/32) documentation addresses preserving
    source ``/64`` structure. The pool holds 2^32 source ``/64``s — large
    enough that exhaustion is not a v0.0.3 concern."""

    def __init__(self) -> None:
        self.subnet_map: dict[ipaddress.IPv6Network, ipaddress.IPv6Network] = {}
        self.next_subnet_idx = 0
        self.used: set[int] = set()

    def allocate(self, addr: ipaddress.IPv6Address) -> ipaddress.IPv6Address:
        src_net = ipaddress.IPv6Network(f"{addr}/64", strict=False)
        docs_net = self.subnet_map.get(src_net)
        if docs_net is None:
            base = int(_RFC3849_NETWORK.network_address)
            net_int = base + (self.next_subnet_idx << 64)
            if self.next_subnet_idx >= (1 << 32):
                raise RuntimeError(
                    "RFC 3849 IPv6 docs subnet pool exhausted "
                    "(more than 2^32 unique source /64s)"
                )
            docs_net = ipaddress.IPv6Network((net_int, 64))
            self.next_subnet_idx += 1
            self.subnet_map[src_net] = docs_net
        host_offset = int(addr) - int(src_net.network_address)
        result_int = int(docs_net.network_address) + host_offset
        if result_int in self.used:
            raise RuntimeError(
                "unexpected IPv6 collision within preserved /64 — "
                "investigate allocator state"
            )
        self.used.add(result_int)
        return ipaddress.IPv6Address(result_int)
