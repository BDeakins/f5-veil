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
    PROFILE = "PROFILE"  # ``ltm profile <subtype> /path { ... }`` objects.
    # Subtype-agnostic — http, tcp, clientssl, oneconnect, fastL4, etc.
    # all share the same registration path. BIG-IP factory built-in
    # profile leaf names (``/Common/http``, ``/Common/tcp``, etc.) are
    # exempt and pass through literal — universal BIG-IP signal, not
    # customer identity. Custom profiles get ``PROFILE_NNNN``.
    GTM_POOL = "GTM_POOL"  # ``gtm pool <subtype> /path { ... }`` — DNS
    # load-balancing pool. Subtype indicates DNS record type (a, aaaa,
    # mx, cname, naptr, ...) — preserved structurally, not in placeholder.
    GTM_WIDEIP = "GTM_WIDEIP"  # ``gtm wideip <subtype> /path { ... }`` —
    # wide IP / GSLB record. Leaf is typically a FQDN (the wide IP name).
    GTM_SERVER = "GTM_SERVER"  # ``gtm server /path { ... }`` — GTM data
    # source (BIG-IP, generic-host, etc.).
    GTM_DC = "GTM_DC"  # ``gtm datacenter /path { ... }`` — physical /
    # logical site grouping for GTM topology decisions.
    DG = "DG"  # ``ltm data-group <internal|external> /path { ... }`` —
    # named key/value list. Records inside the body often hold
    # customer-identifying values; v0.0.7 substitutes the header path
    # only (record values are body content, future work).
    SNAT = "SNAT"  # ``ltm snat /path { ... }`` — source NAT object.
    SNATPOOL = "SNATPOOL"  # ``ltm snatpool /path { ... }`` — SNAT IP
    # address pool.
    VADDR = "VADDR"  # ``ltm virtual-address /path { ... }`` — explicit
    # virtual-address object (auto-created by virtual definitions, but
    # configs may override settings via explicit blocks).
    VLAN = "VLAN"  # ``net vlan /path { ... }`` — L2 broadcast domain.
    ROUTE_DOMAIN = "ROUTE_DOMAIN"  # ``net route-domain /path { ... }``
    # — routing-namespace isolation for multi-tenant.
    SELF_IP = "SELF_IP"  # ``net self /path { ... }`` — self-IP object
    # (the BIG-IP's own L3 address on a VLAN).
    TRUNK = "TRUNK"  # ``net trunk /path { ... }`` — LACP / link
    # aggregation.
    GTM_REGION = "GTM_REGION"  # ``gtm region /path { ... }`` — named
    # collection of subnets / countries for GTM topology decisions.
    APM_POLICY = "APM_POLICY"  # ``apm policy <subtype> /path { ... }``
    # — access policies (access-policy, customization-source, etc.).
    APM_PROFILE = "APM_PROFILE"  # ``apm profile <subtype> /path { ... }``
    # — access profile (access, etc.).
    FIREWALL_POLICY = "FIREWALL_POLICY"  # ``security firewall policy
    # /path { ... }`` — AFM firewall policy object.
    FIREWALL_RULE_LIST = "FIREWALL_RULE_LIST"  # ``security firewall
    # rule-list /path { ... }`` — reusable AFM rule list.
    FIREWALL_ADDRESS_LIST = "FIREWALL_ADDRESS_LIST"  # ``security
    # firewall address-list /path { ... }``.
    FIREWALL_PORT_LIST = "FIREWALL_PORT_LIST"  # ``security firewall
    # port-list /path { ... }``.
    IRULE_COMMENT = "IRULE_COMMENT"  # Tcl ``#`` comments discovered inside
    # an ``ltm rule /path { ... }`` body. ``original`` stores the full
    # COMMENT token text (leading ``#`` included, no trailing newline).
    # Pass-2 emits the placeholder as a COMMENT token in the form
    # ``# IRULE_COMMENT_NNNN`` so the leading ``#`` survives round-trip
    # via the tokenizer; the reverse pass restores the original byte-exact
    # via the comment reverse map. Top-level comments (e.g.
    # ``#TMSH-VERSION:``) are never interned and pass through verbatim.
    FQDN = "FQDN"  # Internal / private FQDNs discovered inside any
    # WORD or QSTRING token by pass-2.0 (regex match against a fixed set
    # of internal suffixes: ``.local``, ``.corp``, ``.lan``,
    # ``.internal``, ``.intranet``, ``.home.arpa``, ``.private``).
    # ``original`` stores the bare FQDN text (no surrounding URL syntax,
    # no QSTRING quotes). Pass-2's substring substitution machinery (the
    # same v0.0.14 QSTRING + v1.1 BAREWORD walker) substitutes each
    # match in place. Bare-placeholder render (``FQDN_NNNN``). Public-
    # internet FQDNs (``vendor.example.com``) are NOT discovered —
    # only internal suffixes that reveal customer namespace.
    AD_GROUP_DN = "AD_GROUP_DN"  # LDAP / AD distinguished names discovered
    # inside any QSTRING by pass-1.9 (regex match for the
    # ``CN=...,DC=...,DC=...`` shape with arbitrary leading/intermediate
    # RDN components). ``original`` stores the bare DN text (without the
    # surrounding QSTRING quotes or any ``memberOf=`` / ``memberOF=``
    # prefix). Pass-2 substring-substitutes AD_GROUP_DN entries inside
    # every QSTRING globally (not just ``ltm rule`` bodies) because DNs
    # have no legitimate probe-payload use case and customer AD domain
    # names are unambiguously identifying. Bare-placeholder render
    # (``AD_GROUP_DN_NNNN``); reverse map restores byte-exact.
    REMOTE_ROLE = "REMOTE_ROLE"  # Customer-defined role bucket paths
    # discovered inside an ``auth remote-role { role-info { ... } }``
    # body by pass-1.85 (v1.2). Pre-v1.2 these leaked verbatim because
    # ``auth remote-role`` lands in ``_record_unknown_top_level`` and
    # pass-1 doesn't descend into unknown bodies. ``original`` stores
    # the full path (``/Common/F5_Admins``). Path-shaped substitution
    # via pass-2's WORD-token full-match path (same model as
    # ``Kind.PROFILE`` etc.) — bucket leaf renders as
    # ``/Common/REMOTE_ROLE_NNNN``; non-Common partitions get the
    # usual ``PARTITION_NNNN`` treatment.
    SNMP_COMMUNITY = "SNMP_COMMUNITY"  # Bucket header path of an SNMP
    # community object inside ``sys snmp { communities { ... } }``
    # discovered by pass-1.85b (v1.2). Path-shaped registration; pass-2's
    # generic WORD-token full-match path substitutes
    # ``/Common/<name>`` → ``/Common/SNMP_COMMUNITY_NNNN``. The bucket
    # leaf name itself frequently EMBEDS the community string (TMSH
    # auto-names communities as ``i<community>_<index>``), which makes
    # the bucket name doubly sensitive — full-path substitution covers
    # it but the embedded substring also gets caught via the secret-
    # value substring sub when ``community-name`` is present.
    SNMP_TRAP = "SNMP_TRAP"  # Bucket header path of an SNMP trap
    # destination inside ``sys snmp { traps { ... } }`` discovered by
    # pass-1.85b (v1.2). Same path-shape and substitution model as
    # ``Kind.SNMP_COMMUNITY``. Bucket leaf names commonly embed
    # IP-shape substrings (``i192_168_1_1_3``) — those get caught by
    # the IP underscore-form substring sub planned for v1.2 Phase 3a.
    SNMP_COMMUNITY_SECRET = "SNMP_COMMUNITY_SECRET"  # Plaintext SNMP
    # community string discovered by pass-1.85b as the value of a
    # ``community-name`` field inside a ``communities`` bucket or a
    # ``community`` field inside a ``traps`` bucket. Bare-placeholder
    # substitution via pass-2's substring sub machinery (same model as
    # ``Kind.FQDN``) — finds the secret as a substring inside any
    # WORD or QSTRING content and replaces with
    # ``SNMP_COMMUNITY_SECRET_NNNN``. Trap ``community`` and
    # community ``community-name`` share this kind so the same secret
    # interns once and substitutes consistently in both places.
    SYS_CONTACT = "SYS_CONTACT"  # Free-text value of the
    # ``sys-contact`` field inside ``sys snmp { ... }`` (operator
    # contact name / email). Bareword or QSTRING form, both intern
    # the bare value text (no surrounding quotes). Substring-sub
    # substitution via pass-2 with bare-placeholder render
    # (``SYS_CONTACT_NNNN``).
    SYS_LOCATION = "SYS_LOCATION"  # Free-text value of the
    # ``sys-location`` field inside ``sys snmp { ... }`` (physical /
    # logical device location). Same form, same substitution model
    # as ``Kind.SYS_CONTACT``.
    SYSLOG_SERVER = "SYSLOG_SERVER"  # Bucket header path of a syslog
    # remote-server destination inside
    # ``sys syslog { remote-servers { ... } }`` discovered by
    # pass-1.85c (v1.2). Pre-v1.2 these names leaked verbatim because
    # ``sys syslog`` lands in ``_record_unknown_top_level`` and pass-1
    # skips its body. Path-shaped registration; pass-2's generic
    # WORD-token full-match path substitutes ``/Common/<name>`` →
    # ``/Common/SYSLOG_SERVER_NNNN``. Inner ``host`` field is already
    # caught by pass-1.5 IP literal walker; no secret-string body
    # fields exist in this block shape.
    SSHD_BANNER = "SSHD_BANNER"  # Free-text value of ``banner-text``,
    # ``pre-login-banner``, or ``post-login-banner`` inside
    # ``sys sshd { ... }`` discovered by pass-1.85d (v1.2). Real-world
    # banners frequently embed company name, legal jurisdiction, or
    # operations contact info. Multi-line QSTRING values are captured
    # by the tokenizer as a single QSTRING token whose content
    # includes embedded newlines; substring-sub substitution finds
    # the bare content (no surrounding quotes) inside any QSTRING
    # and replaces with bare-placeholder ``SSHD_BANNER_NNNN``.
    CERT_KEY_CHAIN = "CERT_KEY_CHAIN"  # Bareword bucket identifier
    # inside an ``ltm profile client-ssl { cert-key-chain { ... } }``
    # nested object body, discovered by pass-1.85e (v1.2). The
    # ``cert-key-chain`` block lives inside a KNOWN top-level kind
    # (``ltm profile client-ssl`` → ``Kind.PROFILE``) whose body the
    # main pass-1 loop brace-counts and skips — so the inner bucket
    # bareword identifier (typically composed from cert / root-CA
    # filenames) leaks verbatim. Stored as bare bareword value with
    # ``partition=None``; substring-sub renders bare placeholder
    # ``CERT_KEY_CHAIN_NNNN``. The bucket body's ``cert`` / ``chain`` /
    # ``key`` field values reference cert paths from ``sys file ssl-*``
    # top-level blocks already registered as ``Kind.UNKNOWN``, and
    # substitute via the existing UNK substring sub.
    CLIENT_POLICY = "CLIENT_POLICY"  # Bareword bucket identifier
    # inside an ``apm profile connectivity { client-policy { ... } }``
    # nested object body (and adjacent profile families), discovered
    # by pass-1.85f (v1.2). Same root-cause family as
    # ``Kind.CERT_KEY_CHAIN``: the enclosing profile body is brace-
    # skipped so the nested bucket name (typically derived from the
    # connectivity profile name itself) leaks verbatim. Stored as
    # bare bareword with ``partition=None``; substring-sub renders
    # ``CLIENT_POLICY_NNNN``.
    USERNAME = "USERNAME"  # Identity / hostname value attached to a
    # field-name allowlist discovered by pass-1.85g (v1.2). Field
    # names: ``admin-name``, ``basic-auth-username``, ``user``,
    # ``account-name``, ``server-name``. Values may be QSTRING or
    # WORD; TMSH literal keywords (``none``, ``default``, ``any``,
    # etc.) and path-shaped values are skipped. Stored bare with
    # ``partition=None``; substring-sub renders ``USERNAME_NNNN``.
    KRB_REALM = "KRB_REALM"  # Kerberos realm value (e.g.
    # ``ACME.CORP``, ``BOGUS.COM``) attached to a ``realm`` field
    # inside ``apm sso kerberos`` / ``apm aaa kerberos`` blocks,
    # discovered by pass-1.85h (v1.2). Match is ALL-UPPERCASE
    # dot-delimited shape — covers public-TLD realms that the FQDN
    # walker skips by design. Realms with internal-suffix top labels
    # (``ACME.LOCAL``) are already caught by FQDN; this walker
    # short-circuits if the value is already in the ledger under
    # another kind. Stored bare with ``partition=None``; substring-
    # sub renders ``KRB_REALM_NNNN``.
    LDAP_FILTER = "LDAP_FILTER"  # LDAP filter expression value
    # (e.g. ``sAMAccountName=foo``, ``(&(objectClass=user)(...))``)
    # attached to a ``filter`` field inside an LDAP-flavoured block,
    # discovered by pass-1.85i (v1.2). Context-gated to top-level
    # blocks ``apm aaa ldap`` / ``apm aaa active-directory`` /
    # ``auth ldap`` / ``auth active-directory`` / ``ltm monitor
    # ldap``. Filter values may embed usernames or other
    # customer-identifying information; treated as opaque (whole
    # value redacted). Stored bare with ``partition=None``;
    # substring-sub renders ``LDAP_FILTER_NNNN``.
    SAML_ENTITY_ID = "SAML_ENTITY_ID"  # Value of ``entity-id`` field
    # inside SAML SP/IdP blocks, discovered by pass-1.85j (v1.2). May
    # be a URL, a URN, or an opaque string; whole value interned to
    # avoid leaking sub-paths that the FQDN walker doesn't reach
    # (``https://idp.acme.local/ark-ipmi`` → entire URL redacted, not
    # just the FQDN portion). Substring-sub renders
    # ``SAML_ENTITY_ID_NNNN``. Double-tokenization with FQDN walker is
    # accepted: SAML walker runs first; FQDN walker may register the
    # inner FQDN separately; substring-sub longest-match-first then
    # picks the SAML entry for the full URL.
    SAML_SSO_URI = "SAML_SSO_URI"  # Value of ``sso-uri`` field. Same
    # semantics and substitution model as ``Kind.SAML_ENTITY_ID``.
    SAML_SLO_URI = "SAML_SLO_URI"  # Value of ``single-logout-uri``
    # field. Same semantics as ``Kind.SAML_ENTITY_ID``.
    SAML_SLO_RESPONSE_URI = "SAML_SLO_RESPONSE_URI"  # Value of
    # ``single-logout-response-uri`` field. Same semantics.
    OAUTH_AUDIENCE = "OAUTH_AUDIENCE"  # Value(s) of ``audience``
    # field inside ``apm oauth oauth-provider`` and adjacent blocks,
    # discovered by pass-1.85j. The braced-list form
    # ``audience { url1 url2 ... }`` interns each list element
    # separately. Same substitution model as ``Kind.SAML_ENTITY_ID``.
    OAUTH_ISSUER = "OAUTH_ISSUER"  # Value of ``issuer`` field.
    # Same semantics as ``Kind.SAML_ENTITY_ID``.


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
