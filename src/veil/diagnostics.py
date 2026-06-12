"""Pass 1 + pass 2 diagnostics — things the scanner / substituter
encountered but did not handle, surfaced so callers can fail closed.

The obfuscate command MUST refuse to write sanitized output if any
diagnostic list is non-empty, unless the operator explicitly opted into
``--allow-incomplete``.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Diagnostics:
    # ----- Pass 1 (scanner) findings ------------------------------------

    unknown_top_level: list[tuple[str, int]] = field(default_factory=list)
    """List of ``(header_signature, line)`` for top-level blocks the
    scanner did not recognise — e.g. ``('gtm wideip', 42)`` or
    ``('ltm dns', 17)``. Pass 1 records these and skips the body."""

    malformed_paths: list[tuple[str, str, int]] = field(default_factory=list)
    """List of ``(kind, raw_path, line)`` for object headers of a
    recognised kind whose path token is not a well-formed
    ``/Partition/leaf`` — e.g. ``('POOL', '/Common/', 5)``."""

    # ----- Pass 2 (substituter) findings --------------------------------

    unredacted_description: list[tuple[int, int]] = field(default_factory=list)
    """List of ``(byte_offset, line)`` for each ``description`` keyword
    pass 2 encountered. Pass 2 passes the description value through
    verbatim — DESC_NNNN minting is deferred to a 'pass 1.5: free-text
    discovery' PR."""

    qstring_contains_identifier: list[tuple[str, int, int]] = field(default_factory=list)
    """List of ``(placeholder, qstring_offset, line)`` for each QSTRING
    (outside a ``description``) whose content contains a substring
    matching a ledger entry's original value. Tcl-lexer-aware string
    substitution is deferred — pass 2 leaves the QSTRING verbatim."""

    orphan_entries: list[str] = field(default_factory=list)
    """Placeholders that were minted by pass 1 but received zero
    references during pass 2. Signals a discovery / substitution
    mismatch — the cross-reference integrity contract from the locked
    architecture."""

    # ----- Pass 1.5 (IP discovery) findings -----------------------------

    ipv4_subnet_collapsed: list[str] = field(default_factory=list)
    """Source ``/24`` networks whose host addresses had to be packed into
    a shared RFC 5737 docs ``/24`` because the configuration spanned more
    than 3 distinct source ``/24``s (RFC 5737 has 3 ``/24``s total). AI
    tools lose subnet-co-location signal for collapsed nets but the
    round-trip mapping remains exact. Pass-2 callers can treat this as a
    warning, not a fail-closed condition."""
