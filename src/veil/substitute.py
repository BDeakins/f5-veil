"""bigip.conf pass-2 substitution — rewrite the source with placeholders.

Walks the token stream from :func:`veil.tokenizer.tokenize` and emits a
new string in which every WORD token whose value matches a ledger entry
is replaced with the entry's rendered placeholder. Inter-token whitespace
and comments are preserved byte-for-byte by copying gaps directly from
the source.

Path-piece rendering (locked architecture):
- ``/Common/foo_pool`` -> ``/Common/POOL_0001`` — the ``/Common/`` literal
  is preserved as universal BIG-IP signal.
- ``/Tenant_A/foo_pool`` -> ``/PARTITION_0001/POOL_0001`` — the partition
  itself is also placeholdered.

Member-port suffix handling
---------------------------
WORD tokens like ``/Common/10.0.0.1:80`` are handled via longest-prefix
match with non-word-character boundary detection. The matched prefix
becomes the substituted placeholder; the suffix (``:80``, ``.80``,
``%rd0`` etc.) is preserved. Forward and reverse substitution use
symmetric logic so the round-trip works cleanly.

Kind.UNKNOWN handling
---------------------
Top-level blocks whose module/subtype isn't in the recognised set
(profiles, GTM, ASM, DG, etc.) get their header path registered as
``Kind.UNKNOWN`` so pass-2 substitutes it — without this, an unknown
block's header path (e.g. ``gtm pool /Common/<node>_servers``) would
leak any registered LTM identifier whose path is a prefix of it.
``Kind.UNKNOWN`` is best-effort: a UNK path can still leak via
substring inside a longer non-header bareword in another block's body
(no current diagnostic catches that), or via QSTRING contents
(flagged by ``qstring_contains_identifier``). The safety-critical
kinds (POOL/VS/NODE/MON/IRULE) do not have this caveat — their
substitution is strictly enforced.

Known gaps deferred to follow-up PRs (each surfaces as a Diagnostics
entry where applicable so callers can fail closed):
- QSTRING content substitution OUTSIDE iRule bodies. ``"foo /Common/bar
  baz"`` containing a ledger original still surfaces
  ``qstring_contains_identifier`` but the string body is emitted
  verbatim — monitor send-strings etc. can legitimately need original
  bytes (probe payloads), so we surface the diagnostic instead of
  mutating.
- ``description "..."`` and ``description { ... }`` values pass through
  verbatim and surface in ``unredacted_description``. DESC_NNNN minting
  is deferred to a dedicated 'pass 1.5: free-text discovery' PR.
- Folder-nested object paths (``/Common/folder/sub/leaf``) collapse the
  folder into the leaf placeholder; folder semantics are not preserved.
- Tcl-string-aware substring substitution inside iRule bodies landed in
  v0.0.12: QSTRINGs inside ``ltm rule /path { ... }`` bodies have their
  content scanned for substrings matching any non-DESC, non-IRULE_COMMENT
  ledger original; matches are substituted in place with word-boundary
  guards on both sides. QSTRINGs outside iRule bodies keep the legacy
  verbatim emit + ``qstring_contains_identifier`` diagnostic.
- Tcl ``#`` comments inside ``ltm rule`` bodies are redacted in v0.0.11
  via :func:`veil.irule_comment_discovery.discover_irule_comments` +
  ledger lookup in :func:`_emit_token`. Top-level COMMENT tokens
  (``#TMSH-VERSION:`` etc.) are never interned and pass through verbatim.
- Unterminated QSTRINGs (source has an opening quote with no close)
  scan to EOF; the qstring-contains-identifier check still runs on the
  EOF-truncated content. Edge case, deferred.
- Substring-in-bareword leaks for ``Kind.UNKNOWN`` paths. When a UNK
  header path is a substring of a longer non-header bareword reference
  elsewhere (with word-character boundary), prefix-match correctly
  rejects but the literal UNK path appears as substring. Closing this
  requires either tokenizer-level path detection or a substring
  diagnostic — deferred.
"""

from __future__ import annotations

from .diagnostics import Diagnostics
from .ledger import COMMON_PARTITION, Kind, Ledger, LedgerEntry, Ref
from .tokenizer import Token, TokKind, tokenize

# Characters considered "word characters" — a prefix-match WORD token is
# rejected if the character at the boundary position falls in this set,
# so e.g. ``/Common/web`` is NOT a prefix of ``/Common/web_pool`` (word
# boundary failure) but IS a prefix of ``/Common/web:80`` (non-word ':').
# This covers both IPv4 ``:port`` and IPv6 ``.port`` / ``%route-domain``
# suffixes — anything not in this set qualifies as a boundary.
_WORD_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)
# v1.2 — right-side boundary set for FQDN substring substitution. The
# F5 file storage layer auto-generates compound filenames of the form
# ``<fqdn>_<index>_<index>`` (e.g.
# ``:Common:host01.example.local_69313_3``) where the customer FQDN
# is followed by an underscore-separated numeric index. Treating ``_``
# as a non-word RIGHT boundary lets the FQDN substitute even in this
# shape; the leading ``_<index>`` is universal F5 bookkeeping, not
# customer content. Left boundary stays strict — relaxing left could
# let a shorter FQDN partially substitute inside a longer
# customer-defined compound (rare but possible).
_WORD_CHARS_FQDN_RIGHT = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

# v1.2 — description-family field names. Walker (pass-1.7) and
# substitute side both gate on this set. Keep in sync with
# ``_DESC_FIELDS`` in ``description_discovery.py``.
_DESC_FIELDS = frozenset({"description", "caption", "service-name"})


def substitute(
    src: str,
    ledger: Ledger,
    diagnostics: Diagnostics | None = None,
) -> tuple[str, Diagnostics]:
    """Pass 2: render the sanitized source from the source + ledger.

    Freezes the ledger if it isn't already (idempotent). Returns
    ``(sanitized_text, diagnostics)``. The returned diagnostics carries
    forward any pass-1 entries plus pass-2 findings (descriptions,
    qstring-embedded identifiers outside iRule bodies, orphan ledger
    entries).

    v0.0.12 tracks ``ltm rule`` body entry via the same depth state
    machine as :func:`veil.irule_comment_discovery.discover_irule_comments`.
    Inside an iRule body, QSTRINGs get substring substitution against
    every non-DESC, non-IRULE_COMMENT ledger original; outside, they
    keep the legacy verbatim emit + ``qstring_contains_identifier``
    diagnostic.
    """
    if not ledger.frozen:
        ledger.freeze()
    if diagnostics is None:
        diagnostics = Diagnostics()
    tokens = list(tokenize(src))
    # v0.0.14 — unified substring map for ALL QSTRINGs (both inside and
    # outside ``ltm rule`` bodies). The v0.0.12 split between
    # iRule-body (full sub) and non-iRule (verbatim + diagnostic) was a
    # conservative call premised on "probe payloads may legitimately
    # need original bytes" — but the sanitized output is never deployed
    # to a live BIG-IP (it's AI workspace), so substituting everywhere
    # is strictly better. EXAMPLE_CORPUS survivor audit drove the unification:
    # 23 ``/Common/...`` UNK references and 11 ``192.168.x.x/24`` IPADDR
    # references inside monitor send-strings + APM expressions that
    # weren't redacted under the v0.0.13 contract.
    qstring_render_map = _build_substring_render_map(ledger)
    out: list[str] = []
    cursor = 0
    depth = 0
    rule_entry_depth: int | None = None
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.offset > cursor:
            out.append(src[cursor:tok.offset])
        # ---- Detect ``ltm rule <path> {`` at top level ----
        if (
            rule_entry_depth is None
            and depth == 0
            and tok.kind == TokKind.WORD
            and tok.value == "ltm"
            and i + 3 < n
            and tokens[i + 1].kind == TokKind.WORD
            and tokens[i + 1].value == "rule"
            and tokens[i + 2].kind == TokKind.WORD
            and tokens[i + 3].kind == TokKind.LBRACE
        ):
            # Emit ltm, rule, <path>, { — path goes through _emit_token so
            # the IRULE entry substitutes normally; the LBRACE passes through.
            for j in range(4):
                t = tokens[i + j]
                if j > 0:
                    prev = tokens[i + j - 1]
                    out.append(src[prev.offset + prev.length : t.offset])
                out.append(_emit_token(t, ledger, diagnostics, qstring_render_map))
            rule_entry_depth = depth
            depth += 1
            last = tokens[i + 3]
            cursor = last.offset + last.length
            i += 4
            continue
        # ---- Description-family handling (TMSH context only, not inside iRule) ----
        # v1.2: ``caption`` and ``service-name`` join ``description``
        # under Kind.DESC. Same emission logic — the keyword is echoed
        # verbatim and the value is substituted with a DESC_NNNN
        # placeholder.
        if (
            rule_entry_depth is None
            and tok.kind == TokKind.WORD
            and tok.value in _DESC_FIELDS
        ):
            consumed = _emit_description(
                tokens, i, src, out, ledger, diagnostics,
            )
            last = tokens[i + consumed - 1]
            cursor = last.offset + last.length
            i += consumed
            continue
        # ---- QSTRING (any context): full substring substitution (v0.0.14) ----
        if tok.kind == TokKind.QSTRING:
            out.append(
                _substitute_in_irule_qstring(tok, qstring_render_map, ledger)
            )
            cursor = tok.offset + tok.length
            i += 1
            continue
        # ---- Default emit ----
        out.append(_emit_token(tok, ledger, diagnostics, qstring_render_map))
        # Brace tracking AFTER emit so the closing RBRACE of an iRule
        # body has already been written before we clear rule_entry_depth.
        if tok.kind == TokKind.LBRACE:
            depth += 1
        elif tok.kind == TokKind.RBRACE:
            depth -= 1
            if rule_entry_depth is not None and depth == rule_entry_depth:
                rule_entry_depth = None
        cursor = tok.offset + tok.length
        i += 1
    if cursor < len(src):
        out.append(src[cursor:])
    _check_orphan_entries(ledger, diagnostics)
    return "".join(out), diagnostics


def _emit_token(
    tok: Token,
    ledger: Ledger,
    diagnostics: Diagnostics,
    infix_render_map: dict[str, list[tuple[str, str, str]]] | None = None,
) -> str:
    if tok.kind == TokKind.WORD:
        # 1. Exact match — fast path for ordinary identifiers.
        for kind in Kind:
            placeholder = ledger.by_original.get((kind, tok.value))
            if placeholder is None:
                continue
            entry = ledger.entries[placeholder]
            ledger.record_reference(
                placeholder,
                Ref(byte_offset=tok.offset, length=tok.length, line=tok.line),
            )
            return _render_placeholder(entry, ledger, tok)
        # 2. v1.1 — Infix substring substitution subsumes the
        # legacy prefix-with-suffix tier (member-port forms like
        # ``/Common/10.0.0.1:80``, IPv6 ``/Common/2001:db8::1.80``,
        # route-domain ``%rd0``) AND the new compound-bareword cases
        # (``https://10.0.0.143/path``, IP ranges like
        # ``10.0.0.1-10.0.0.50``). The substring walker is
        # char-by-char with longest-match-first and word-boundary
        # protection on both sides, so a single token can carry several
        # independent substitutions (the range case) and the suffix
        # after a prefix match also gets scanned. Partition references
        # on infix hits are NOT recorded — non-Common partitions
        # matched only as infix substring (rare in real configs) may
        # orphan; documented gap.
        if infix_render_map is not None:
            substituted = _substitute_in_irule_qstring(
                tok, infix_render_map, ledger,
            )
            if substituted != tok.value:
                return substituted
        return tok.value
    if tok.kind == TokKind.QSTRING:
        _check_qstring_for_identifier(tok, ledger, diagnostics)
        return tok.value
    if tok.kind == TokKind.COMMENT:
        # iRule-body comments (Kind.IRULE_COMMENT) interned by pass-1.8
        # are redacted here; top-level comments are never interned and
        # pass through verbatim.
        placeholder = ledger.by_original.get((Kind.IRULE_COMMENT, tok.value))
        if placeholder is not None:
            entry = ledger.entries[placeholder]
            ledger.record_reference(
                placeholder,
                Ref(byte_offset=tok.offset, length=tok.length, line=tok.line),
            )
            return f"# {entry.placeholder}"
        return tok.value
    # LBRACE, RBRACE pass through verbatim.
    return tok.value


def _find_longest_prefix_match(
    value: str, ledger: Ledger
) -> tuple[LedgerEntry, int] | None:
    """Find the longest ledger original that is a strict prefix of
    ``value`` followed by a non-word-character boundary. Returns
    ``(entry, prefix_len)`` or ``None`` if no candidate matches."""
    best_entry: LedgerEntry | None = None
    best_len = 0
    value_len = len(value)
    for (_kind, original), placeholder in ledger.by_original.items():
        original_len = len(original)
        if original_len >= value_len or original_len <= best_len:
            continue
        if not value.startswith(original):
            continue
        if value[original_len] in _WORD_CHARS:
            continue
        best_entry = ledger.entries[placeholder]
        best_len = original_len
    if best_entry is None:
        return None
    return best_entry, best_len


def _render_placeholder(entry: LedgerEntry, ledger: Ledger, tok: Token) -> str:
    leaf = entry.placeholder
    if entry.partition is None:
        return leaf
    if entry.partition == "Common":
        return f"/Common/{leaf}"
    part_ph = ledger.by_original.get((Kind.PARTITION, entry.partition))
    if part_ph is None:
        # Pass 1 must register a non-Common partition before any object
        # inside it. If we get here, the ledger is inconsistent — refuse
        # to fall back to the literal partition name (which would leak
        # the customer's tenant label). Loud crash > silent leak.
        raise RuntimeError(
            f"ledger invariant violated: object {entry.placeholder} "
            f"references partition {entry.partition!r} which has no "
            f"PARTITION entry. Refusing to emit literal partition name "
            f"into sanitized output."
        )
    ledger.record_reference(
        part_ph,
        Ref(
            byte_offset=tok.offset + 1,
            length=len(entry.partition),
            line=tok.line,
        ),
    )
    return f"/{part_ph}/{leaf}"


def _check_qstring_for_identifier(
    tok: Token,
    ledger: Ledger,
    diagnostics: Diagnostics,
) -> None:
    if len(tok.value) < 2:
        return
    content = tok.value[1:-1]
    if not content:
        return
    for (kind, original), placeholder in ledger.by_original.items():
        # AD_GROUP_DN entries are always substring-substituted globally
        # in pass-2 (v0.0.13) — they never trigger the "not handled"
        # diagnostic, regardless of which QSTRING context they appear in.
        if kind == Kind.AD_GROUP_DN:
            continue
        if original in content:
            diagnostics.qstring_contains_identifier.append(
                (placeholder, tok.offset, tok.line)
            )


def _emit_description(
    tokens: list[Token],
    i: int,
    src: str,
    out: list[str],
    ledger: Ledger,
    diagnostics: Diagnostics,
) -> int:
    """Emit the ``description`` keyword and substitute its value with a
    ``DESC_NNNN`` placeholder. QSTRING and bareword forms are redacted
    in place; braced form falls back to verbatim emit + the legacy
    ``unredacted_description`` diagnostic (deferred to v0.0.5).

    Returns total tokens consumed (including the description keyword).
    """
    desc_tok = tokens[i]
    out.append(desc_tok.value)
    if i + 1 >= len(tokens):
        return 1
    next_tok = tokens[i + 1]
    out.append(src[desc_tok.offset + desc_tok.length : next_tok.offset])
    if next_tok.kind == TokKind.QSTRING:
        placeholder = ledger.by_original.get((Kind.DESC, next_tok.value))
        if placeholder is not None:
            entry = ledger.entries[placeholder]
            ledger.record_reference(
                placeholder,
                Ref(
                    byte_offset=next_tok.offset,
                    length=next_tok.length,
                    line=next_tok.line,
                ),
            )
            out.append(f'"{entry.placeholder}"')
        else:
            # Empty body or otherwise not interned — leave verbatim. No
            # leak (empty body has nothing to redact) and no diagnostic.
            out.append(next_tok.value)
        return 2
    if next_tok.kind == TokKind.LBRACE:
        # Braced form. Pass-1.7 interns the full LBRACE-through-RBRACE
        # span as the ``original``. We reproduce that exact span here,
        # look it up, and emit the placeholder in QSTRING form so the
        # reverse path's qstring_reverse_map handles the round-trip.
        # Find the matching RBRACE.
        depth = 1
        j = i + 2
        end_offset = -1
        consumed = 1  # description WORD already consumed by caller
        while j < len(tokens) and depth > 0:
            t = tokens[j]
            if t.kind == TokKind.LBRACE:
                depth += 1
            elif t.kind == TokKind.RBRACE:
                depth -= 1
            if depth == 0:
                end_offset = t.offset + t.length
                consumed = j - i + 1
                break
            j += 1
        if end_offset < 0:
            # Malformed — no matching RBRACE. Fall back to verbatim.
            diagnostics.unredacted_description.append(
                (desc_tok.offset, desc_tok.line)
            )
            out.append(src[next_tok.offset:])
            return len(tokens) - i
        span_text = src[next_tok.offset:end_offset]
        placeholder = ledger.by_original.get((Kind.DESC, span_text))
        if placeholder is not None:
            entry = ledger.entries[placeholder]
            ledger.record_reference(
                placeholder,
                Ref(
                    byte_offset=next_tok.offset,
                    length=end_offset - next_tok.offset,
                    line=next_tok.line,
                ),
            )
            out.append(f'"{entry.placeholder}"')
        else:
            # Pass-1.7 should have interned every braced description.
            # If we're here, the descriptions discovered in pass-1.7 and
            # the ones substituted in pass-2 disagree — fail closed
            # rather than leaking the body.
            diagnostics.unredacted_description.append(
                (desc_tok.offset, desc_tok.line)
            )
            out.append(span_text)
        return consumed
    if next_tok.kind == TokKind.WORD:
        placeholder = ledger.by_original.get((Kind.DESC, next_tok.value))
        if placeholder is not None:
            entry = ledger.entries[placeholder]
            ledger.record_reference(
                placeholder,
                Ref(
                    byte_offset=next_tok.offset,
                    length=next_tok.length,
                    line=next_tok.line,
                ),
            )
            out.append(entry.placeholder)
        else:
            out.append(next_tok.value)
        return 2
    return 1


def _check_orphan_entries(ledger: Ledger, diagnostics: Diagnostics) -> None:
    """Surface entries that received zero references — the parser gap
    signal — but suppress shadowed duplicates.

    Real configs can register the same path under multiple kinds (e.g.
    ``/Common/<ip>`` as both NODE and VADDR for the same address).
    Pass-2's Kind-iteration order picks one, leaving the other unused.
    That's not a parser gap — the path WAS substituted, just via the
    other entry — so we don't flag it as an orphan.

    Substring-shadow exemption (v1.2): when the SAML/OAuth walker
    (pass-1.85j) interns a full URL like
    ``https://idp.example.local/svc`` and the FQDN walker (pass-2.0)
    independently registers the inner ``idp.example.local``,
    longest-match-first substring substitution picks the full URL
    everywhere — leaving the inner FQDN entry orphan IF it doesn't
    appear anywhere outside the URL. That's a designed consequence
    of the user-approved double-tokenization model, not a parser
    gap. So an entry whose original is a strict substring of some
    REFERENCED entry's original is exempted from orphan reporting.
    """
    referenced_originals: set[str] = set()
    for entry in ledger.entries.values():
        if entry.references:
            referenced_originals.add(entry.original)
    for placeholder, entry in ledger.entries.items():
        if entry.references:
            continue
        if entry.original in referenced_originals:
            continue
        # Substring-shadow exemption — see docstring.
        if _is_substring_of_any(entry.original, referenced_originals):
            continue
        diagnostics.orphan_entries.append(placeholder)


def _is_substring_of_any(needle: str, originals: set[str]) -> bool:
    """Return True if ``needle`` is a strict substring of any item in
    ``originals``. Identity matches are NOT counted (that case is
    handled by the ``entry.original in referenced_originals`` check
    above)."""
    if not needle:
        return False
    for s in originals:
        if len(s) > len(needle) and needle in s:
            return True
    return False


# ---------------------------------------------------------------------
# Reverse substitution (deobfuscation)
# ---------------------------------------------------------------------


def reverse_substitute(sanitized: str, ledger: Ledger) -> str:
    """Inverse of :func:`substitute`. Replaces rendered placeholders in
    ``sanitized`` with their original values from the (frozen) ledger.

    Walks the sanitized source as a token stream and replaces any WORD
    token whose value matches a rendered-placeholder key in the reverse
    map. Inter-token whitespace is preserved via cursor-tracking, so the
    output is byte-faithful to the sanitized input modulo the placeholder
    swap-outs.

    Tokens that don't match the reverse map pass through verbatim — this
    is how the AI's newly-introduced content (e.g. new iRule code) is
    preserved while still restoring any placeholder it referenced.

    Matching is symmetric with :func:`substitute`: exact match first,
    then longest-prefix match with non-word boundary, so port-suffix
    tokens like ``/Common/NODE_0001:80`` round-trip back to
    ``/Common/10.0.0.1:80`` cleanly.

    v0.0.12 tracks ``ltm rule`` body entry symmetrically with the
    forward pass; QSTRINGs inside an iRule body get rendered-placeholder
    substring substitution back to originals.
    """
    reverse_map = _build_reverse_map(ledger)
    qstring_reverse_map = _build_qstring_reverse_map(ledger)
    comment_reverse_map = _build_comment_reverse_map(ledger)
    # v0.0.14 — single unified reverse map for ALL QSTRINGs.
    qstring_substring_reverse_map = _build_substring_reverse_render_map(ledger)
    tokens = list(tokenize(sanitized))
    out: list[str] = []
    cursor = 0
    depth = 0
    rule_entry_depth: int | None = None
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.offset > cursor:
            out.append(sanitized[cursor:tok.offset])
        # ---- Detect ``ltm rule <path> {`` at top level ----
        if (
            rule_entry_depth is None
            and depth == 0
            and tok.kind == TokKind.WORD
            and tok.value == "ltm"
            and i + 3 < n
            and tokens[i + 1].kind == TokKind.WORD
            and tokens[i + 1].value == "rule"
            and tokens[i + 2].kind == TokKind.WORD
            and tokens[i + 3].kind == TokKind.LBRACE
        ):
            for j in range(4):
                t = tokens[i + j]
                if j > 0:
                    prev = tokens[i + j - 1]
                    out.append(sanitized[prev.offset + prev.length : t.offset])
                out.append(
                    _reverse_emit_token(
                        t, reverse_map, qstring_reverse_map,
                        comment_reverse_map, qstring_substring_reverse_map,
                    )
                )
            rule_entry_depth = depth
            depth += 1
            last = tokens[i + 3]
            cursor = last.offset + last.length
            i += 4
            continue
        # ---- QSTRING (any context): DESC reverse first, else substring reverse (v0.0.14) ----
        if tok.kind == TokKind.QSTRING:
            if tok.value in qstring_reverse_map:
                # Whole-QSTRING DESC placeholder ("DESC_NNNN") restores
                # to the original quoted/braced span verbatim.
                out.append(qstring_reverse_map[tok.value])
            else:
                out.append(
                    _reverse_substitute_in_irule_qstring(
                        tok, qstring_substring_reverse_map,
                    )
                )
            cursor = tok.offset + tok.length
            i += 1
            continue
        # ---- Default emit ----
        out.append(
            _reverse_emit_token(
                tok, reverse_map, qstring_reverse_map, comment_reverse_map,
                qstring_substring_reverse_map,
            )
        )
        if tok.kind == TokKind.LBRACE:
            depth += 1
        elif tok.kind == TokKind.RBRACE:
            depth -= 1
            if rule_entry_depth is not None and depth == rule_entry_depth:
                rule_entry_depth = None
        cursor = tok.offset + tok.length
        i += 1
    if cursor < len(sanitized):
        out.append(sanitized[cursor:])
    return "".join(out)


def _reverse_emit_token(
    tok: Token,
    reverse_map: dict[str, str],
    qstring_reverse_map: dict[str, str],
    comment_reverse_map: dict[str, str],
    infix_reverse_map: dict[str, list[tuple[str, str]]] | None = None,
) -> str:
    """Pure-function token-level reverse emit shared by the top-level
    reverse pass and the iRule-rule-header emission path."""
    if tok.kind == TokKind.WORD:
        if tok.value in reverse_map:
            return reverse_map[tok.value]
        # v1.1 — infix substring reverse substitution subsumes the
        # legacy longest-prefix-reverse tier. Handles the original
        # suffix-after-prefix case (``/Common/POOL_0001:80`` →
        # ``/Common/foo:80``) AND new compound cases like IP ranges
        # (``203.0.113.1-203.0.113.50`` → ``10.0.0.1-10.0.0.50``).
        if infix_reverse_map is not None:
            substituted = _reverse_substitute_in_irule_qstring(
                tok, infix_reverse_map,
            )
            if substituted != tok.value:
                return substituted
        return tok.value
    if tok.kind == TokKind.QSTRING:
        # DESC_NNNN placeholders inside QSTRINGs (description bodies in
        # QSTRING or braced form). Key includes the quotes; the value is
        # the original QSTRING token (also quoted) or the full braced
        # span, so the wrapping restores byte-exactly.
        if tok.value in qstring_reverse_map:
            return qstring_reverse_map[tok.value]
        return tok.value
    if tok.kind == TokKind.COMMENT:
        # IRULE_COMMENT placeholders (v0.0.11). Key includes the leading
        # ``#`` so a direct ``tok.value`` lookup works.
        if tok.value in comment_reverse_map:
            return comment_reverse_map[tok.value]
        return tok.value
    return tok.value


def _find_longest_reverse_prefix(
    value: str, reverse_map: dict[str, str]
) -> tuple[int, str] | None:
    """Symmetric counterpart to :func:`_find_longest_prefix_match` that
    walks the rendered-placeholder map instead of the ledger."""
    best_len = 0
    best_original: str | None = None
    value_len = len(value)
    for placeholder, original in reverse_map.items():
        placeholder_len = len(placeholder)
        if placeholder_len >= value_len or placeholder_len <= best_len:
            continue
        if not value.startswith(placeholder):
            continue
        if value[placeholder_len] in _WORD_CHARS:
            continue
        best_len = placeholder_len
        best_original = original
    if best_original is None:
        return None
    return best_len, best_original


def _build_qstring_reverse_map(ledger: Ledger) -> dict[str, str]:
    """Map quoted-placeholder QSTRING values back to their original
    form, for description redaction (QSTRING form AND braced form,
    both of which emit ``"DESC_NNNN"`` in sanitized output).

    Key: the quoted placeholder as it appears in the sanitized output
    (e.g. ``'"DESC_0001"'``).
    Value: the original — either a quoted QSTRING
    (``'"primary cluster"'``) or a full braced span
    (``'{ multi line body }'``).

    Bareword-form DESC entries (``original`` starts with neither ``"``
    nor ``{``) are handled by the standard WORD reverse map and skipped
    here."""
    rmap: dict[str, str] = {}
    for entry in ledger.entries.values():
        if entry.kind != Kind.DESC:
            continue
        if not (entry.original.startswith('"') or entry.original.startswith("{")):
            continue
        rmap[f'"{entry.placeholder}"'] = entry.original
    return rmap


def _build_comment_reverse_map(ledger: Ledger) -> dict[str, str]:
    """Map ``# IRULE_COMMENT_NNNN`` (as it appears in sanitized output,
    re-tokenized as a single COMMENT token) back to the original COMMENT
    token text. Key includes the leading ``#`` so a direct
    ``tok.value`` lookup works."""
    rmap: dict[str, str] = {}
    for entry in ledger.entries.values():
        if entry.kind != Kind.IRULE_COMMENT:
            continue
        rmap[f"# {entry.placeholder}"] = entry.original
    return rmap


def _build_reverse_map(ledger: Ledger) -> dict[str, str]:
    """Build the rendered-placeholder -> original lookup table.

    Keys are the string forms that pass-2 substitution actually emits:
    bare ``PARTITION_NNNN`` for partition references, ``/Common/POOL_NNNN``
    for Common-partition objects, ``/PARTITION_NNNN/POOL_NNNN`` for
    non-Common objects, and bare ``POOL_NNNN`` for entries with no
    partition. Same partition-invariant guard as the forward path:
    if a non-Common object's partition has no ``PARTITION_NNNN`` entry,
    refuse — the ledger is inconsistent and deobfuscation would either
    fail silently or leak the literal partition name.
    """
    rmap: dict[str, str] = {}
    for entry in ledger.entries.values():
        # QSTRING-form and braced-form DESC entries are routed through
        # the qstring reverse map; skip here to avoid spurious
        # WORD-level matches.
        if entry.kind == Kind.DESC and (
            entry.original.startswith('"') or entry.original.startswith("{")
        ):
            continue
        # IRULE_COMMENT entries route through the comment reverse map.
        if entry.kind == Kind.IRULE_COMMENT:
            continue
        if entry.kind == Kind.PARTITION:
            rmap[entry.placeholder] = entry.original
        elif entry.partition is None:
            rmap[entry.placeholder] = entry.original
        elif entry.partition == "Common":
            rmap[f"/Common/{entry.placeholder}"] = entry.original
        else:
            part_ph = ledger.by_original.get((Kind.PARTITION, entry.partition))
            if part_ph is None:
                raise RuntimeError(
                    f"ledger invariant violated during deobfuscation: "
                    f"object {entry.placeholder} references partition "
                    f"{entry.partition!r} which has no PARTITION entry."
                )
            rmap[f"/{part_ph}/{entry.placeholder}"] = entry.original
    return rmap


# ---------------------------------------------------------------------
# v0.0.12 — Tcl QSTRING substring substitution inside iRule bodies
# ---------------------------------------------------------------------


def _build_substring_render_map(
    ledger: Ledger,
    kind_filter: set[Kind] | None = None,
) -> dict[str, list[tuple[str, str, str, frozenset[str]]]]:
    """First-char-bucketed substring lookup table for QSTRING contents.

    For each ledger entry, computes the rendered placeholder text exactly
    as pass-2 would emit a standalone WORD reference (path-bearing kinds
    get ``/Common/POOL_NNNN`` or ``/PARTITION_NNNN/POOL_NNNN`` shape;
    bare-placeholder kinds emit plain ``PARTITION_NNNN``). Entries are
    indexed by their original's first character; each bucket is sorted
    by ``len(original)`` descending so callers can scan
    longest-match-first.

    Skipped unconditionally: DESC (description bodies don't appear
    inside Tcl strings as meaningful content) and IRULE_COMMENT (the
    placeholder is a COMMENT token, not a substring target).

    ``kind_filter`` narrows to a specific set of kinds. v0.0.13 uses
    ``{Kind.AD_GROUP_DN}`` to build the globally-applied AD DN map,
    while leaving ``kind_filter=None`` to build the full iRule-body map.

    Returns: ``{first_char: [(original, rendered, placeholder, right_word_chars), ...]}``.

    ``right_word_chars`` is the per-entry character set used for the
    RIGHT-side word-boundary check at substitution time. Most entries
    use the strict ``_WORD_CHARS``; ``Kind.FQDN`` uses
    ``_WORD_CHARS_FQDN_RIGHT`` (drops ``_``) to handle the F5 file-
    storage compound-filename shape ``<fqdn>_<index>``.
    """
    by_first_char: dict[str, list[tuple[str, str, str, frozenset[str]]]] = {}
    for entry in ledger.entries.values():
        if entry.kind in (Kind.DESC, Kind.IRULE_COMMENT):
            continue
        if kind_filter is not None and entry.kind not in kind_filter:
            continue
        if not entry.original:
            continue
        rendered = _rendered_for_substring(entry, ledger)
        if rendered is None:
            continue
        first = entry.original[0]
        right_wc = _right_word_chars_for_kind(entry.kind)
        by_first_char.setdefault(first, []).append(
            (entry.original, rendered, entry.placeholder, right_wc)
        )
        # v1.2 Phase 3b — F5 filestore colon-separator variant. For
        # path-shaped entries (entry.partition set), generate a
        # ``:partition:leaf`` form so substring sub catches references
        # in filestore paths like
        # ``/config/filestore/files_d/Common_d/X_d/:Common:<leaf>_NNNN_N``.
        # Uses relaxed right-boundary (drops ``_``) so the trailing
        # ``_<index>_<index>`` filestore suffix doesn't block matches.
        colon_variant = _colon_form_pair(entry, ledger)
        if colon_variant is not None:
            colon_orig, colon_rendered = colon_variant
            by_first_char.setdefault(colon_orig[0], []).append(
                (colon_orig, colon_rendered, entry.placeholder,
                 _WORD_CHARS_FQDN_RIGHT)
            )
    for lst in by_first_char.values():
        lst.sort(key=lambda x: -len(x[0]))
    return by_first_char


def _colon_form_pair(entry: LedgerEntry, ledger: Ledger) -> tuple[str, str] | None:
    """For a path-shaped entry, return the colon-separator variant
    ``(:partition:leaf, :partition:placeholder)``. Returns None for
    non-path entries (partition=None) or malformed paths.

    Examples:
    - entry.original=/Common/foo, partition=Common, placeholder=POOL_0001
      → (":Common:foo", ":Common:POOL_0001")
    - entry.original=/Tenant_A/foo, partition=Tenant_A,
      placeholder=POOL_0001, PARTITION_0001=Tenant_A
      → (":Tenant_A:foo", ":PARTITION_0001:POOL_0001")
    """
    if entry.partition is None:
        return None
    if not entry.original.startswith(f"/{entry.partition}/"):
        return None
    prefix_len = 1 + len(entry.partition) + 1  # ``/`` + part + ``/``
    leaf = entry.original[prefix_len:]
    if not leaf:
        return None
    colon_orig = f":{entry.partition}:{leaf}"
    if entry.partition == COMMON_PARTITION:
        colon_rendered = f":Common:{entry.placeholder}"
    else:
        part_ph = ledger.by_original.get((Kind.PARTITION, entry.partition))
        if part_ph is None:
            return None
        colon_rendered = f":{part_ph}:{entry.placeholder}"
    return colon_orig, colon_rendered


def _right_word_chars_for_kind(kind: Kind) -> frozenset[str]:
    """Per-kind right-boundary char set. Default is strict
    ``_WORD_CHARS``; FQDN relaxes (drops ``_``) so the F5
    compound-filename shape ``<fqdn>_<index>`` substitutes cleanly."""
    if kind == Kind.FQDN:
        return _WORD_CHARS_FQDN_RIGHT
    return _WORD_CHARS


def _build_substring_reverse_render_map(
    ledger: Ledger,
    kind_filter: set[Kind] | None = None,
) -> dict[str, list[tuple[str, str, frozenset[str]]]]:
    """Reverse counterpart of :func:`_build_substring_render_map`. Same
    eligibility rules and ``kind_filter`` semantics; indexed by the
    rendered placeholder's first character; each bucket sorted by
    ``len(rendered)`` descending.

    Returns: ``{first_char: [(rendered, original, right_word_chars), ...]}``.
    """
    by_first_char: dict[str, list[tuple[str, str, frozenset[str]]]] = {}
    for entry in ledger.entries.values():
        if entry.kind in (Kind.DESC, Kind.IRULE_COMMENT):
            continue
        if kind_filter is not None and entry.kind not in kind_filter:
            continue
        if not entry.original:
            continue
        rendered = _rendered_for_substring(entry, ledger)
        if rendered is None:
            continue
        first = rendered[0]
        right_wc = _right_word_chars_for_kind(entry.kind)
        by_first_char.setdefault(first, []).append(
            (rendered, entry.original, right_wc)
        )
        # v1.2 Phase 3b — colon-separator variant (reverse). Mirror
        # _build_substring_render_map's filestore-path handling.
        colon_variant = _colon_form_pair(entry, ledger)
        if colon_variant is not None:
            colon_orig, colon_rendered = colon_variant
            by_first_char.setdefault(colon_rendered[0], []).append(
                (colon_rendered, colon_orig, _WORD_CHARS_FQDN_RIGHT)
            )
    for lst in by_first_char.values():
        lst.sort(key=lambda x: -len(x[0]))
    return by_first_char


def _rendered_for_substring(entry: LedgerEntry, ledger: Ledger) -> str | None:
    """Compute the rendered placeholder string for a substring-substitution
    target. Returns ``None`` to signal the caller should skip this entry
    (only fires when a non-Common partition entry lacks its PARTITION
    placeholder — a ledger inconsistency the forward pass would already
    have crashed on for any path-token reference, so silently skipping
    here is safe)."""
    if entry.kind == Kind.PARTITION:
        return entry.placeholder
    if entry.partition is None:
        return entry.placeholder
    if entry.partition == COMMON_PARTITION:
        return f"/Common/{entry.placeholder}"
    part_ph = ledger.by_original.get((Kind.PARTITION, entry.partition))
    if part_ph is None:
        return None
    return f"/{part_ph}/{entry.placeholder}"


def _substitute_in_irule_qstring(
    tok: Token,
    by_first_char: dict[str, list[tuple[str, str, str]]],
    ledger: Ledger,
) -> str:
    """Substring-substitute identifier originals inside a Tcl QSTRING
    that falls within an ``ltm rule`` body.

    Walks the QSTRING value character-by-character; at each position the
    first-char bucket of candidates is consulted longest-first. A match
    is accepted only when both sides are non-word characters (or the
    string boundary) so ``mypool1`` does not false-match a ``pool1``
    ledger original. On match, emits the rendered placeholder, records
    a Ref, and advances past the match. Otherwise emits one char
    verbatim and advances by 1.

    The wrapping ``"..."`` quotes are part of ``tok.value`` and pass
    through unchanged because ``"`` is a non-word boundary; substitutions
    never overlap the quotes themselves.
    """
    s = tok.value
    n = len(s)
    parts: list[str] = []
    i = 0
    while i < n:
        ch = s[i]
        candidates = by_first_char.get(ch, ())
        matched = False
        for original, rendered, placeholder, right_word_chars in candidates:
            olen = len(original)
            if i + olen > n:
                continue
            if not s.startswith(original, i):
                continue
            left_ok = (i == 0) or (s[i - 1] not in _WORD_CHARS)
            right_pos = i + olen
            right_ok = (
                right_pos == n or s[right_pos] not in right_word_chars
            )
            if not (left_ok and right_ok):
                continue
            parts.append(rendered)
            ledger.record_reference(
                placeholder,
                Ref(
                    byte_offset=tok.offset + i,
                    length=olen,
                    line=tok.line,
                ),
            )
            i = right_pos
            matched = True
            break
        if not matched:
            parts.append(ch)
            i += 1
    return "".join(parts)


def _reverse_substitute_in_irule_qstring(
    tok: Token,
    by_first_char: dict[str, list[tuple[str, str, frozenset[str]]]],
) -> str:
    """Reverse of :func:`_substitute_in_irule_qstring`: walk the
    sanitized QSTRING and replace each rendered-placeholder substring
    with the original ledger value. Same per-entry right-boundary
    protection (FQDN relaxed; others strict)."""
    s = tok.value
    n = len(s)
    parts: list[str] = []
    i = 0
    while i < n:
        ch = s[i]
        candidates = by_first_char.get(ch, ())
        matched = False
        for rendered, original, right_word_chars in candidates:
            rlen = len(rendered)
            if i + rlen > n:
                continue
            if not s.startswith(rendered, i):
                continue
            left_ok = (i == 0) or (s[i - 1] not in _WORD_CHARS)
            right_pos = i + rlen
            right_ok = (
                right_pos == n or s[right_pos] not in right_word_chars
            )
            if not (left_ok and right_ok):
                continue
            parts.append(original)
            i = right_pos
            matched = True
            break
        if not matched:
            parts.append(ch)
            i += 1
    return "".join(parts)
