"""Pass 2.2 — APM session-variable custom-namespace tokenization.

v1.2.1 T1B. Walks the token stream after the FQDN (pass-2.0) and
Kerberos-realm (pass-2.1) walkers; for every WORD or QSTRING token,
regex-scans for ``session.<seg1>(.<seg2>)?`` patterns and applies
option-C redaction:

1. ``session.custom.<word>.<rest>`` — interns ``<word>`` (the user-
   chosen segment under the F5-documented ``session.custom.`` user-
   namespace) as :class:`Kind.SESSION_NS`.
2. ``session.<word>.<rest>`` where ``<word>`` is NOT in the F5-
   builtin allowlist — interns ``<word>`` (the user-chosen first
   segment, e.g. ``session.tenants.acme.*``).
3. ``session.<builtin>.<rest>`` — pass through verbatim. F5 documents
   roughly 22 first-segment namespaces (``session.ad.*``,
   ``session.logon.*``, ``session.policy.*``, ...) that every APM
   config uses; tokenizing them would break iRule readability for
   downstream review without obfuscating customer data.

Placeholder vocab is the canonical 13-word metasyntactic set
(``foo``, ``bar``, ``baz``, ``qux``, ``quux``, ``corge``, ``grault``,
``garply``, ``waldo``, ``fred``, ``plugh``, ``xyzzy``, ``thud``),
allocated in order by :meth:`Ledger.intern_session_namespace_word`.
The visual signal — bare metasyntactic word, NOT ``KIND_NNNN`` — lets
reviewers see at a glance which substitutions are redacted org
namespaces.

Round-trip safety
-----------------
Vocab words can occur as legitimate identifiers in some configs
(``foo``, ``bar``, and ``baz`` especially are common in dev / test
contexts). If a vocab word also appears word-bounded in the source,
the reverse substitution pass would over-rewrite that pre-existing
occurrence and corrupt byte-exact round-trip. To avoid this,
:func:`preregister_session_ns_collisions` scans the source for
vocab words occurring with word boundaries on both sides and marks
those slots as unsafe BEFORE any per-file walker runs. The unsafe
set is ledger-wide, so :func:`veil.scanner.scan_many` must pre-scan
all input files before the first walker call.

Why this exists
---------------
v1.2 red-team T1B finding: customer portal name ``cygnus`` leaked
through ``session.custom.cygnus.webui.userid`` (and 17 sibling
references) because no walker covered the ``session.custom.<word>``
user-namespace. Vendor names also leaked at
``session.custom.grafana.*``, ``session.custom.owa.*``,
``session.custom.portainer.*``, ``session.custom.pihole.*``.
"""

from __future__ import annotations

import re

from .ledger import _SESSION_NS_VOCAB, Kind, Ledger, Ref
from .tokenizer import TokKind, tokenize


# F5-documented APM session-variable first-segment namespaces.
# Anything outside this set under ``session.`` is user-chosen and
# gets tokenized. ``custom`` is in the set but special-cased: it
# triggers second-segment tokenization (the user's word under
# ``session.custom.``).
_F5_BUILTIN_NAMESPACES = frozenset({
    "ad", "logon", "policy", "assigned", "sso", "saml", "oauth",
    "radius", "ldap", "kerberos", "krb", "check", "client",
    "server", "user", "ssl", "captcha", "accesscontrol", "idp",
    "sp", "modules", "last", "custom",
})

# Match ``session.<seg1>`` optionally followed by ``.<seg2>``.
# Left boundary uses a strict character lookaround to avoid
# false-matching the inner ``session.`` substring of words like
# ``mysession.custom.foo`` (rare, defensive).
_SESSION_VAR_RE = re.compile(
    r"(?<![A-Za-z0-9_.])"
    r"session\."
    r"(?P<seg1>[A-Za-z_][A-Za-z0-9_-]*)"
    r"(?:\.(?P<seg2>[A-Za-z_][A-Za-z0-9_-]*))?"
)


def preregister_session_ns_collisions(src: str, ledger: Ledger) -> None:
    """Scan ``src`` for word-bounded occurrences of any vocab word and
    register the colliding slots as unsafe with ``ledger``. Must be
    called BEFORE any :func:`discover_apm_session_namespaces` call on
    any source file in the batch — vocab assignments are ledger-wide
    and can't be safely retroactively reassigned once minted.

    Idempotent across calls (the unsafe set is a Python set)."""
    if not src:
        return
    colliding: list[str] = []
    for word in _SESSION_NS_VOCAB:
        if re.search(rf"\b{re.escape(word)}\b", src):
            colliding.append(word)
    if colliding:
        ledger.mark_session_ns_unsafe(colliding)


def discover_apm_session_namespaces(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Pass 2.2 — walk WORD/QSTRING tokens, find ``session.<seg>...``
    patterns, intern user-chosen segment words as
    :class:`Kind.SESSION_NS`. Must run before ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "apm_session_var_discovery must run before ledger.freeze()"
        )
    for tok in tokenize(src):
        if tok.kind not in (TokKind.WORD, TokKind.QSTRING):
            continue
        # Skip description bodies. The DESC walker has already
        # registered the whole token value as a single redacted
        # placeholder; if we sub-intern a session segment inside the
        # description body, both entries fight for substitution.
        if tok.kind == TokKind.QSTRING and (Kind.DESC, tok.value) in ledger.by_original:
            continue
        if tok.kind == TokKind.WORD and (Kind.DESC, tok.value) in ledger.by_original:
            continue
        for match in _SESSION_VAR_RE.finditer(tok.value):
            seg1 = match.group("seg1")
            seg2 = match.group("seg2")
            target = _select_target(seg1, seg2)
            if target is None:
                continue
            target_word, target_group = target
            target_span = match.span(target_group)
            ref = Ref(
                byte_offset=tok.offset + target_span[0],
                length=target_span[1] - target_span[0],
                line=tok.line,
            )
            ledger.intern_session_namespace_word(target_word, ref)


def _select_target(
    seg1: str, seg2: str | None,
) -> tuple[str, str] | None:
    """Apply option-C: if seg1 is ``custom`` AND seg2 exists, target
    seg2; else if seg1 is NOT in the F5 allowlist, target seg1; else
    pass through. Returns ``(word, regex_group_name)`` or ``None``."""
    if seg1 == "custom":
        if seg2 is None:
            return None
        # Guard against pathological segments (single char, all-digit)
        # to avoid noisy tokenization of obvious non-identifiers.
        if len(seg2) < 2 or seg2.isdigit():
            return None
        return seg2, "seg2"
    if seg1 in _F5_BUILTIN_NAMESPACES:
        return None
    if len(seg1) < 2 or seg1.isdigit():
        return None
    return seg1, "seg1"
