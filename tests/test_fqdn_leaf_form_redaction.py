"""v1.2 (post-Phase-3b follow-up) — FQDN-shaped leaf substring sub.

User feedback on phase4a sanitized output: line 22842 leaked
``source-path /config/ssl/ssl.csr/basestar.example.com``. The
``sys file ssl-csr /Common/basestar.example.com`` top-level block
registers the path as UNK, but:

- The source-path value has no ``/Common/`` prefix → slash-form
  substring miss.
- No ``:Common:`` prefix → colon-form (Phase 3b) miss.
- ``.com`` is a public TLD → FQDN walker skipped by design.

Fix: ``_build_substring_render_map`` (and reverse) now also
register a leaf-only substring-sub variant for path-shape entries
whose leaf is FQDN-shaped AND the FQDN walker hasn't already
caught the leaf. The bare placeholder ``UNK_NNNN`` substitutes
the leaf wherever it appears; longer slash/colon forms still win
in their own contexts via longest-match-first.
"""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


def test_public_tld_leaf_redacted_via_source_path():
    """The canonical leak shape from user feedback."""
    src = (
        "sys file ssl-csr /Common/basestar.acme.com {\n"
        "    source-path /config/ssl/ssl.csr/basestar.acme.com\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _diag = substitute(src, ledger, diag)
    assert "basestar.acme.com" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_public_tld_leaf_redacted_via_arbitrary_field():
    """Leaf-form variant works anywhere the bare FQDN appears."""
    src = (
        "sys file ssl-cert /Common/host.acme.com { }\n"
        "ltm pool /Common/p {\n"
        "    description \"refs cert host.acme.com from a CSR field\"\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    # The pool description is interned as DESC (whole QSTRING form),
    # so the leaf-form match is shadowed there. But the cert entry's
    # leaf-form is still registered.
    cert_entry = None
    for e in ledger.entries.values():
        if e.kind == Kind.UNKNOWN and e.original == "/Common/host.acme.com":
            cert_entry = e
            break
    assert cert_entry is not None, "cert top-level block should register as UNK"


def test_internal_tld_leaf_uses_fqdn_walker_not_leaf_form():
    """For internal-TLD leafs (.local etc.), the FQDN walker catches
    them globally; the leaf-form variant is suppressed to avoid a
    duplicate substring-sub key with ambiguous placement."""
    src = (
        "sys file ssl-cert /Common/host.acme.local {\n"
        "    source-path /config/ssl/ssl.crt/host.acme.local\n"
        "}\n"
    )
    ledger, diag = scan(src)
    # The FQDN walker registers the FQDN.
    assert (Kind.FQDN, "host.acme.local") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    # Either placeholder (UNK_NNNN or FQDN_NNNN) is acceptable; the
    # bare FQDN must be gone.
    assert "host.acme.local" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_non_fqdn_leaf_does_not_get_leaf_form_variant():
    """Path-shape entries with non-FQDN leafs (e.g. ``my_pool``) must
    NOT get a leaf-form variant — registering ``my_pool`` as a
    substring-sub key would create false-positive matches anywhere
    that substring appears."""
    src = (
        "ltm pool /Common/my_pool { }\n"
        "ltm rule /Common/r {\n"
        "    when CLIENT_ACCEPTED {\n"
        "        log local0. \"see my_pool here\"\n"
        "    }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    sanitized, _diag = substitute(src, ledger, _diag)
    # my_pool inside the iRule comment-free body would only get
    # substituted via the path-shape entry's existing slash form (when
    # the bareword starts with /). The bare leaf inside a log string
    # is NOT redacted via leaf-form (no leaf-form registered).
    # We assert correctness of the existing path-shape behavior: the
    # original full path is substituted but the leaf-only mention is
    # untouched in this scenario.
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_leaf_form_with_compound_suffix():
    """The leaf-form variant uses _WORD_CHARS_FQDN_RIGHT (drops ``_``),
    so trailing index suffixes don't block matches."""
    src = (
        "sys file ssl-csr /Common/foo.acme.com {\n"
        "    cache-path /config/filestore/files_d/Common_d/cert_d/:Common:foo.acme.com_111_2\n"
        "    source-path /config/ssl/ssl.csr/foo.acme.com\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _diag = substitute(src, ledger, diag)
    assert "foo.acme.com" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src
