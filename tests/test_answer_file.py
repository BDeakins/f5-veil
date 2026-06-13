import json
import tempfile
from pathlib import Path

from veil.answer_file import (
    AnswerFileError,
    read_answer_file,
    write_answer_file,
)
from veil.diagnostics import Diagnostics
from veil.ledger import Kind, Ledger, Ref
from veil.scanner import scan
from veil.substitute import substitute


def _sample_ledger_and_diag():
    src = (
        "ltm pool /Tenant_A/customer_app_pool {\n"
        "}\n"
        "ltm virtual /Tenant_A/vs_customer_app {\n"
        "    pool /Tenant_A/customer_app_pool\n"
        "}\n"
    )
    ledger, diag = scan(src)
    substitute(src, ledger, diag)
    return ledger, diag


def test_round_trip_recovers_all_ledger_entries():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        ledger, diag = _sample_ledger_and_diag()
        write_answer_file(
            path, ledger, "correct horse battery staple", diagnostics=diag
        )
        loaded_ledger, _, _ = read_answer_file(
            path, "correct horse battery staple"
        )
        assert set(loaded_ledger.entries.keys()) == set(ledger.entries.keys())
        for ph, entry in ledger.entries.items():
            le = loaded_ledger.entries[ph]
            assert le.original == entry.original
            assert le.kind == entry.kind
            assert le.partition == entry.partition
            assert le.discovery == entry.discovery
        assert loaded_ledger.frozen is True
        # Counters round-trip too.
        assert loaded_ledger.counters == ledger.counters


def test_round_trip_recovers_all_diagnostic_fields():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        ledger, diag = _sample_ledger_and_diag()
        diag.unknown_top_level.append(("gtm wideip", 42))
        diag.malformed_paths.append(("POOL", "/Common/", 5))
        diag.unredacted_description.append((100, 7))
        diag.qstring_contains_identifier.append(("POOL_0001", 200, 11))
        diag.orphan_entries.append("VS_9999")
        write_answer_file(path, ledger, "passphrase", diagnostics=diag)
        _, loaded_diag, _ = read_answer_file(path, "passphrase")
        assert ("gtm wideip", 42) in loaded_diag.unknown_top_level
        assert ("POOL", "/Common/", 5) in loaded_diag.malformed_paths
        assert (100, 7) in loaded_diag.unredacted_description
        assert ("POOL_0001", 200, 11) in loaded_diag.qstring_contains_identifier
        assert "VS_9999" in loaded_diag.orphan_entries


def test_wrong_passphrase_raises_generic_decryption_failed():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        ledger, diag = _sample_ledger_and_diag()
        write_answer_file(path, ledger, "correct", diagnostics=diag)
        try:
            read_answer_file(path, "wrong")
        except AnswerFileError as exc:
            assert "decryption failed" in str(exc)
            return
        raise AssertionError("expected AnswerFileError for wrong passphrase")


def test_tampered_ciphertext_raises_decryption_failed():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        ledger, diag = _sample_ledger_and_diag()
        write_answer_file(path, ledger, "passphrase", diagnostics=diag)
        envelope = json.loads(path.read_text())
        # Flip the leading character of the ciphertext to break the GCM tag.
        ct = envelope["ciphertext"]
        ct_list = list(ct)
        ct_list[0] = "A" if ct_list[0] != "A" else "B"
        envelope["ciphertext"] = "".join(ct_list)
        path.write_text(json.dumps(envelope))
        try:
            read_answer_file(path, "passphrase")
        except AnswerFileError as exc:
            assert "decryption failed" in str(exc)
            return
        raise AssertionError(
            "expected AnswerFileError for tampered ciphertext"
        )


def test_tampered_kdf_n_does_not_weaken_or_succeed():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        ledger, diag = _sample_ledger_and_diag()
        write_answer_file(path, ledger, "passphrase", diagnostics=diag)
        envelope = json.loads(path.read_text())
        envelope["kdf"]["n"] = 1024  # attacker reduces to brute-forceable n
        path.write_text(json.dumps(envelope))
        try:
            read_answer_file(path, "passphrase")
        except AnswerFileError as exc:
            # Either "decryption failed" or "envelope malformed" is fine —
            # the point is the modified envelope does NOT yield plaintext.
            assert (
                "decryption failed" in str(exc)
                or "malformed" in str(exc).lower()
            )
            return
        raise AssertionError(
            "expected AnswerFileError for tampered KDF params"
        )


def test_malformed_envelope_json_raises():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        path.write_text("not json at all {{{")
        try:
            read_answer_file(path, "anything")
        except AnswerFileError as exc:
            assert "not valid JSON" in str(exc) or "malformed" in str(exc).lower()
            return
        raise AssertionError("expected AnswerFileError for malformed JSON")


def test_unknown_envelope_version_raises():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        envelope = {
            "veil_answer_file_version": 99,
            "kdf": {},
            "encryption": {},
            "ciphertext": "",
        }
        path.write_text(json.dumps(envelope))
        try:
            read_answer_file(path, "anything")
        except AnswerFileError as exc:
            msg = str(exc).lower()
            assert "unsupported" in msg and "version" in msg
            return
        raise AssertionError("expected AnswerFileError for unknown version")


def test_passphrase_accepts_both_bytes_and_str():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        ledger, diag = _sample_ledger_and_diag()
        write_answer_file(path, ledger, "passphrase", diagnostics=diag)
        loaded1, _, _ = read_answer_file(path, "passphrase")
        loaded2, _, _ = read_answer_file(path, b"passphrase")
        assert set(loaded1.entries) == set(loaded2.entries)


def test_atomic_write_replaces_existing_file_cleanly():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        path.write_bytes(b"existing garbage")
        ledger, diag = _sample_ledger_and_diag()
        write_answer_file(path, ledger, "passphrase", diagnostics=diag)
        loaded, _, _ = read_answer_file(path, "passphrase")
        assert "POOL_0001" in loaded.entries
        # tmp file is cleaned up
        assert not (Path(td) / "answers.enc.tmp").exists()


def test_envelope_does_not_leak_originals_in_plaintext():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        ledger, diag = _sample_ledger_and_diag()
        write_answer_file(path, ledger, "passphrase", diagnostics=diag)
        envelope_text = path.read_text()
        assert "Tenant_A" not in envelope_text
        assert "customer_app_pool" not in envelope_text
        assert "vs_customer_app" not in envelope_text


def test_each_write_uses_a_fresh_nonce_and_salt():
    with tempfile.TemporaryDirectory() as td:
        path1 = Path(td) / "a.enc"
        path2 = Path(td) / "b.enc"
        ledger, diag = _sample_ledger_and_diag()
        write_answer_file(path1, ledger, "passphrase", diagnostics=diag)
        write_answer_file(path2, ledger, "passphrase", diagnostics=diag)
        env1 = json.loads(path1.read_text())
        env2 = json.loads(path2.read_text())
        assert env1["encryption"]["nonce"] != env2["encryption"]["nonce"]
        assert env1["kdf"]["salt"] != env2["kdf"]["salt"]
        assert env1["ciphertext"] != env2["ciphertext"]


def test_write_freezes_an_unfrozen_ledger():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        ledger = Ledger()
        ledger.intern(
            Kind.POOL,
            "/Common/foo",
            Ref(byte_offset=9, length=11, line=1),
            partition="Common",
        )
        assert ledger.frozen is False
        write_answer_file(path, ledger, "passphrase")
        assert ledger.frozen is True


def test_writing_with_no_diagnostics_uses_empty_default():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        ledger, _ = _sample_ledger_and_diag()
        write_answer_file(path, ledger, "passphrase")  # no diagnostics=
        _, loaded_diag, _ = read_answer_file(path, "passphrase")
        assert loaded_diag.unknown_top_level == []
        assert loaded_diag.orphan_entries == []


def test_envelope_is_deterministic_modulo_random_salt_and_nonce():
    # Same passphrase + same plaintext + same envelope schema means the
    # only sources of variation between two writes are the random salt
    # and nonce. Everything else (algorithm names, KDF params, key
    # ordering) is stable.
    with tempfile.TemporaryDirectory() as td:
        path1 = Path(td) / "a.enc"
        path2 = Path(td) / "b.enc"
        ledger, diag = _sample_ledger_and_diag()
        write_answer_file(path1, ledger, "passphrase", diagnostics=diag)
        write_answer_file(path2, ledger, "passphrase", diagnostics=diag)
        env1 = json.loads(path1.read_text())
        env2 = json.loads(path2.read_text())
        # Same structural keys, same algorithm names, same KDF params
        assert sorted(env1.keys()) == sorted(env2.keys())
        assert env1["veil_answer_file_version"] == env2["veil_answer_file_version"]
        assert env1["kdf"]["algorithm"] == env2["kdf"]["algorithm"]
        assert env1["encryption"]["algorithm"] == env2["encryption"]["algorithm"]
        assert env1["kdf"]["n"] == env2["kdf"]["n"]


def test_sources_round_trip_when_set():
    """v1.2 multi-file mode: the ``sources`` list of input filenames
    round-trips through write/read."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        ledger, diag = _sample_ledger_and_diag()
        write_answer_file(
            path, ledger, "passphrase",
            diagnostics=diag,
            sources=["bigip_base.conf", "bigip.conf"],
        )
        _, _, loaded_sources = read_answer_file(path, "passphrase")
        assert loaded_sources == ["bigip_base.conf", "bigip.conf"]


def test_sources_absent_returns_none():
    """Single-file mode (the default and the v1.0/v1.1 behavior) omits
    the ``sources`` field; the reader returns ``None``."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        ledger, diag = _sample_ledger_and_diag()
        write_answer_file(path, ledger, "passphrase", diagnostics=diag)
        _, _, loaded_sources = read_answer_file(path, "passphrase")
        assert loaded_sources is None
        # And the envelope plaintext must not have a ``sources`` key
        # (would surface in audit grep against the encrypted file).
        envelope = json.loads(path.read_text())
        assert "sources" not in envelope  # not in envelope either way
        # We can't easily inspect the plaintext without the passphrase
        # in this test; absence-via-reader is the contract that matters.


def test_sources_empty_list_round_trips_as_empty_list():
    """An empty ``sources=[]`` is distinct from ``sources=None``: it
    records "this was multi-file mode but with zero input files," which
    is degenerate but not the same as the absent case. Pin the
    distinction."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        ledger, diag = _sample_ledger_and_diag()
        write_answer_file(
            path, ledger, "passphrase", diagnostics=diag, sources=[]
        )
        _, _, loaded_sources = read_answer_file(path, "passphrase")
        assert loaded_sources == []
        assert loaded_sources is not None


def test_unsupported_kdf_algorithm_raises():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        envelope = {
            "veil_answer_file_version": 1,
            "kdf": {"algorithm": "pbkdf2", "n": 1, "r": 1, "p": 1,
                    "length": 32, "salt": ""},
            "encryption": {"algorithm": "AES-256-GCM", "nonce": ""},
            "ciphertext": "",
        }
        path.write_text(json.dumps(envelope))
        try:
            read_answer_file(path, "anything")
        except AnswerFileError as exc:
            assert "unsupported KDF" in str(exc) or "kdf" in str(exc).lower()
            return
        raise AssertionError("expected AnswerFileError for non-scrypt KDF")


def test_unsupported_cipher_raises():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        envelope = {
            "veil_answer_file_version": 1,
            "kdf": {"algorithm": "scrypt", "n": 1, "r": 1, "p": 1,
                    "length": 32, "salt": ""},
            "encryption": {"algorithm": "ChaCha20-Poly1305", "nonce": ""},
            "ciphertext": "",
        }
        path.write_text(json.dumps(envelope))
        try:
            read_answer_file(path, "anything")
        except AnswerFileError as exc:
            assert "unsupported cipher" in str(exc) or "cipher" in str(exc).lower()
            return
        raise AssertionError("expected AnswerFileError for non-GCM cipher")


def test_envelope_with_wrong_shape_subfield_raises_answer_file_error():
    # CRUCIBLE C3-1: attacker-crafted envelope where "kdf" is a list,
    # not a dict, must surface as AnswerFileError — not a raw Python
    # AttributeError. Single-exception contract.
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        envelope = {
            "veil_answer_file_version": 1,
            "kdf": ["not", "a", "dict"],
            "encryption": {"algorithm": "AES-256-GCM", "nonce": ""},
            "ciphertext": "",
        }
        path.write_text(json.dumps(envelope))
        try:
            read_answer_file(path, "anything")
        except AnswerFileError as exc:
            assert "malformed" in str(exc).lower()
            return
        raise AssertionError(
            "expected AnswerFileError for envelope with wrong-shaped subfield"
        )


def test_passphrase_must_be_bytes_or_str():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "answers.enc"
        ledger, _ = _sample_ledger_and_diag()
        try:
            write_answer_file(path, ledger, 12345)  # int, not bytes/str
        except TypeError as exc:
            assert "bytes" in str(exc) and "str" in str(exc)
            return
        raise AssertionError("expected TypeError for non-bytes/str passphrase")
