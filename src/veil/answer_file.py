"""f5-veil answer file — AES-256-GCM encrypted persistence of the ledger.

The answer file is the deobfuscation key: anyone with the file AND the
passphrase can recover the original BIG-IP config from sanitized output.
Treat it like a UCS archive — protect accordingly, never commit it
(``.gitignore`` blocks ``*.answers.enc`` by default).

Threat model
------------
- File-at-rest disclosure (laptop loss, backup leak): AES-256-GCM +
  scrypt KDF makes brute-forcing infeasible for any reasonable passphrase.
- Wrong-passphrase oracle: a single
  :class:`AnswerFileError` ``("decryption failed")`` is raised; callers
  cannot distinguish "wrong passphrase" from "tampered file."
- Tampered ciphertext, nonce, salt, or KDF params: AES-GCM authenticated
  decryption fails closed. Any change to KDF params (e.g. attacker
  reduces ``n`` for easier brute force) derives a different key, which
  fails the GCM tag — no weakening attack.

Envelope (versioned JSON)::

    {
      "veil_answer_file_version": 1,
      "kdf": {"algorithm": "scrypt", "n": 131072, "r": 8, "p": 1,
              "length": 32, "salt": "<base64>"},
      "encryption": {"algorithm": "AES-256-GCM", "nonce": "<base64>"},
      "ciphertext": "<base64>"
    }

Plaintext payload (versioned JSON, then encrypted)::

    {
      "veil_payload_version": 1,
      "ledger": {"entries": [{"placeholder": "POOL_0001", ...}, ...]},
      "diagnostics": {...}
    }

Both layers use ``json.dumps(..., sort_keys=True, indent=2)`` for
deterministic, diff-friendly output (audit-friendly).

Known limitations deferred
--------------------------
- No Associated Authenticated Data binding the envelope identity to the
  ciphertext. Not needed in v0.1 because any envelope tampering changes
  the derived key and breaks the GCM tag; revisit if a use case for
  envelope-identity binding emerges.
- No fsync before rename. Atomic in the POSIX sense (rename is atomic
  on a single filesystem) but a power loss between write and fsync can
  lose the new file on some filesystems. Acceptable for v0.1.
- Python memory hygiene: plaintext payload and passphrase live in
  ``bytes``/``str`` objects subject to normal garbage collection.
  Python does not expose ``memset_s``-style explicit zeroing, so a
  process memory dump after decryption could expose both. Common
  Python limitation; would require switching to a compiled crypto
  helper to address.
- Asymmetric error messages: ``"decryption failed"`` for ``InvalidTag``
  versus ``"answer file envelope is malformed"`` for KDF-param
  corruption. The asymmetry does not leak information that would help
  recover the legitimate key (attacker still needs the passphrase),
  so it is accepted in v0.1.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .diagnostics import Diagnostics
from .ledger import Kind, Ledger, LedgerEntry, Ref


SUPPORTED_ENVELOPE_VERSIONS = frozenset({1})
SUPPORTED_PAYLOAD_VERSIONS = frozenset({1})

# OWASP 2024 interactive-scrypt recommendation. ~130 ms key derivation
# on a 2023-era laptop CPU. Encoded in the envelope so a future param
# change does not break existing files.
_SCRYPT_N = 2**17  # 131072
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LENGTH = 32  # AES-256
_SALT_LENGTH = 16
_NONCE_LENGTH = 12


class AnswerFileError(Exception):
    """Single exception type for all answer-file failures. The message
    is intentionally generic on the decryption path so attackers cannot
    distinguish wrong-passphrase from tampered-file via timing or
    message-content inspection."""


def write_answer_file(
    path: str | os.PathLike[str],
    ledger: Ledger,
    passphrase: bytes | str,
    *,
    diagnostics: Diagnostics | None = None,
) -> None:
    """Encrypt the ledger (and optional diagnostics) and write to ``path``.

    Atomic: writes to ``<path>.tmp`` and ``os.replace``s into place. If
    the ledger is unfrozen, freezes it before serialization (the answer
    file must reflect a final ledger state, not one mid-mutation).
    """
    path = Path(path)
    if not ledger.frozen:
        ledger.freeze()
    payload_bytes = _payload_to_bytes(ledger, diagnostics or Diagnostics())
    salt = os.urandom(_SALT_LENGTH)
    nonce = os.urandom(_NONCE_LENGTH)
    key = _derive_key(
        _normalize_passphrase(passphrase),
        salt,
        _SCRYPT_N,
        _SCRYPT_R,
        _SCRYPT_P,
        _KEY_LENGTH,
    )
    ciphertext = AESGCM(key).encrypt(nonce, payload_bytes, associated_data=None)
    envelope = {
        "veil_answer_file_version": 1,
        "kdf": {
            "algorithm": "scrypt",
            "n": _SCRYPT_N,
            "r": _SCRYPT_R,
            "p": _SCRYPT_P,
            "length": _KEY_LENGTH,
            "salt": base64.b64encode(salt).decode("ascii"),
        },
        "encryption": {
            "algorithm": "AES-256-GCM",
            "nonce": base64.b64encode(nonce).decode("ascii"),
        },
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    envelope_bytes = json.dumps(envelope, sort_keys=True, indent=2).encode("utf-8")
    try:
        _atomic_write(path, envelope_bytes)
    except OSError as exc:
        raise AnswerFileError(f"could not write answer file: {exc!s}") from exc


def read_answer_file(
    path: str | os.PathLike[str],
    passphrase: bytes | str,
) -> tuple[Ledger, Diagnostics]:
    """Decrypt and load an answer file. Returns ``(ledger, diagnostics)``.

    The returned ledger is frozen. Any failure raises
    :class:`AnswerFileError`; the decryption-failure path uses a
    deliberately generic message to avoid an oracle.
    """
    path = Path(path)
    try:
        envelope_bytes = path.read_bytes()
    except OSError as exc:
        raise AnswerFileError(f"could not read answer file: {exc!s}") from exc
    try:
        envelope = json.loads(envelope_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise AnswerFileError("answer file is not valid JSON") from None
    version = envelope.get("veil_answer_file_version")
    if version not in SUPPORTED_ENVELOPE_VERSIONS:
        raise AnswerFileError(
            f"unsupported answer-file version: {version!r}"
        )
    try:
        kdf_meta = envelope["kdf"]
        enc_meta = envelope["encryption"]
        if kdf_meta.get("algorithm") != "scrypt":
            raise AnswerFileError(
                f"unsupported KDF algorithm: {kdf_meta.get('algorithm')!r}"
            )
        if enc_meta.get("algorithm") != "AES-256-GCM":
            raise AnswerFileError(
                f"unsupported cipher: {enc_meta.get('algorithm')!r}"
            )
        salt = base64.b64decode(kdf_meta["salt"], validate=True)
        nonce = base64.b64decode(enc_meta["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        n = int(kdf_meta["n"])
        r = int(kdf_meta["r"])
        p = int(kdf_meta["p"])
        length = int(kdf_meta["length"])
    except AnswerFileError:
        raise
    except (KeyError, ValueError, TypeError, AttributeError):
        # AttributeError covers envelope subfields that parsed as the
        # wrong JSON shape — e.g. ``envelope["kdf"]`` ending up as a list
        # instead of a dict, which would make ``.get("algorithm")`` blow
        # up. All such cases collapse to "malformed envelope" so the
        # caller sees a single exception type, not a Python traceback.
        raise AnswerFileError("answer file envelope is malformed") from None
    try:
        key = _derive_key(
            _normalize_passphrase(passphrase), salt, n, r, p, length
        )
        aesgcm = AESGCM(key)
    except (ValueError, TypeError):
        # Bad KDF params or key length — envelope was modified.
        raise AnswerFileError("answer file envelope is malformed") from None
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag:
        raise AnswerFileError("decryption failed") from None
    except ValueError:
        # Bad nonce length or similar — treat as envelope tamper.
        raise AnswerFileError("answer file envelope is malformed") from None
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Cryptographically improbable — auth tag passed but bytes are
        # not JSON. Surface generically to avoid any oracle.
        raise AnswerFileError("decryption failed") from None
    return _payload_from_dict(payload)


# ---------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------


def _normalize_passphrase(p: bytes | str) -> bytes:
    if isinstance(p, str):
        return p.encode("utf-8")
    if isinstance(p, bytes):
        return p
    raise TypeError(
        f"passphrase must be bytes or str, got {type(p).__name__}"
    )


def _derive_key(
    passphrase: bytes,
    salt: bytes,
    n: int,
    r: int,
    p: int,
    length: int,
) -> bytes:
    return Scrypt(salt=salt, length=length, n=n, r=r, p=p).derive(passphrase)


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    try:
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _payload_to_bytes(ledger: Ledger, diagnostics: Diagnostics) -> bytes:
    payload = {
        "veil_payload_version": 1,
        "ledger": {"entries": ledger.dump_unsafe()},
        "diagnostics": {
            "unknown_top_level": [
                list(t) for t in diagnostics.unknown_top_level
            ],
            "malformed_paths": [
                list(t) for t in diagnostics.malformed_paths
            ],
            "unredacted_description": [
                list(t) for t in diagnostics.unredacted_description
            ],
            "qstring_contains_identifier": [
                list(t) for t in diagnostics.qstring_contains_identifier
            ],
            "orphan_entries": list(diagnostics.orphan_entries),
        },
    }
    return json.dumps(payload, sort_keys=True, indent=2).encode("utf-8")


def _payload_from_dict(payload: dict) -> tuple[Ledger, Diagnostics]:
    version = payload.get("veil_payload_version")
    if version not in SUPPORTED_PAYLOAD_VERSIONS:
        raise AnswerFileError(
            f"unsupported payload version: {version!r}"
        )
    try:
        ledger = _ledger_from_entries(payload["ledger"]["entries"])
        diagnostics = _diagnostics_from_dict(payload.get("diagnostics", {}))
    except (KeyError, ValueError, TypeError):
        raise AnswerFileError("decrypted payload is malformed") from None
    return ledger, diagnostics


def _ledger_from_entries(entries: list[dict]) -> Ledger:
    ledger = Ledger()
    for e in entries:
        placeholder = e["placeholder"]
        kind = Kind(e["kind"])
        partition = e["partition"]  # may be None
        original = e["original"]
        disc = e["discovery"]
        discovery = Ref(
            byte_offset=int(disc["byte_offset"]),
            length=int(disc["length"]),
            line=int(disc["line"]),
        )
        ledger.entries[placeholder] = LedgerEntry(
            placeholder=placeholder,
            original=original,
            kind=kind,
            partition=partition,
            discovery=discovery,
        )
        ledger.by_original[(kind, original)] = placeholder
        # Counter = highest numeric suffix per kind so future interns
        # (after an unfreeze, if v2.0 supports it) keep counting up.
        try:
            n = int(placeholder.rsplit("_", 1)[1])
        except (IndexError, ValueError):
            continue
        if ledger.counters.get(kind, 0) < n:
            ledger.counters[kind] = n
    ledger.freeze()
    return ledger


def _diagnostics_from_dict(d: dict) -> Diagnostics:
    return Diagnostics(
        unknown_top_level=[tuple(x) for x in d.get("unknown_top_level", [])],
        malformed_paths=[tuple(x) for x in d.get("malformed_paths", [])],
        unredacted_description=[
            tuple(x) for x in d.get("unredacted_description", [])
        ],
        qstring_contains_identifier=[
            tuple(x) for x in d.get("qstring_contains_identifier", [])
        ],
        orphan_entries=list(d.get("orphan_entries", [])),
    )
