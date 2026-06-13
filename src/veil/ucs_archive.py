"""UCS (BIG-IP backup) archive ingestion — extract-only (v1.2).

A UCS is a gzipped tarball containing every config + state file the F5
appliance needs to restore itself. We treat it as a multi-file *input
source* only: extract the four well-known config files, hand them to
``scan_many`` / ``substitute``, and emit them as separate sanitized
text files.

We never recreate the UCS. The original UCS stays on the operator's
disk; the sanitized output is text files in ``--output-dir``. The
operator hands those to an LLM, then deobfuscates them back with
``veil deobfuscate`` (and, if desired, manually re-packs them into
the original UCS shape).

Hard rules
----------
- Allowlist only: ``config/bigip_base.conf``, ``config/bigip.conf``,
  ``config/bigip_user.conf``. Every other archive member is ignored
  (see :data:`CONFIG_MEMBERS_OPTIONAL` for why
  ``config/bigip_script.conf`` is NOT in the allowlist).
- Required: ``config/bigip.conf`` and ``config/bigip_base.conf``.
  ``config/bigip_user.conf`` is optional (older F5 versions may
  omit it).
- Defensive: reject allowlisted members that are symlinks /
  hardlinks / directories, have absolute paths, or contain ``..``
  segments. The allowlist itself already pins the canonical paths;
  these checks are belt-and-braces for malicious tarballs.
- Per-member size cap: ``MAX_CONFIG_MEMBER_BYTES`` = 50 MiB. Real
  BIG-IP config-file members top out around 2 MB; the cap refuses
  tar-bomb-style oversized members.
- Strict UTF-8 decoding. A config that does not decode is refused —
  silent mangling would defeat round-trip exactness.
- ``.diffVersions/`` snapshots and every other non-allowlisted
  member are ignored entirely (never read, never written).
"""

from __future__ import annotations

import tarfile
from dataclasses import dataclass
from pathlib import Path

_UCS_GZIP_MAGIC = b"\x1f\x8b"
_UCS_EXT = ".ucs"

# Order here is the order ``scan_many`` will see the members. Base
# file MUST go first so its VLAN / SELF_IP / route-domain / etc.
# definitions land in the ledger before the main file's references
# need to resolve.
CONFIG_MEMBERS_REQUIRED: tuple[str, ...] = (
    "config/bigip_base.conf",
    "config/bigip.conf",
)
# v1.2 ships ``bigip_user.conf`` as the only optional member. The other
# obvious candidate, ``config/bigip_script.conf``, is deliberately
# excluded — its iApp template bodies routinely contain literal
# RFC 5737 docs-range IPs (``192.0.2.7``, ``192.0.2.10``, etc.) inside
# user-facing example help text, which collides with VEIL's IP
# placeholder model (customer IPs are substituted INTO docs-range IPs,
# not into symbolic ``IPADDR_NNNN`` placeholders). Reverse-substitute
# cannot distinguish a docs-range IP that was allocated from a
# docs-range IP that was already present in the source — round-trip
# breaks at real-world script.conf scale. Fix is architectural
# (reserve source-literal docs IPs from the allocation pool) and is
# tracked for v1.3 / v2.0. Operator workaround: hand bigip_script.conf
# to the LLM as a separate plain-text file if needed.
CONFIG_MEMBERS_OPTIONAL: tuple[str, ...] = (
    "config/bigip_user.conf",
)
CONFIG_MEMBERS: tuple[str, ...] = (
    CONFIG_MEMBERS_REQUIRED + CONFIG_MEMBERS_OPTIONAL
)

MAX_CONFIG_MEMBER_BYTES = 50 * 1024 * 1024


class UcsExtractError(Exception):
    """Raised when a UCS cannot be safely extracted."""


@dataclass(frozen=True)
class UcsExtractResult:
    """Outcome of an ``extract_ucs_configs`` call.

    ``configs`` is the ordered list of ``(archive_path, content)``
    pairs for the allowlisted config members actually present in the
    UCS, in :data:`CONFIG_MEMBERS` order. ``skipped_member_count`` is
    every other tar entry (binaries, certs, licenses, .diffVersions,
    state files, etc.) — extraction reads none of those.
    """

    configs: list[tuple[str, str]]
    skipped_member_count: int
    total_member_count: int


def is_ucs_file(path: str | Path) -> bool:
    """True only when ``path`` has the ``.ucs`` extension AND its
    first two bytes are the gzip magic ``1f 8b``.

    Both conditions are required so a renamed-to-``.ucs`` plain
    text file doesn't get routed into the UCS pipeline, and a
    gzipped tarball with a different extension doesn't either.
    """
    p = Path(path)
    if p.suffix.lower() != _UCS_EXT:
        return False
    try:
        with open(p, "rb") as fh:
            magic = fh.read(2)
    except OSError:
        return False
    return magic == _UCS_GZIP_MAGIC


def extract_ucs_configs(path: str | Path) -> UcsExtractResult:
    """Open a UCS and extract the allowlisted config-file members.

    See module docstring for the full rule set. Raises
    :class:`UcsExtractError` on any rule violation; never raises
    :class:`tarfile.TarError` or :class:`OSError` directly.
    """
    p = Path(path)
    try:
        tar = tarfile.open(p, "r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise UcsExtractError(
            f"could not open UCS archive {p!s}: {exc!s}"
        ) from exc

    extracted: dict[str, str] = {}
    total_members = 0
    try:
        for member in tar:
            total_members += 1
            name = member.name
            if name not in CONFIG_MEMBERS:
                # Non-allowlisted members are ignored entirely. We
                # do NOT validate their shape — they will not be
                # read, written, or referenced.
                continue
            _validate_member_shape(member)
            if member.size > MAX_CONFIG_MEMBER_BYTES:
                raise UcsExtractError(
                    f"UCS member {name!r} is {member.size:,} bytes; "
                    f"exceeds {MAX_CONFIG_MEMBER_BYTES:,}-byte cap"
                )
            fobj = tar.extractfile(member)
            if fobj is None:
                raise UcsExtractError(
                    f"UCS member {name!r} has no extractable content "
                    f"(unexpected member shape)"
                )
            try:
                raw = fobj.read()
            except OSError as exc:
                raise UcsExtractError(
                    f"could not read UCS member {name!r}: {exc!s}"
                ) from exc
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise UcsExtractError(
                    f"UCS member {name!r} is not valid UTF-8: {exc!s}"
                ) from exc
            extracted[name] = text
    finally:
        tar.close()

    missing = [m for m in CONFIG_MEMBERS_REQUIRED if m not in extracted]
    if missing:
        raise UcsExtractError(
            f"UCS missing required config member(s): {missing!r}"
        )

    ordered = [
        (name, extracted[name])
        for name in CONFIG_MEMBERS
        if name in extracted
    ]
    return UcsExtractResult(
        configs=ordered,
        skipped_member_count=total_members - len(ordered),
        total_member_count=total_members,
    )


def _validate_member_shape(member: tarfile.TarInfo) -> None:
    """Defensive shape checks for an allowlisted member. The
    allowlist already pins the canonical name, but malicious
    tarballs can still ship the right name with a wrong shape
    (symlink pointing at ``/etc/passwd``, etc.).
    """
    name = member.name
    if member.issym() or member.islnk():
        raise UcsExtractError(
            f"UCS member {name!r} is a link (sym/hard); refusing"
        )
    if not member.isfile():
        raise UcsExtractError(
            f"UCS member {name!r} is not a regular file "
            f"(type={member.type!r})"
        )
    if name.startswith("/") or "\\" in name:
        raise UcsExtractError(
            f"UCS member {name!r} has an absolute or backslash path"
        )
    if ".." in name.split("/"):
        raise UcsExtractError(
            f"UCS member {name!r} contains a '..' path component"
        )
