"""On-demand verification of a selected subset of a manifest.

``verify-selected DIRECTORY MANIFEST PUBLIC SELECTION`` trusts only the
given PEM Ed25519 public key and verifies version 1/2 manifests exactly
like ``verify``, but it reads only the files named by SELECTION instead
of scanning the whole delivery tree; nothing else in the tree is read.

SELECTION is an out-of-tree UTF-8 JSON file holding a non-empty array of
unique strings; each entry must match a manifest ``files.path`` exactly.
Absolute paths, empty segments, ``.``/``..`` segments, backslashes and
paths the manifest does not list are refused.

Manifest structure, ``key_id`` and signature are checked first; an
untrusted manifest returns exit 1 with ``valid: false``,
``reason: "untrusted_manifest"``, ``checked: 0`` and empty
``modified``/``missing`` lists, and no delivery file is read. Only after
trust is established are the selected files read, in manifest order.
Every level of each path is checked: symbolic links and special files
are refused, reads use ``O_NOFOLLOW``, and the path and open handle are
checked before and after the read (type, ``(dev, ino)`` identity, size
and nanosecond mtime); a replacement or any change during the read
returns exit 2. A full match returns exit 0 with ``valid: true`` and
``checked``; a tampered or missing selected file returns exit 1 with
``reason: "file_mismatch"`` and sorted ``modified``/``missing`` lists.
"""

import hashlib
import json
import os
from pathlib import Path
import stat

from cryptography.exceptions import InvalidSignature

from .inventory import _lstat_checked
from .seal import (
    SealError,
    canonical_payload,
    key_id_of,
    load_manifest,
    load_public_key,
    require_outside,
)

REASON_UNTRUSTED = "untrusted_manifest"
REASON_FILE_MISMATCH = "file_mismatch"


def _untrusted() -> dict:
    """The code-1 result for a manifest that failed the trust checks."""
    return {
        "valid": False,
        "reason": REASON_UNTRUSTED,
        "checked": 0,
        "modified": [],
        "missing": [],
    }


def validate_selection_path(entry: str) -> None:
    """Refuse absolute paths, backslashes and empty/``.``/``..`` segments."""
    if "\\" in entry:
        raise SealError(f"selection paths must use '/' separators: {entry}")
    if entry.startswith("/"):
        raise SealError(f"selection paths must be relative: {entry}")
    for segment in entry.split("/"):
        if segment == "" or segment in (".", ".."):
            raise SealError(f"selection path has an invalid segment: {entry}")


def validate_selection(document: object) -> list[str]:
    """Validate a parsed SELECTION document, returning its entries.

    It must be a non-empty JSON array of unique, non-empty strings with
    well-formed relative path shapes (see :func:`validate_selection_path`).
    Whether an entry is listed in the manifest is checked separately.
    """
    if not isinstance(document, list) or not document:
        raise SealError("selection must be a non-empty JSON array")
    selection: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(document):
        if not isinstance(entry, str) or entry == "":
            raise SealError(f"selection entry {index} must be a non-empty string")
        validate_selection_path(entry)
        if entry in seen:
            raise SealError(f"selection lists a duplicate path: {entry}")
        seen.add(entry)
        selection.append(entry)
    return selection


def load_selection(path: Path) -> list[str]:
    """Read and strictly validate a SELECTION file."""
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read selection {path}: {error}") from error
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SealError(f"selection is not UTF-8 JSON: {path}: {error}") from error
    try:
        return validate_selection(document)
    except SealError as error:
        raise SealError(f"{error}: {path}") from error


def _lstat(path: Path, *, expect_dir: bool) -> os.stat_result:
    """lstat a delivery path, turning every stat failure into SealError.

    Symbolic links and special files are refused like the rest of the
    tool; a missing entry raises :class:`FileNotFoundError` so the caller
    can classify it as ``missing`` rather than an error.
    """
    try:
        return _lstat_checked(path, expect_dir=expect_dir)
    except ValueError as error:
        # _lstat_checked reports all stat failures as ValueError; a
        # missing entry's cause is FileNotFoundError.
        if isinstance(error.__cause__, FileNotFoundError):
            raise FileNotFoundError(str(error)) from error.__cause__
        raise SealError(str(error)) from error


def _identity(st: os.stat_result) -> tuple:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def _fd_identity(fd: int, path: Path) -> tuple:
    """Identity of an open descriptor, refusing non-regular files."""
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise SealError(f"expected an ordinary file: {path}")
    return _identity(st)


def _parents_present(directory: Path, rel: str) -> bool:
    """lstat every parent directory of a selected path.

    Every level of the delivery tree is checked so a symlinked directory
    can never redirect a selected read. Returns ``False`` when a parent
    level is absent (the selected file is therefore missing) and raises
    on links, special files or other stat failures.
    """
    parent = directory
    for segment in rel.split("/")[:-1]:
        parent = parent / segment
        try:
            _lstat(parent, expect_dir=True)
        except FileNotFoundError:
            return False
    return True


def _read_selected_file(directory: Path, rel: str, record: dict) -> bool:
    """Read one selected file, proving it stayed the same file throughout.

    The parent directories and the file itself are lstat-checked (links
    and special files refused), the file is opened with ``O_NOFOLLOW``,
    and the path identity is compared against the open descriptor's
    identity before and after the streamed read (type, ``(dev, ino)``,
    size, nanosecond mtime). A replacement or any change while reading
    raises :class:`SealError` (exit 2). Returns whether the streamed
    bytes match the manifest record's size and SHA-256.
    """
    path = directory / rel
    before = _lstat(path, expect_dir=False)
    before_identity = _identity(before)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        # O_NOFOLLOW turns a link swapped in after the lstat into ELOOP.
        raise SealError(f"cannot read {path}: {error}") from error
    wrapped = False
    try:
        opened_identity = _fd_identity(fd, path)
        if opened_identity != before_identity:
            raise SealError(f"file changed while opening: {path}")
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(fd, "rb", closefd=True) as source:
            wrapped = True
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
            after_fd = _fd_identity(source.fileno(), path)
        if after_fd != opened_identity:
            raise SealError(f"file changed while reading: {path}")
    finally:
        if not wrapped:
            os.close(fd)
    # A same-named replacement (rename) leaves the open descriptor on the
    # old inode but moves the path; the post-read lstat catches it. The
    # file vanishing or turning into a link at this point is likewise a
    # change during verification, not a pre-existing missing file.
    try:
        after = _lstat(path, expect_dir=False)
    except FileNotFoundError as error:
        raise SealError(f"file changed while reading: {path}") from error
    if _identity(after) != before_identity:
        raise SealError(f"file changed while reading: {path}")
    return size == record["size"] and digest.hexdigest() == record["sha256"]


def verify_selected(directory, manifest, public_key, selection) -> dict:
    """Verify a selected subset of a signed manifest against directory.

    Accepts manifest versions 1 and 2. The MANIFEST, PUBLIC key and
    SELECTION files must all stay outside the delivery tree. See the
    module docstring for the exact result shapes and exit-code mapping:
    an untrusted manifest or a file mismatch is a code-1 result; anything
    structural, unsafe or a tree change raises :class:`SealError`
    (exit 2). Delivery files are read only after the manifest is trusted
    and only the selected ones are touched, in manifest order.
    """
    directory = Path(directory)
    manifest = Path(manifest)
    public_key = Path(public_key)
    selection = Path(selection)
    require_outside(directory, (manifest, public_key, selection))
    # The root itself must be a real directory, without links, exactly
    # like the other verify commands.
    _lstat(directory, expect_dir=True)
    # All inputs must parse and have the right shape before any trust
    # verdict is produced: a malformed SELECTION or manifest is exit 2,
    # never an "untrusted" result.
    selected = load_selection(selection)
    key = load_public_key(public_key)
    version, files, signature, key_id = load_manifest(manifest)
    # Trust gate: key id (version 2), then the signature. Nothing in the
    # delivery tree is read until both pass.
    if version == 2 and key_id != key_id_of(key):
        return _untrusted()
    try:
        key.verify(signature, canonical_payload(version, key_id, files))
    except InvalidSignature:
        return _untrusted()
    records_by_path = {record["path"]: record for record in files}
    # The manifest is authoritative only once trusted, so membership of
    # the selection in its files listing is checked here.
    for entry in selected:
        if entry not in records_by_path:
            raise SealError(
                f"selection path is not listed in the manifest: {entry}"
            )
    wanted = set(selected)
    modified: list[str] = []
    missing: list[str] = []
    checked = 0
    for record in files:
        rel = record["path"]
        if rel not in wanted:
            continue
        # Follow the signed manifest's order, not the SELECTION order.
        if not _parents_present(directory, rel):
            missing.append(rel)
            continue
        try:
            matches = _read_selected_file(
                directory, rel, records_by_path[rel]
            )
        except FileNotFoundError:
            missing.append(rel)
            continue
        checked += 1
        if not matches:
            modified.append(rel)
    if modified or missing:
        return {
            "valid": False,
            "reason": REASON_FILE_MISMATCH,
            "checked": checked,
            "modified": sorted(modified),
            "missing": sorted(missing),
        }
    return {"valid": True, "checked": checked}
