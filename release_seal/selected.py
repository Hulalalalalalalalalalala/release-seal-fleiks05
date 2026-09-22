"""Verify a selected subset of a signed manifest against a directory.

``verify-selected DIRECTORY MANIFEST PUBLIC SELECTION`` trusts only the
PEM Ed25519 public key given on the command line and accepts manifest
versions 1 and 2, exactly like ``verify``. SELECTION is a UTF-8 JSON
file outside the delivery tree holding a non-empty array of unique
strings; every entry must exactly match a ``files.path`` of the
manifest. Absolute paths, empty segments, ``.`` and ``..`` segments,
backslashes and paths missing from the manifest are rejected: the
reason goes to standard error, the exit code is 2 and no delivery file
is read.

The manifest's structure, ``key_id`` and signature are checked first.
An untrusted manifest exits 1 with ``valid: false``,
``reason: "untrusted_manifest"``, ``checked: 0`` and empty ``modified``
and ``missing`` lists. Once the manifest is trusted, only the selected
files are read, in manifest order — nothing else in the tree is
scanned. When every selected file matches, the exit code is 0 with
``valid: true`` and ``checked``; a tampered or missing selected file
exits 1 with ``reason: "file_mismatch"`` and sorted ``modified`` /
``missing`` lists.

Every path component is checked level by level: symbolic links and
special files are rejected and reads use ``O_NOFOLLOW``. Path and
handle state (type, ``(dev, ino)``, size, nanosecond mtime) are
compared before and after each read; a replacement or change is a
status-2 failure.
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


def _identity(kind: str, st: os.stat_result) -> tuple:
    return (kind, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def _lstat_selected(root: Path, rel: str) -> tuple[Path, os.stat_result] | None:
    """Stat the selected file, checking every path component.

    Returns ``(path, stat)`` for a present ordinary file, ``None`` when
    the path cannot lead to it (a missing component, or a regular file
    where a directory would be needed). Symbolic links and special
    files at any level raise :class:`SealError`.
    """
    parts = rel.split("/")
    current = root
    for part in parts[:-1]:
        current = current / part
        try:
            st = current.lstat()
        except (FileNotFoundError, NotADirectoryError):
            return None
        except OSError as error:
            raise SealError(f"cannot stat {current}: {error}") from error
        mode = st.st_mode
        if stat.S_ISLNK(mode):
            raise SealError(f"symbolic links are not supported: {current}")
        if stat.S_ISDIR(mode):
            continue
        if stat.S_ISREG(mode):
            return None
        raise SealError(f"expected a directory: {current}")
    target = current / parts[-1]
    try:
        st = target.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as error:
        raise SealError(f"cannot stat {target}: {error}") from error
    mode = st.st_mode
    if stat.S_ISLNK(mode):
        raise SealError(f"symbolic links are not supported: {target}")
    if not stat.S_ISREG(mode):
        raise SealError(f"expected an ordinary file: {target}")
    return target, st


def _hash_selected_file(path: Path, before: tuple) -> tuple[int, str]:
    """Hash path, proving its identity held across the read.

    ``before`` is the identity tuple from the pre-read lstat. The
    opened handle must show the same identity (type, ``(dev, ino)``,
    size, nanosecond mtime) right after opening, and both the handle
    and the path must still show it after the read; a replacement or
    change raises :class:`SealError`. The open uses ``O_NOFOLLOW`` so a
    link swapped in after the lstat is refused.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise SealError(f"cannot read {path}: {error}") from error
    with os.fdopen(fd, "rb", closefd=True) as source:
        handle = os.fstat(source.fileno())
        if not stat.S_ISREG(handle.st_mode) or _identity("file", handle) != before:
            raise SealError(f"file changed while reading: {path}")
        digest = hashlib.sha256()
        size = 0
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
        handle_after = os.fstat(source.fileno())
        try:
            path_after = path.lstat()
        except OSError as error:
            raise SealError(f"file changed while reading: {path}") from error
        if (
            _identity("file", handle_after) != before
            or not stat.S_ISREG(path_after.st_mode)
            or _identity("file", path_after) != before
        ):
            raise SealError(f"file changed while reading: {path}")
    return size, digest.hexdigest()


def _validate_selection_path(item: str, where: Path) -> None:
    if item.startswith("/"):
        raise SealError(f"selection path must be relative: {item!r}: {where}")
    if "\\" in item:
        raise SealError(
            f"selection path must not contain backslashes: {item!r}: {where}"
        )
    if any(part in ("", ".", "..") for part in item.split("/")):
        raise SealError(
            f"selection path holds an empty, '.' or '..' segment: "
            f"{item!r}: {where}"
        )


def load_selection(path: Path, files: list[dict]) -> list[str]:
    """Load and strictly validate a SELECTION file against the manifest.

    Returns the selected paths in selection order. Raises
    :class:`SealError` for any problem: the file is not UTF-8 JSON, is
    not a non-empty array of unique strings, or an entry is absolute,
    holds an empty/``.``/``..`` segment or a backslash, or does not
    exactly match a ``files.path`` of the manifest.
    """
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read selection {path}: {error}") from error
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SealError(f"selection is not UTF-8 JSON: {path}: {error}") from error
    if not isinstance(document, list) or not document:
        raise SealError(f"selection must be a non-empty JSON array: {path}")
    if any(not isinstance(item, str) for item in document):
        raise SealError(f"selection entries must be strings: {path}")
    if len(set(document)) != len(document):
        raise SealError(f"selection entries must be unique: {path}")
    known = {record["path"] for record in files}
    for item in document:
        _validate_selection_path(item, path)
        if item not in known:
            raise SealError(f"selection path is not in the manifest: {item!r}")
    return document


def _untrusted() -> dict:
    return {
        "valid": False,
        "reason": "untrusted_manifest",
        "checked": 0,
        "modified": [],
        "missing": [],
    }


def verify_selected(directory, manifest, public_key, selection) -> dict:
    """Verify only the selected files of a signed manifest.

    Accepts manifest versions 1 and 2, trusting only ``public_key``.
    The manifest's structure, ``key_id`` and signature are checked
    first; an untrusted manifest yields ``valid: false`` with
    ``reason: "untrusted_manifest"``, ``checked: 0`` and empty lists.
    Once trusted, the SELECTION file (outside the tree) is validated
    and only the selected files are read, in manifest order. The result
    is ``{"valid": True, "checked": n}`` or ``valid: false`` with
    ``reason: "file_mismatch"`` and sorted ``modified`` / ``missing``
    lists. Format, I/O, safety and change-detection problems raise
    :class:`SealError` (standard error, exit code 2).
    """
    directory = Path(directory)
    manifest = Path(manifest)
    public_key = Path(public_key)
    selection = Path(selection)
    require_outside(directory, (manifest, public_key, selection))
    key = load_public_key(public_key)
    version, files, signature, key_id = load_manifest(manifest)
    if version == 2 and key_id != key_id_of(key):
        return _untrusted()
    try:
        key.verify(signature, canonical_payload(version, key_id, files))
    except InvalidSignature:
        return _untrusted()
    selected = set(load_selection(selection, files))
    _lstat_checked(directory, expect_dir=True)
    modified: list[str] = []
    missing: list[str] = []
    checked = 0
    for record in files:  # manifest order, never a tree scan
        rel = record["path"]
        if rel not in selected:
            continue
        checked += 1
        found = _lstat_selected(directory, rel)
        if found is None:
            missing.append(rel)
            continue
        path, st = found
        size, digest = _hash_selected_file(path, _identity("file", st))
        if (size, digest) != (record["size"], record["sha256"]):
            modified.append(rel)
    if modified or missing:
        return {
            "valid": False,
            "reason": "file_mismatch",
            "checked": checked,
            "modified": sorted(modified),
            "missing": sorted(missing),
        }
    return {"valid": True, "checked": checked}
