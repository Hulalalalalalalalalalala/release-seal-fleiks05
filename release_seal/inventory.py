"""Read a directory into a deterministic file inventory."""

import hashlib
import os
from pathlib import Path
import stat


def _raise_walk_error(error: OSError) -> None:
    raise error


def _lstat_checked(path: Path, *, expect_dir: bool) -> os.stat_result:
    """lstat path, rejecting symbolic links and non-ordinary file types."""
    try:
        st = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot stat {path}: {error}") from error
    mode = st.st_mode
    if stat.S_ISLNK(mode):
        raise ValueError(f"symbolic links are not supported: {path}")
    if expect_dir:
        if not stat.S_ISDIR(mode):
            raise ValueError(f"expected a directory: {path}")
    elif not stat.S_ISREG(mode):
        raise ValueError(f"expected an ordinary file: {path}")
    return st


def _identity(kind: str, st: os.stat_result) -> tuple:
    return (kind, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def stat_snapshot(directory: str | Path) -> dict[str, tuple]:
    """Return an identity/metadata snapshot of every entry in directory.

    Maps '/'-separated paths relative to directory (``.`` for the root)
    to ``(kind, st_dev, st_ino, st_size, st_mtime_ns)`` tuples, where
    kind is ``"dir"`` or ``"file"``. Symbolic links and special files are
    rejected. Two equal snapshots prove the tree kept the same entries,
    file identities (``(dev, ino)``), sizes and modification times across
    a scan: a replacement created by rename cannot hide behind an
    unchanged path.
    """
    root = Path(directory)
    root_st = _lstat_checked(root, expect_dir=True)
    snapshot = {".": _identity("dir", root_st)}
    for current, subdirs, filenames in os.walk(root, onerror=_raise_walk_error):
        for name in subdirs:
            child = Path(current) / name
            st = _lstat_checked(child, expect_dir=True)
            snapshot[child.relative_to(root).as_posix()] = _identity("dir", st)
        for name in filenames:
            path = Path(current) / name
            st = _lstat_checked(path, expect_dir=False)
            snapshot[path.relative_to(root).as_posix()] = _identity("file", st)
    return snapshot


def inventory(directory: str | Path) -> list[dict[str, str | int]]:
    """Return path, size and SHA-256 for every ordinary file in directory."""
    root = Path(directory)
    _lstat_checked(root, expect_dir=True)

    records: list[dict[str, str | int]] = []
    for current, subdirs, filenames in os.walk(root, onerror=_raise_walk_error):
        for name in subdirs:
            _lstat_checked(Path(current) / name, expect_dir=True)
        for name in filenames:
            path = Path(current) / name
            _lstat_checked(path, expect_dir=False)
            digest = hashlib.sha256()
            size = 0
            # O_NOFOLLOW: refuse to follow a link swapped in after the lstat.
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(path, flags)
            except OSError as error:
                raise ValueError(f"cannot read {path}: {error}") from error
            with os.fdopen(fd, "rb", closefd=True) as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
            records.append({
                "path": path.relative_to(root).as_posix(),
                "size": size,
                "sha256": digest.hexdigest(),
            })

    return sorted(records, key=lambda record: str(record["path"]))
