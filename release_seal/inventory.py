"""Read a directory into a deterministic file inventory."""

import hashlib
import os
from pathlib import Path
import stat


def inventory(directory: str | Path) -> list[dict[str, str | int]]:
    """Return path, size and SHA-256 for every ordinary file in directory."""
    root = Path(directory)
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"expected a directory without a symbolic link: {root}")

    records: list[dict[str, str | int]] = []

    def walk_error(error: OSError) -> None:
        raise error

    for current, subdirs, filenames in os.walk(root, onerror=walk_error):
        for name in subdirs:
            child = Path(current) / name
            if child.is_symlink():
                raise ValueError(f"symbolic links are not supported: {child}")
        for name in filenames:
            path = Path(current) / name
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError(f"expected an ordinary file: {path}")
            digest = hashlib.sha256()
            size = 0
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
            records.append({
                "path": path.relative_to(root).as_posix(),
                "size": size,
                "sha256": digest.hexdigest(),
            })

    return sorted(records, key=lambda record: str(record["path"]))
