"""Sign and verify directory inventories with Ed25519."""

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

MANIFEST_VERSION = 1
MANIFEST_ALGORITHM = "Ed25519"
MANIFEST_HASH = "SHA-256"
MANIFEST_KEYS = {"version", "algorithm", "hash", "files", "signature"}


class SignVerifyError(Exception):
    """Argument, I/O, key or manifest problems; reported with exit status 2."""


def _stable_inventory(directory: Path) -> list[dict[str, str | int]]:
    """Inventory that refuses files which change while they are being read."""
    root = Path(directory)
    if root.is_symlink() or not root.is_dir():
        raise SignVerifyError(f"expected a directory without a symbolic link: {root}")

    records: list[dict[str, str | int]] = []

    def walk_error(error: OSError) -> None:
        raise error

    for current, subdirs, filenames in os.walk(root, onerror=walk_error):
        for name in subdirs:
            child = Path(current) / name
            if child.is_symlink():
                raise SignVerifyError(f"symbolic links are not supported: {child}")
        for name in filenames:
            path = Path(current) / name
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode):
                raise SignVerifyError(f"expected an ordinary file: {path}")
            digest = hashlib.sha256()
            size = 0
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
            after = path.lstat()
            changed = (
                before.st_ino != after.st_ino
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_size != after.st_size
                or after.st_size != size
            )
            if changed:
                raise SignVerifyError(f"file changed while it was being read: {path}")
            records.append({
                "path": path.relative_to(root).as_posix(),
                "size": size,
                "sha256": digest.hexdigest(),
            })

    return sorted(records, key=lambda record: str(record["path"]))


def _resolve_outside(directory: Path, path: str | Path, what: str) -> Path:
    """Resolve path and refuse anything inside the delivery tree."""
    root = Path(directory).resolve()
    resolved = Path(path).resolve()
    if resolved == root or resolved.is_relative_to(root):
        raise SignVerifyError(f"{what} must not be inside the delivery tree: {path}")
    return resolved


def _payload(files: list[dict[str, str | int]]) -> bytes:
    """Canonical UTF-8 JSON covered by the signature."""
    body = {
        "version": MANIFEST_VERSION,
        "algorithm": MANIFEST_ALGORITHM,
        "hash": MANIFEST_HASH,
        "files": files,
    }
    return json.dumps(
        body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise SignVerifyError(f"cannot read private key: {error}") from error
    try:
        key = load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as error:
        raise SignVerifyError(f"cannot load PEM private key: {error}") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise SignVerifyError("private key is not an Ed25519 key")
    return key


def _load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise SignVerifyError(f"cannot read public key: {error}") from error
    try:
        key = load_pem_public_key(data)
    except (ValueError, TypeError) as error:
        raise SignVerifyError(f"cannot load PEM public key: {error}") from error
    if not isinstance(key, Ed25519PublicKey):
        raise SignVerifyError("public key is not an Ed25519 key")
    return key


def _create_manifest(path: Path, data: bytes) -> None:
    """Create the manifest atomically and refuse to overwrite."""
    if os.path.lexists(path):
        raise SignVerifyError(f"manifest already exists: {path}")
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        with os.fdopen(handle, "wb") as target:
            target.write(data)
        try:
            os.link(temporary, path)
        except FileExistsError:
            raise SignVerifyError(f"manifest already exists: {path}") from None
        except OSError:
            # Filesystems without hard links: exclusive create still refuses
            # to overwrite, just without a rename-style commit.
            try:
                with open(path, "xb") as target:
                    target.write(data)
            except FileExistsError:
                raise SignVerifyError(f"manifest already exists: {path}") from None
    finally:
        try:
            os.unlink(temporary)
        except OSError:
            pass


def sign_directory(
    directory: str | Path, private_key: str | Path, manifest: str | Path
) -> dict:
    """Sign the inventory of directory and create manifest; return the document."""
    root = Path(directory)
    key_path = _resolve_outside(root, private_key, "private key")
    manifest_path = _resolve_outside(root, manifest, "manifest")
    key = _load_private_key(key_path)
    files = _stable_inventory(root)
    signature = key.sign(_payload(files))
    document = {
        "version": MANIFEST_VERSION,
        "algorithm": MANIFEST_ALGORITHM,
        "hash": MANIFEST_HASH,
        "files": files,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    text = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    _create_manifest(manifest_path, text.encode("utf-8"))
    return document


def _load_manifest(path: Path) -> dict:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SignVerifyError(f"cannot read manifest: {error}") from error
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SignVerifyError(f"manifest is not UTF-8 JSON: {error}") from error
    if not isinstance(document, dict) or set(document) != MANIFEST_KEYS:
        raise SignVerifyError(
            "manifest must be a JSON object with keys: " + ", ".join(sorted(MANIFEST_KEYS))
        )
    version = document["version"]
    if isinstance(version, bool) or version != 1:
        raise SignVerifyError("manifest version must be 1")
    if document["algorithm"] != MANIFEST_ALGORITHM:
        raise SignVerifyError(f"manifest algorithm must be {MANIFEST_ALGORITHM!r}")
    if document["hash"] != MANIFEST_HASH:
        raise SignVerifyError(f"manifest hash must be {MANIFEST_HASH!r}")
    files = document["files"]
    if not isinstance(files, list):
        raise SignVerifyError("manifest files must be a list")
    seen: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
            raise SignVerifyError("manifest files entries need path, size and sha256")
        name, size, digest = entry["path"], entry["size"], entry["sha256"]
        if not isinstance(name, str) or not name or name in seen:
            raise SignVerifyError("manifest files entries need unique path strings")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise SignVerifyError(f"manifest entry has an invalid size: {name}")
        if not isinstance(digest, str) or len(digest) != 64 or any(
            char not in "0123456789abcdef" for char in digest
        ):
            raise SignVerifyError(f"manifest entry has an invalid sha256: {name}")
        seen.add(name)
    signature = document["signature"]
    if not isinstance(signature, str):
        raise SignVerifyError("manifest signature must be base64 text")
    try:
        decoded = base64.b64decode(signature, validate=True)
    except binascii.Error as error:
        raise SignVerifyError(f"manifest signature is not valid base64: {error}") from error
    if len(decoded) != 64:
        raise SignVerifyError("manifest signature must be 64 bytes")
    return document


def _diff(
    expected: list[dict[str, str | int]], actual: list[dict[str, str | int]]
) -> tuple[list[str], list[str], list[str]]:
    wanted = {str(entry["path"]): entry for entry in expected}
    found = {str(entry["path"]): entry for entry in actual}
    modified = sorted(
        path
        for path in wanted.keys() & found.keys()
        if wanted[path]["size"] != found[path]["size"]
        or wanted[path]["sha256"] != found[path]["sha256"]
    )
    missing = sorted(wanted.keys() - found.keys())
    unexpected = sorted(found.keys() - wanted.keys())
    return modified, missing, unexpected


def verify_directory(
    directory: str | Path, manifest: str | Path, public_key: str | Path
) -> dict:
    """Verify the manifest signature, then compare the inventory on disk."""
    root = Path(directory)
    manifest_path = _resolve_outside(root, manifest, "manifest")
    key_path = _resolve_outside(root, public_key, "public key")
    document = _load_manifest(manifest_path)
    key = _load_public_key(key_path)
    signature = base64.b64decode(document["signature"])
    try:
        key.verify(signature, _payload(document["files"]))
    except InvalidSignature:
        return {"valid": False, "modified": [], "missing": [], "unexpected": []}
    modified, missing, unexpected = _diff(
        document["files"], _stable_inventory(root)
    )
    if modified or missing or unexpected:
        return {
            "valid": False,
            "modified": modified,
            "missing": missing,
            "unexpected": unexpected,
        }
    return {"valid": True}
