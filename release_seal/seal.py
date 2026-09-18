"""Sign and verify a directory inventory with Ed25519.

Manifests exist in two versions:

* version 1 holds ``version``, ``algorithm``, ``hash``, ``files`` and
  ``signature``;
* version 2 adds ``key_id``, the lowercase SHA-256 hex of the signer's
  DER SubjectPublicKeyInfo.

The signature covers every field except ``signature``, serialized with
keys sorted, no whitespace and no Unicode escaping. Verification accepts
both versions; signing always emits version 2.
"""

import base64
import binascii
import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from .inventory import inventory, stat_snapshot

VERSION = 1
VERSION_CURRENT = 2
SUPPORTED_VERSIONS = (1, 2)
ALGORITHM = "Ed25519"
HASH = "SHA-256"
TRUST_STORE_KIND = "release-seal-trust-store"
V1_FIELDS = ("version", "algorithm", "hash", "files", "signature")
V2_FIELDS = ("version", "algorithm", "hash", "key_id", "files", "signature")

_PUBLIC_PEM_MARKERS = (b"-----BEGIN PUBLIC KEY-----", b"-----END PUBLIC KEY-----")
_PRIVATE_PEM_MARKERS = (b"-----BEGIN PRIVATE KEY-----", b"-----END PRIVATE KEY-----")


class SealError(ValueError):
    """A user-facing failure: print the message and exit with status 2."""


def key_id_of(key: Ed25519PublicKey) -> str:
    """Return the lowercase SHA-256 hex of a public key's DER SPKI."""
    der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def is_key_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def canonical_payload(version: int, key_id: str | None, files: list[dict]) -> bytes:
    """Return the canonical UTF-8 JSON the signature covers.

    The signed body holds every manifest field except ``signature``
    (including ``key_id`` on version 2), with keys sorted, no whitespace
    and no Unicode escaping.
    """
    body: dict = {
        "version": version,
        "algorithm": ALGORITHM,
        "hash": HASH,
        "files": files,
    }
    if version >= 2:
        body["key_id"] = key_id
    return json.dumps(
        body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def require_outside(directory: Path, paths: tuple[Path, ...]) -> None:
    root = directory.resolve()
    for path in paths:
        if path.resolve().is_relative_to(root):
            raise SealError(
                f"keys, manifests and trust stores must stay outside the "
                f"delivery tree: {path}"
            )


def load_private_key(path: Path) -> Ed25519PrivateKey:
    # The key is only read into memory for signing; it is never printed,
    # copied into the manifest or written anywhere else.
    try:
        data = path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read private key {path}: {error}") from error
    if not all(marker in data for marker in _PRIVATE_PEM_MARKERS):
        raise SealError(f"expected a PEM Ed25519 private key: {path}")
    try:
        key = load_pem_private_key(data, password=None)
    except Exception as error:
        raise SealError(f"cannot load PEM private key {path}: {error}") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise SealError(f"expected an Ed25519 private key: {path}")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read public key {path}: {error}") from error
    return decode_public_key(data, where=str(path))


def decode_public_key(data: bytes, *, where: str) -> Ed25519PublicKey:
    """Strictly decode a PEM Ed25519 SubjectPublicKeyInfo blob."""
    if not all(marker in data for marker in _PUBLIC_PEM_MARKERS):
        raise SealError(f"expected a PEM Ed25519 public key: {where}")
    try:
        key = load_pem_public_key(data)
    except Exception as error:
        raise SealError(f"cannot load PEM public key {where}: {error}") from error
    if not isinstance(key, Ed25519PublicKey):
        raise SealError(f"expected an Ed25519 public key: {where}")
    return key


def valid_record(record: object) -> bool:
    if not isinstance(record, dict):
        return False
    fields = set(record)
    if fields != {"path", "size", "sha256"}:
        return False
    size = record["size"]
    digest = record["sha256"]
    return (
        isinstance(record["path"], str)
        and record["path"] != ""
        and isinstance(size, int)
        and not isinstance(size, bool)
        and size >= 0
        and isinstance(digest, str)
        and len(digest) == 64
        and all(char in "0123456789abcdef" for char in digest)
    )


def load_manifest(path: Path) -> tuple[int, list[dict], bytes, str | None]:
    """Return (version, files, signature, key_id) from a manifest file."""
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read manifest {path}: {error}") from error
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SealError(f"manifest is not UTF-8 JSON: {path}: {error}") from error
    if not isinstance(document, dict):
        raise SealError(f"manifest must be a JSON object: {path}")
    version = document.get("version")
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version not in SUPPORTED_VERSIONS
    ):
        supported = " or ".join(str(value) for value in SUPPORTED_VERSIONS)
        raise SealError(
            f"manifest field 'version' must be {supported}: {path}"
        )
    expected = set(V2_FIELDS if version == 2 else V1_FIELDS)
    if set(document) != expected:
        raise SealError(
            f"manifest version {version} must contain exactly "
            f"{', '.join(sorted(expected))}: {path}"
        )
    if document["algorithm"] != ALGORITHM:
        raise SealError(f"manifest field 'algorithm' must be {ALGORITHM!r}: {path}")
    if document["hash"] != HASH:
        raise SealError(f"manifest field 'hash' must be {HASH!r}: {path}")
    key_id = None
    if version == 2:
        key_id = document["key_id"]
        if not is_key_id(key_id):
            raise SealError(
                f"manifest field 'key_id' must be 64 lowercase hex digits: {path}"
            )
    files = document["files"]
    if not isinstance(files, list) or any(not valid_record(r) for r in files):
        raise SealError(f"manifest field 'files' holds invalid records: {path}")
    paths = [record["path"] for record in files]
    if len(set(paths)) != len(paths):
        raise SealError(f"manifest lists duplicate paths: {path}")
    signature = document["signature"]
    if not isinstance(signature, str):
        raise SealError(f"manifest field 'signature' must be Base64 text: {path}")
    try:
        decoded = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError) as error:
        raise SealError(f"manifest signature is not Base64: {path}") from error
    if len(decoded) != 64:
        raise SealError(f"manifest signature must be 64 bytes: {path}")
    return version, files, decoded, key_id


def diff_inventory(expected: list[dict], actual: list[dict]) -> tuple[list, list, list]:
    expected_by_path = {record["path"]: record for record in expected}
    actual_by_path = {record["path"]: record for record in actual}
    common = expected_by_path.keys() & actual_by_path.keys()
    modified = sorted(
        path
        for path in common
        if (expected_by_path[path]["size"], expected_by_path[path]["sha256"])
        != (actual_by_path[path]["size"], actual_by_path[path]["sha256"])
    )
    missing = sorted(expected_by_path.keys() - actual_by_path.keys())
    unexpected = sorted(actual_by_path.keys() - expected_by_path.keys())
    return modified, missing, unexpected


def _looks_like_manifest(document: dict) -> bool:
    keys = set(document)
    if keys == set(V2_FIELDS) or keys == set(V1_FIELDS):
        return document.get("algorithm") == ALGORITHM
    return False


def _looks_like_trust_store(document: dict) -> bool:
    return document.get("kind") == TRUST_STORE_KIND and "keys" in document


def _read_nofollow(path: Path, max_bytes: int | None = None) -> bytes:
    """Read a regular file without ever following a swapped-in symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise SealError(f"cannot read {path}: {error}") from error
    with os.fdopen(fd, "rb") as source:
        if max_bytes is None:
            return source.read()
        return source.read(max_bytes)


def reject_forbidden_files(directory: Path, files: list[dict]) -> None:
    """Reject keys, manifests or trust stores placed inside the tree."""
    for record in files:
        rel = record["path"]
        path = directory / rel
        name = rel.rsplit("/", 1)[-1].lower()
        prefix = _read_nofollow(path, 256).lstrip()
        if name.endswith(".pem") or (
            prefix.startswith(b"-----BEGIN ") and b"KEY-----" in prefix[:80]
        ):
            raise SealError(f"keys must stay outside the delivery tree: {path}")
        if not name.endswith(".json"):
            continue
        try:
            document = json.loads(_read_nofollow(path).decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(document, dict):
            continue
        if _looks_like_manifest(document):
            raise SealError(
                f"manifests must stay outside the delivery tree: {path}"
            )
        if _looks_like_trust_store(document):
            raise SealError(
                f"trust stores must stay outside the delivery tree: {path}"
            )


def guarded_inventory(directory: Path) -> list[dict]:
    """Inventory directory, proving it did not change during the scan.

    Identity snapshots taken before and after cover paths, file types,
    ``(dev, ino)`` identity, sizes and nanosecond mtimes. Every content
    read (hashing and forbidden-file classification) happens between the
    two snapshots, so a swapped or modified file is always caught. The
    tree is also refused if it contains keys, manifests or trust stores.
    """
    before = stat_snapshot(directory)
    files = inventory(directory)
    reject_forbidden_files(directory, files)
    after = stat_snapshot(directory)
    if before != after:
        raise SealError(f"directory changed while scanning: {directory}")
    return files


def _sync_directory(directory: Path) -> None:
    """fsync a directory; tolerate filesystems that reject it (EINVAL)."""
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    except OSError as error:
        if error.errno != errno.EINVAL:
            raise
    finally:
        os.close(fd)


def _staged_temp(parent: Path, hint: str, data: bytes) -> Path:
    """Write data to a synced hidden temp file in parent; fsync it."""
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{hint}.", suffix=".tmp", dir=parent
    )
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp


def publish_new(target: Path, data: bytes, *, hint: str = "manifest") -> None:
    """Publish data once, never overwriting an existing target.

    The bytes land in a synced temp file in target's directory and are
    published with a single non-overwriting hard link. An existing
    target is left byte-for-byte untouched; on failure no temp file or
    half-written target remains.
    """
    parent = target.parent
    tmp = _staged_temp(parent, hint, data)
    published = False
    try:
        try:
            os.link(tmp, target)
        except FileExistsError as error:
            raise SealError(f"manifest already exists: {target}") from error
        except OSError as error:
            raise SealError(f"cannot publish manifest {target}: {error}") from error
        published = True
        try:
            _sync_directory(parent)
        except OSError as error:
            raise SealError(
                f"manifest published but directory sync failed: {target}: {error}"
            ) from error
    finally:
        if not published:
            tmp.unlink(missing_ok=True)
        else:
            # The hard link keeps the inode alive under target.
            tmp.unlink(missing_ok=True)


def publish_replace(target: Path, data: bytes, *, hint: str) -> None:
    """Atomically replace target with synced data; clean up on failure."""
    parent = target.parent
    tmp = _staged_temp(parent, hint, data)
    replaced = False
    try:
        try:
            os.replace(tmp, target)
        except OSError as error:
            raise SealError(f"cannot publish {target}: {error}") from error
        replaced = True
        try:
            _sync_directory(parent)
        except OSError as error:
            raise SealError(
                f"{target} published but directory sync failed: {error}"
            ) from error
    finally:
        if not replaced:
            tmp.unlink(missing_ok=True)
        else:
            tmp.unlink(missing_ok=True)


def sign_directory(directory, private_key, manifest) -> dict:
    """Sign the inventory of directory and atomically create manifest."""
    directory = Path(directory)
    private_key = Path(private_key)
    manifest = Path(manifest)
    require_outside(directory, (private_key, manifest))
    key = load_private_key(private_key)
    public = key.public_key()
    key_id = key_id_of(public)
    files = guarded_inventory(directory)
    document = {
        "version": VERSION_CURRENT,
        "algorithm": ALGORITHM,
        "hash": HASH,
        "key_id": key_id,
        "files": files,
        "signature": base64.b64encode(
            key.sign(canonical_payload(VERSION_CURRENT, key_id, files))
        ).decode("ascii"),
    }
    data = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    publish_new(manifest, data)
    return document


def verify_directory(directory, manifest, public_key) -> dict:
    """Verify a signed manifest against directory using only public_key.

    Accepts manifest versions 1 and 2. The result keeps the original
    shape: ``{"valid": true}`` or ``valid: false`` with sorted
    ``modified`` / ``missing`` / ``unexpected`` lists.
    """
    directory = Path(directory)
    manifest = Path(manifest)
    public_key = Path(public_key)
    require_outside(directory, (manifest, public_key))
    key = load_public_key(public_key)
    version, files, signature, key_id = load_manifest(manifest)
    if version == 2 and key_id != key_id_of(key):
        return {"valid": False, "modified": [], "missing": [], "unexpected": []}
    try:
        key.verify(signature, canonical_payload(version, key_id, files))
    except InvalidSignature:
        return {"valid": False, "modified": [], "missing": [], "unexpected": []}
    modified, missing, unexpected = diff_inventory(
        files, guarded_inventory(directory)
    )
    if modified or missing or unexpected:
        return {
            "valid": False,
            "modified": modified,
            "missing": missing,
            "unexpected": unexpected,
        }
    return {"valid": True}
