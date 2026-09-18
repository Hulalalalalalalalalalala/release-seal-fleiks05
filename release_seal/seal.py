"""Sign and verify a directory inventory with Ed25519."""

import base64
import binascii
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from .inventory import inventory

VERSION = 1
ALGORITHM = "Ed25519"
HASH = "SHA-256"
FIELDS = ("version", "algorithm", "hash", "files", "signature")


class SealError(ValueError):
    """A user-facing failure: print the message and exit with status 2."""


def _payload(files: list[dict]) -> bytes:
    """Return the canonical UTF-8 JSON the signature covers.

    The signed body holds version, algorithm, hash and files, with keys
    sorted, no whitespace and no Unicode escaping.
    """
    body = {"version": VERSION, "algorithm": ALGORITHM, "hash": HASH, "files": files}
    return json.dumps(
        body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _require_outside(directory: Path, paths: tuple[Path, ...]) -> None:
    root = directory.resolve()
    for path in paths:
        if path.resolve().is_relative_to(root):
            raise SealError(
                f"keys and manifests must stay outside the delivery tree: {path}"
            )


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    # The key is only read into memory for signing; it is never printed,
    # copied into the manifest or written anywhere else.
    try:
        data = path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read private key {path}: {error}") from error
    try:
        key = load_pem_private_key(data, password=None)
    except Exception as error:
        raise SealError(f"cannot load PEM private key {path}: {error}") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise SealError(f"expected an Ed25519 private key: {path}")
    return key


def _load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read public key {path}: {error}") from error
    try:
        key = load_pem_public_key(data)
    except Exception as error:
        raise SealError(f"cannot load PEM public key {path}: {error}") from error
    if not isinstance(key, Ed25519PublicKey):
        raise SealError(f"expected an Ed25519 public key: {path}")
    return key


def _scan_unchanged(directory: Path) -> list[dict]:
    files = inventory(directory)
    if inventory(directory) != files:
        raise SealError(f"directory changed while scanning: {directory}")
    return files


def _valid_record(record: object) -> bool:
    if not isinstance(record, dict) or set(record) != {"path", "size", "sha256"}:
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


def _load_manifest(path: Path) -> tuple[list[dict], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read manifest {path}: {error}") from error
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SealError(f"manifest is not UTF-8 JSON: {path}: {error}") from error
    if not isinstance(document, dict) or set(document) != set(FIELDS):
        raise SealError(
            f"manifest must contain exactly {', '.join(FIELDS)}: {path}"
        )
    version = document["version"]
    if not isinstance(version, int) or isinstance(version, bool) or version != VERSION:
        raise SealError(f"manifest field 'version' must be {VERSION}: {path}")
    if document["algorithm"] != ALGORITHM:
        raise SealError(f"manifest field 'algorithm' must be {ALGORITHM!r}: {path}")
    if document["hash"] != HASH:
        raise SealError(f"manifest field 'hash' must be {HASH!r}: {path}")
    files = document["files"]
    if not isinstance(files, list) or any(not _valid_record(r) for r in files):
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
    return files, decoded


def _diff(expected: list[dict], actual: list[dict]) -> tuple[list, list, list]:
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


def sign_directory(directory, private_key, manifest) -> dict:
    """Sign the inventory of directory and atomically create manifest."""
    directory = Path(directory)
    private_key = Path(private_key)
    manifest = Path(manifest)
    _require_outside(directory, (private_key, manifest))
    key = _load_private_key(private_key)
    files = _scan_unchanged(directory)
    document = {
        "version": VERSION,
        "algorithm": ALGORITHM,
        "hash": HASH,
        "files": files,
        "signature": base64.b64encode(key.sign(_payload(files))).decode("ascii"),
    }
    data = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    try:
        fd = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError as error:
        raise SealError(f"manifest already exists: {manifest}") from error
    except OSError as error:
        raise SealError(f"cannot create manifest {manifest}: {error}") from error
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
    except OSError as error:
        manifest.unlink(missing_ok=True)
        raise SealError(f"cannot write manifest {manifest}: {error}") from error
    return document


def verify_directory(directory, manifest, public_key) -> dict:
    """Verify a signed manifest against directory using only public_key."""
    directory = Path(directory)
    manifest = Path(manifest)
    public_key = Path(public_key)
    _require_outside(directory, (manifest, public_key))
    key = _load_public_key(public_key)
    files, signature = _load_manifest(manifest)
    try:
        key.verify(signature, _payload(files))
    except InvalidSignature:
        return {"valid": False, "modified": [], "missing": [], "unexpected": []}
    modified, missing, unexpected = _diff(files, _scan_unchanged(directory))
    if modified or missing or unexpected:
        return {
            "valid": False,
            "modified": modified,
            "missing": missing,
            "unexpected": unexpected,
        }
    return {"valid": True}
