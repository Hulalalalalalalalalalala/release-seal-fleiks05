"""Offline trust store for pinned Ed25519 public keys."""

import json
import os
from pathlib import Path
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

from .seal import (
    SealError,
    _diff,
    _load_manifest,
    _load_public_key,
    _payload,
    _require_outside,
    _scan_unchanged,
    _valid_key_id,
    key_id_of,
)

STORE_VERSION = 1
ENTRY_FIELDS = ("public_key", "status", "reason")
STATUSES = ("active", "revoked")


def load_store(path: Path) -> dict:
    """Read and fully validate a trust store, including every pinned key."""
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read trust store {path}: {error}") from error
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SealError(f"trust store is not UTF-8 JSON: {path}: {error}") from error
    if not isinstance(document, dict) or set(document) != {"version", "keys"}:
        raise SealError(f"trust store must contain exactly version, keys: {path}")
    if document["version"] != STORE_VERSION:
        raise SealError(
            f"trust store field 'version' must be {STORE_VERSION}: {path}"
        )
    keys = document["keys"]
    if not isinstance(keys, dict):
        raise SealError(f"trust store field 'keys' must be an object: {path}")
    for key_id, entry in keys.items():
        if not _valid_key_id(key_id):
            raise SealError(f"trust store holds an invalid key id: {key_id!r}")
        if not isinstance(entry, dict) or set(entry) != set(ENTRY_FIELDS):
            raise SealError(
                f"trust store entry must contain exactly "
                f"{', '.join(ENTRY_FIELDS)}: {key_id}"
            )
        if entry["status"] not in STATUSES:
            raise SealError(f"trust store entry has an invalid status: {key_id}")
        if entry["reason"] is not None and not isinstance(entry["reason"], str):
            raise SealError(
                f"trust store entry reason must be text or null: {key_id}"
            )
        pem = entry["public_key"]
        if not isinstance(pem, str):
            raise SealError(f"trust store entry public_key must be PEM text: {key_id}")
        try:
            key = load_pem_public_key(pem.encode("utf-8"))
        except Exception as error:
            raise SealError(
                f"trust store entry public_key is not PEM: {key_id}"
            ) from error
        if not isinstance(key, Ed25519PublicKey):
            raise SealError(f"trust store entry is not an Ed25519 key: {key_id}")
        if key_id_of(key) != key_id:
            raise SealError(f"trust store entry does not match its key id: {key_id}")
    return document


def save_store(path: Path, document: dict) -> None:
    """Atomically replace the trust store via a synced temporary file."""
    data = (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as error:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise SealError(f"cannot update trust store {path}: {error}") from error


def import_key(public_key, store) -> dict:
    """Pin a PEM Ed25519 public key in the store; idempotent, never revives."""
    public_key = Path(public_key)
    store = Path(store)
    key = _load_public_key(public_key)
    key_id = key_id_of(key)
    if store.exists():
        document = load_store(store)
    else:
        document = {"version": STORE_VERSION, "keys": {}}
    entry = document["keys"].get(key_id)
    if entry is not None:
        # Re-importing is a no-op; a revoked key stays revoked.
        return {"key_id": key_id, "status": entry["status"], "reason": entry["reason"]}
    pem = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    document["keys"][key_id] = {
        "public_key": pem.decode("ascii"),
        "status": "active",
        "reason": None,
    }
    save_store(store, document)
    return {"key_id": key_id, "status": "active", "reason": None}


def revoke_key(store, key_id, reason=None) -> dict:
    """Mark a trusted key as revoked; revoking twice is idempotent."""
    store = Path(store)
    if not _valid_key_id(key_id):
        raise SealError(
            f"expected a key id of 64 lowercase hex characters: {key_id!r}"
        )
    document = load_store(store)
    entry = document["keys"].get(key_id)
    if entry is None:
        raise SealError(f"key is not in the trust store: {key_id}")
    if entry["status"] == "revoked" and reason is None:
        return {"key_id": key_id, "status": "revoked", "reason": entry["reason"]}
    entry["status"] = "revoked"
    if reason is not None:
        entry["reason"] = reason
    save_store(store, document)
    return {"key_id": key_id, "status": "revoked", "reason": entry["reason"]}


def verify_trusted(directory, manifest, store) -> dict:
    """Verify a version 2 manifest against directory using the trust store."""
    directory = Path(directory)
    manifest = Path(manifest)
    store = Path(store)
    _require_outside(directory, (manifest, store))
    document, signature = _load_manifest(manifest)
    if document["version"] != 2:
        raise SealError(
            f"verify-trusted requires a version 2 manifest with key_id: {manifest}"
        )
    key_id = document["key_id"]
    entry = load_store(store)["keys"].get(key_id)
    failure = {
        "valid": False,
        "key_id": key_id,
        "modified": [],
        "missing": [],
        "unexpected": [],
    }
    if entry is None:
        return {**failure, "reason": "unknown_key"}
    if entry["status"] == "revoked":
        result = {**failure, "reason": "revoked"}
        if entry["reason"] is not None:
            result["detail"] = entry["reason"]
        return result
    key = load_pem_public_key(entry["public_key"].encode("utf-8"))
    try:
        key.verify(signature, _payload(document))
    except InvalidSignature:
        return {**failure, "reason": "invalid_signature"}
    modified, missing, unexpected = _diff(
        document["files"], _scan_unchanged(directory)
    )
    if modified or missing or unexpected:
        return {
            "valid": False,
            "key_id": key_id,
            "reason": "mismatch",
            "modified": modified,
            "missing": missing,
            "unexpected": unexpected,
        }
    return {"valid": True, "key_id": key_id}
