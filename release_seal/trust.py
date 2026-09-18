"""Offline public-key trust store and trusted verification.

The store is a versioned JSON document holding, per key id (the
lowercase SHA-256 hex of a key's DER SubjectPublicKeyInfo), the PEM
public key and an ``active``/``revoked`` status with a revocation
reason. Mutations are atomic (synced temp file plus one ``os.replace``),
re-importing an active key is idempotent, and a revoked key can never
be restored.
"""

import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from .seal import (
    ALGORITHM,
    TRUST_STORE_KIND,
    VERSION_MULTI,
    SealError,
    canonical_payload,
    decode_public_key,
    diff_inventory,
    guarded_inventory,
    is_key_id,
    key_id_of,
    load_manifest,
    load_public_key,
    publish_replace,
    require_outside,
)

STORE_VERSION = 1
ACTIVE = "active"
REVOKED = "revoked"

REASON_UNKNOWN_KEY = "unknown_key"
REASON_REVOKED = "revoked"
REASON_INVALID_SIGNATURE = "invalid_signature"
REASON_FILE_MISMATCH = "file_mismatch"

MAX_REASON_LENGTH = 1024


def _entry(pem: str, status: str, reason: str | None) -> dict:
    return {
        "public_key_pem": pem,
        "status": status,
        "revoked_reason": reason,
    }


def _new_store() -> dict:
    return {
        "kind": TRUST_STORE_KIND,
        "version": STORE_VERSION,
        "algorithm": ALGORITHM,
        "keys": {},
    }


def _validate_store(document: object, path: Path) -> dict:
    if not isinstance(document, dict):
        raise SealError(f"trust store must be a JSON object: {path}")
    if document.get("kind") != TRUST_STORE_KIND:
        raise SealError(f"not a release seal trust store: {path}")
    version = document.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise SealError(f"trust store field 'version' must be an integer: {path}")
    if version < 1 or version > STORE_VERSION:
        raise SealError(
            f"trust store version {version} is not supported "
            f"(supported: {STORE_VERSION}): {path}"
        )
    if document.get("algorithm") != ALGORITHM:
        raise SealError(f"trust store field 'algorithm' must be {ALGORITHM!r}: {path}")
    keys = document.get("keys")
    if not isinstance(keys, dict):
        raise SealError(f"trust store field 'keys' must be an object: {path}")
    for stored_id, record in keys.items():
        if not is_key_id(stored_id):
            raise SealError(f"trust store holds an invalid key id: {path}")
        if not isinstance(record, dict) or set(record) != {
            "public_key_pem",
            "status",
            "revoked_reason",
        }:
            raise SealError(f"trust store entry {stored_id} is malformed: {path}")
        pem = record["public_key_pem"]
        status = record["status"]
        reason = record["revoked_reason"]
        if not isinstance(pem, str) or status not in (ACTIVE, REVOKED):
            raise SealError(f"trust store entry {stored_id} is malformed: {path}")
        if reason is not None and not isinstance(reason, str):
            raise SealError(f"trust store entry {stored_id} is malformed: {path}")
        try:
            key = decode_public_key(pem.encode("ascii"), where=str(path))
        except SealError as error:
            raise SealError(
                f"trust store entry {stored_id} holds an invalid public key: {path}"
            ) from error
        if key_id_of(key) != stored_id:
            raise SealError(
                f"trust store entry {stored_id} does not match its key id: {path}"
            )
    return document


def load_store(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise SealError(f"cannot read trust store {path}: {error}") from error
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as error:
        raise SealError(f"trust store is not UTF-8 JSON: {path}: {error}") from error
    return _validate_store(document, path)


def _write_store(path: Path, document: dict) -> None:
    data = (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    publish_replace(path, data, hint="trust-store")


def normalize_reason(reason: str | None) -> str | None:
    if reason is None:
        return None
    reason = reason.strip()
    return reason or None


def import_key(public_path, store_path) -> dict:
    """Import a PEM Ed25519 public key into the store.

    Importing an already-active key is idempotent and rewrites nothing.
    A revoked key is never revived: the call fails with status 2 and
    the store is left untouched.
    """
    public_path = Path(public_path)
    store_path = Path(store_path)
    key = load_public_key(public_path)
    key_id = key_id_of(key)
    pem = key.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")

    if store_path.exists():
        document = load_store(store_path)
        existing = document["keys"].get(key_id)
        if existing is not None:
            if existing["status"] == REVOKED:
                raise SealError(
                    f"key {key_id} is revoked in {store_path}; a revoked key "
                    "cannot be imported again"
                )
            return {"key_id": key_id, "status": ACTIVE, "changed": False}
        document["keys"][key_id] = _entry(pem, ACTIVE, None)
    else:
        document = _new_store()
        document["keys"][key_id] = _entry(pem, ACTIVE, None)
    _write_store(store_path, document)
    return {"key_id": key_id, "status": ACTIVE, "changed": True}


def revoke_key(store_path, key_id, reason: str | None = None) -> dict:
    """Mark a key revoked with an optional reason.

    Revoking an unknown key fails with status 2. Revoking an already
    revoked key is an idempotent no-op: the original revocation record
    (including its reason) is preserved.
    """
    store_path = Path(store_path)
    if not is_key_id(key_id):
        raise SealError(f"not a key id (64 lowercase hex digits): {key_id!r}")
    if not store_path.exists():
        raise SealError(f"trust store does not exist: {store_path}")
    reason = normalize_reason(reason)
    if reason is not None and len(reason) > MAX_REASON_LENGTH:
        raise SealError(
            f"revocation reason must be at most {MAX_REASON_LENGTH} characters"
        )
    document = load_store(store_path)
    record = document["keys"].get(key_id)
    if record is None:
        raise SealError(f"unknown key id in trust store: {key_id}")
    if record["status"] == REVOKED:
        return {
            "key_id": key_id,
            "status": REVOKED,
            "reason": record["revoked_reason"],
            "changed": False,
        }
    record["status"] = REVOKED
    record["revoked_reason"] = reason
    _write_store(store_path, document)
    return {
        "key_id": key_id,
        "status": REVOKED,
        "reason": reason,
        "changed": True,
    }


def _trusted_failure(key_id, reason: str) -> dict:
    return {
        "valid": False,
        "key_id": key_id,
        "reason": reason,
        "modified": [],
        "missing": [],
        "unexpected": [],
    }


def _stored_public_key(record: dict):
    return decode_public_key(
        record["public_key_pem"].encode("ascii"), where="trust store"
    )


def verify_trusted(directory, manifest_path, store_path) -> dict:
    """Verify a manifest against a directory using only the trust store.

    Version 2 manifests name their signer via ``key_id``; legacy
    version 1 manifests are matched against the store's keys. Failures
    always report ``valid: false`` with a stable ``reason`` and sorted
    file lists, never success.
    """
    directory = Path(directory)
    manifest_path = Path(manifest_path)
    store_path = Path(store_path)
    require_outside(directory, (manifest_path, store_path))
    document = load_store(store_path)
    version, files, signature, key_id = load_manifest(manifest_path)
    if version == VERSION_MULTI:
        raise SealError(
            f"version {VERSION_MULTI} multisig manifests require a threshold "
            f"policy; use verify-policy: {manifest_path}"
        )
    keys = document["keys"]

    if version == 2:
        record = keys.get(key_id)
        if record is None:
            return _trusted_failure(key_id, REASON_UNKNOWN_KEY)
        if record["status"] == REVOKED:
            return _trusted_failure(key_id, REASON_REVOKED)
        key = _stored_public_key(record)
        try:
            key.verify(signature, canonical_payload(version, key_id, files))
        except InvalidSignature:
            return _trusted_failure(key_id, REASON_INVALID_SIGNATURE)
        signer_id = key_id
    else:
        # Version 1 carries no key id: a revoked signer is reported as
        # revoked even before trying active keys; otherwise the unique
        # active key whose signature validates is the signer.
        for candidate_id, record in keys.items():
            if record["status"] != REVOKED:
                continue
            key = _stored_public_key(record)
            try:
                key.verify(signature, canonical_payload(version, None, files))
            except InvalidSignature:
                continue
            return _trusted_failure(candidate_id, REASON_REVOKED)
        signer_id = None
        for candidate_id, record in keys.items():
            if record["status"] != ACTIVE:
                continue
            key = _stored_public_key(record)
            try:
                key.verify(signature, canonical_payload(version, None, files))
            except InvalidSignature:
                continue
            signer_id = candidate_id
            break
        if signer_id is None:
            return _trusted_failure(None, REASON_UNKNOWN_KEY)

    modified, missing, unexpected = diff_inventory(
        files, guarded_inventory(directory)
    )
    if modified or missing or unexpected:
        return {
            "valid": False,
            "key_id": signer_id,
            "reason": REASON_FILE_MISMATCH,
            "modified": modified,
            "missing": missing,
            "unexpected": unexpected,
        }
    return {"valid": True, "key_id": signer_id}
