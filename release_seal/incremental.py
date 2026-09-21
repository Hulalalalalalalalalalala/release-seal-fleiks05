"""Incremental (version 4) delta manifests.

``sign-incremental DIRECTORY PRIVATE BASE DELTA`` inventories the
current directory and, relative to a version 2 BASE manifest verifiable
by the given private key, writes a version 4 DELTA holding only the
added/modified records (``changes``) and the deleted paths (``removed``).
An empty delta — no changes and no removals — is legal.

A version 4 delta manifest holds exactly eight fields: ``version``
(``4``), ``algorithm``, ``hash``, ``key_id``, ``base_sha256`` (the
lowercase SHA-256 hex of the BASE file's raw bytes), ``changes``
(inventory records sorted by path), ``removed`` (sorted unique paths
never overlapping ``changes``) and ``signature``. The signature covers
every field except ``signature``, canonicalized exactly like version 2
(keys sorted, no whitespace, no Unicode escaping). DELTA is published
with the same non-overwriting atomic publish as ``sign``.

``verify-incremental DIRECTORY BASE DELTA PUBLIC`` trusts only the
given PEM Ed25519 public key: it validates the structure of BASE and
DELTA (exit 2 on format, I/O, path-conflict or scan-change problems),
then checks key ids, the base digest and both signatures — any trust
failure exits 1 with ``valid: false``. With trust established it applies
the delta to the BASE inventory and compares against a guarded scan of
the directory, reporting sorted ``modified``/``missing``/``unexpected``
lists on mismatch (exit 1) or ``{"valid": true}`` (exit 0).
"""

import base64
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from .seal import (
    ALGORITHM,
    HASH,
    SealError,
    _decode_signature_obj,
    canonical_payload,
    diff_inventory,
    guarded_inventory,
    is_key_id,
    key_id_of,
    load_private_key,
    load_public_key,
    publish_new,
    require_outside,
    valid_record,
    validate_manifest_document,
)

VERSION_INCREMENTAL = 4
V4_FIELDS = (
    "version",
    "algorithm",
    "hash",
    "key_id",
    "base_sha256",
    "changes",
    "removed",
    "signature",
)


def canonical_delta_payload(
    key_id: str, base_sha256: str, changes: list[dict], removed: list[str]
) -> bytes:
    """Return the canonical UTF-8 JSON a version 4 signature covers.

    The signed body holds every delta field except ``signature``, with
    keys sorted, no whitespace and no Unicode escaping — the same
    canonicalization rule as version 2 manifests.
    """
    body = {
        "version": VERSION_INCREMENTAL,
        "algorithm": ALGORITHM,
        "hash": HASH,
        "key_id": key_id,
        "base_sha256": base_sha256,
        "changes": changes,
        "removed": removed,
    }
    return json.dumps(
        body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def validate_delta_document(document: object):
    """Strictly validate a parsed version 4 delta manifest document.

    Returns ``(key_id, base_sha256, changes, removed, signature)`` with
    the signature decoded. Only a document with exactly the eight
    version 4 fields, well-formed values, ``changes`` sorted by path
    without duplicates and ``removed`` sorted, unique and disjoint from
    ``changes`` passes. Raises :class:`SealError` on any mismatch; a
    merely similar document does not validate.
    """
    if not isinstance(document, dict):
        raise SealError("delta manifest must be a JSON object")
    version = document.get("version")
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != VERSION_INCREMENTAL
    ):
        raise SealError(
            f"delta manifest field 'version' must be {VERSION_INCREMENTAL}"
        )
    if set(document) != set(V4_FIELDS):
        raise SealError(
            "delta manifest must contain exactly "
            + ", ".join(sorted(V4_FIELDS))
        )
    if document["algorithm"] != ALGORITHM:
        raise SealError(f"delta manifest field 'algorithm' must be {ALGORITHM!r}")
    if document["hash"] != HASH:
        raise SealError(f"delta manifest field 'hash' must be {HASH!r}")
    key_id = document["key_id"]
    if not is_key_id(key_id):
        raise SealError(
            "delta manifest field 'key_id' must be 64 lowercase hex digits"
        )
    base_sha256 = document["base_sha256"]
    if not is_key_id(base_sha256):
        raise SealError(
            "delta manifest field 'base_sha256' must be 64 lowercase hex digits"
        )
    changes = document["changes"]
    if not isinstance(changes, list) or any(not valid_record(r) for r in changes):
        raise SealError("delta manifest field 'changes' holds invalid records")
    change_paths = [record["path"] for record in changes]
    if change_paths != sorted(change_paths) or len(set(change_paths)) != len(
        change_paths
    ):
        raise SealError(
            "delta manifest field 'changes' must be sorted by path, "
            "without duplicates"
        )
    removed = document["removed"]
    if not isinstance(removed, list) or any(
        not isinstance(path, str) or path == "" for path in removed
    ):
        raise SealError(
            "delta manifest field 'removed' must be a list of paths"
        )
    if removed != sorted(removed) or len(set(removed)) != len(removed):
        raise SealError(
            "delta manifest field 'removed' must be sorted and unique"
        )
    if set(removed) & set(change_paths):
        raise SealError("delta manifest 'removed' overlaps 'changes'")
    signature = _decode_signature_obj(document["signature"], field="'signature'")
    return key_id, base_sha256, changes, removed, signature


def _read_json(path: Path, noun: str) -> tuple[bytes, object]:
    """Read a JSON file once, returning its raw bytes and parsed document."""
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read {noun} {path}: {error}") from error
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SealError(f"{noun} is not UTF-8 JSON: {path}: {error}") from error
    return raw, document


def _load_base_manifest(path: Path) -> tuple[bytes, list[dict], bytes, str]:
    """Read a version 2 base manifest: raw bytes, files, signature, key id."""
    raw, document = _read_json(path, "base manifest")
    try:
        _, files, signature, key_id = validate_manifest_document(document, (2,))
    except SealError as error:
        raise SealError(f"{error}: {path}") from error
    return raw, files, signature, key_id


def _load_delta(path: Path):
    """Read and strictly validate a version 4 delta manifest file."""
    _, document = _read_json(path, "delta manifest")
    try:
        return validate_delta_document(document)
    except SealError as error:
        raise SealError(f"{error}: {path}") from error


def sign_incremental_directory(directory, private_key, base, delta) -> dict:
    """Sign a version 4 delta of directory relative to a version 2 BASE.

    BASE must be a version 2 manifest whose signature verifies with the
    given private key. The delta holds only the records added or modified
    relative to BASE (``changes``) and the paths deleted since BASE
    (``removed``); an empty delta is legal. DELTA is published without
    overwriting, exactly like ``sign``.
    """
    directory = Path(directory)
    private_key = Path(private_key)
    base = Path(base)
    delta = Path(delta)
    require_outside(directory, (private_key, base, delta))
    key = load_private_key(private_key)
    key_id = key_id_of(key.public_key())
    raw_base, files, base_signature, base_key_id = _load_base_manifest(base)
    if base_key_id != key_id:
        raise SealError(f"base manifest is signed by a different key: {base}")
    try:
        key.public_key().verify(
            base_signature, canonical_payload(2, base_key_id, files)
        )
    except InvalidSignature as error:
        raise SealError(
            f"base manifest signature does not verify: {base}"
        ) from error
    current = guarded_inventory(directory)
    base_by_path = {record["path"]: record for record in files}
    changes = []
    for record in current:
        base_record = base_by_path.get(record["path"])
        if base_record is None or (
            (base_record["size"], base_record["sha256"])
            != (record["size"], record["sha256"])
        ):
            changes.append(record)
    removed = sorted(set(base_by_path) - {record["path"] for record in current})
    base_sha256 = hashlib.sha256(raw_base).hexdigest()
    document = {
        "version": VERSION_INCREMENTAL,
        "algorithm": ALGORITHM,
        "hash": HASH,
        "key_id": key_id,
        "base_sha256": base_sha256,
        "changes": changes,
        "removed": removed,
        "signature": base64.b64encode(
            key.sign(
                canonical_delta_payload(key_id, base_sha256, changes, removed)
            )
        ).decode("ascii"),
    }
    data = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8"
    )
    publish_new(delta, data, hint="delta", noun="delta manifest")
    return document


def verify_incremental(directory, base, delta, public_key) -> dict:
    """Verify directory against a version 2 BASE plus a version 4 DELTA.

    Only the given PEM Ed25519 public key is trusted. Structural problems
    in BASE or DELTA raise :class:`SealError` (exit 2); a key id, base
    digest or signature mismatch is a trust failure reported as
    ``valid: false`` (exit 1). Once trust is established the delta is
    applied to the BASE inventory and the result is compared against a
    guarded scan of the directory.
    """
    directory = Path(directory)
    base = Path(base)
    delta = Path(delta)
    public_key = Path(public_key)
    require_outside(directory, (base, delta, public_key))
    key = load_public_key(public_key)
    raw_base, files, base_signature, base_key_id = _load_base_manifest(base)
    delta_key_id, base_sha256, changes, removed, delta_signature = _load_delta(
        delta
    )
    invalid = {"valid": False, "modified": [], "missing": [], "unexpected": []}
    key_id = key_id_of(key)
    if base_key_id != key_id or delta_key_id != key_id:
        return invalid
    if base_sha256 != hashlib.sha256(raw_base).hexdigest():
        return invalid
    try:
        key.verify(base_signature, canonical_payload(2, base_key_id, files))
        key.verify(
            delta_signature,
            canonical_delta_payload(delta_key_id, base_sha256, changes, removed),
        )
    except InvalidSignature:
        return invalid
    expected_by_path = {record["path"]: record for record in files}
    for path in removed:
        expected_by_path.pop(path, None)
    for record in changes:
        expected_by_path[record["path"]] = record
    expected = [expected_by_path[path] for path in sorted(expected_by_path)]
    modified, missing, unexpected = diff_inventory(
        expected, guarded_inventory(directory)
    )
    if modified or missing or unexpected:
        return {
            "valid": False,
            "modified": modified,
            "missing": missing,
            "unexpected": unexpected,
        }
    return {"valid": True}
