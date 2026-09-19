"""Offline threshold-signature policies for version 3 manifests.

A policy is a small JSON document naming the minimum number of
distinct trusted signatures (``threshold``) and the key ids allowed to
count toward it (``allowed_key_ids``). ``verify_policy`` checks a
version 3 manifest against an offline trust store under such a policy:
only signatures from distinct store keys that are active, allowed and
cryptographically valid count. The directory inventory is compared
only once the threshold is met.
"""

import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from .seal import (
    MULTI_VERSIONS,
    POLICY_FIELDS,
    SealError,
    canonical_payload,
    diff_inventory,
    guarded_inventory,
    is_key_id,
    load_manifest,
    require_outside,
)
from .trust import REVOKED, _stored_public_key, load_store

POLICY_VERSION = 1

STATUS_VALID = "valid"
STATUS_UNKNOWN = "unknown"
STATUS_REVOKED = "revoked"
STATUS_DISALLOWED = "disallowed"
STATUS_INVALID = "invalid"

REASON_THRESHOLD_NOT_MET = "threshold_not_met"
REASON_FILE_MISMATCH = "file_mismatch"


def load_policy(path: Path) -> dict:
    """Load and strictly validate a threshold policy document."""
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read policy {path}: {error}") from error
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SealError(f"policy is not UTF-8 JSON: {path}: {error}") from error
    return validate_policy_document(document, path)


def validate_policy_document(document: object, path: Path) -> dict:
    """Validate a parsed policy document; see load_policy."""
    if not isinstance(document, dict):
        raise SealError(f"policy must be a JSON object: {path}")
    if set(document) != set(POLICY_FIELDS):
        raise SealError(
            f"policy must contain exactly "
            f"{', '.join(sorted(POLICY_FIELDS))}: {path}"
        )
    version = document["version"]
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != POLICY_VERSION
    ):
        raise SealError(f"policy field 'version' must be {POLICY_VERSION}: {path}")
    threshold = document["threshold"]
    if (
        not isinstance(threshold, int)
        or isinstance(threshold, bool)
        or threshold < 1
    ):
        raise SealError(
            f"policy field 'threshold' must be a positive integer: {path}"
        )
    allowed = document["allowed_key_ids"]
    if not isinstance(allowed, list) or not allowed:
        raise SealError(
            f"policy field 'allowed_key_ids' must be a non-empty list: {path}"
        )
    if any(not is_key_id(key_id) for key_id in allowed):
        raise SealError(f"policy 'allowed_key_ids' holds an invalid key id: {path}")
    if len(set(allowed)) != len(allowed):
        raise SealError(f"policy 'allowed_key_ids' holds duplicates: {path}")
    if threshold > len(allowed):
        raise SealError(
            f"policy threshold exceeds the number of allowed key ids: {path}"
        )
    return {
        "version": version,
        "threshold": threshold,
        "allowed_key_ids": allowed,
    }


def verify_policy(directory, manifest_path, store_path, policy_path) -> dict:
    """Verify a version 3 manifest against a trust store and a policy.

    Each manifest signature is classified, sorted by key id, as
    ``valid`` (active, allowed and correctly signed), ``unknown`` (not
    in the store), ``revoked``, ``disallowed`` (active but not allowed)
    or ``invalid`` (allowed but the signature does not verify). Only
    ``valid`` distinct keys count toward the threshold. Failures always
    report ``valid: false`` with a stable ``reason`` and sorted file
    lists; the directory is inventoried only after the threshold is met.
    """
    directory = Path(directory)
    manifest_path = Path(manifest_path)
    store_path = Path(store_path)
    policy_path = Path(policy_path)
    require_outside(directory, (manifest_path, store_path, policy_path))
    policy = load_policy(policy_path)
    store = load_store(store_path)
    version, files, signatures, _ = load_manifest(
        manifest_path, versions=MULTI_VERSIONS
    )
    keys = store["keys"]
    allowed = set(policy["allowed_key_ids"])

    statuses: dict[str, str] = {}
    verified = 0
    for key_id in sorted(signatures):
        record = keys.get(key_id)
        if record is None:
            statuses[key_id] = STATUS_UNKNOWN
            continue
        if record["status"] == REVOKED:
            statuses[key_id] = STATUS_REVOKED
            continue
        if key_id not in allowed:
            statuses[key_id] = STATUS_DISALLOWED
            continue
        key = _stored_public_key(record)
        try:
            key.verify(signatures[key_id], canonical_payload(version, None, files))
        except InvalidSignature:
            statuses[key_id] = STATUS_INVALID
            continue
        statuses[key_id] = STATUS_VALID
        verified += 1

    summary = {
        "threshold": policy["threshold"],
        "verified": verified,
        "signatures": statuses,
    }
    if verified < policy["threshold"]:
        return {
            "valid": False,
            "reason": REASON_THRESHOLD_NOT_MET,
            **summary,
            "modified": [],
            "missing": [],
            "unexpected": [],
        }
    modified, missing, unexpected = diff_inventory(
        files, guarded_inventory(directory)
    )
    if modified or missing or unexpected:
        return {
            "valid": False,
            "reason": REASON_FILE_MISMATCH,
            **summary,
            "modified": modified,
            "missing": missing,
            "unexpected": unexpected,
        }
    return {"valid": True, **summary}
