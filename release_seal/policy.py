"""Offline threshold policy and multisig manifest verification.

A policy is a versioned JSON document naming the key ids allowed to sign
a release and how many distinct, currently-valid signatures a version 3
manifest must carry before its file inventory is trusted::

    {
      "kind": "release-seal-policy",
      "version": 1,
      "threshold": 2,
      "allowed_key_ids": ["<key id>", "<key id>"]
    }

Verification combines the policy with the trust store: only store keys
that are ``active``, on the allow list and whose signature actually
validates count toward the threshold. Every other signer listed in the
manifest is classified (unknown / revoked / disallowed / invalid) so an
offline operator can see why a release fell short.
"""

import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from .seal import (
    POLICY_KIND,
    VERSION_MULTI,
    SealError,
    canonical_payload,
    diff_inventory,
    guarded_inventory,
    is_key_id,
    load_manifest,
    require_outside,
)
from .trust import ACTIVE, REVOKED, _stored_public_key, load_store

POLICY_VERSION = 1

STATUS_VALID = "valid"
STATUS_UNKNOWN = "unknown"
STATUS_REVOKED = "revoked"
STATUS_DISALLOWED = "disallowed"
STATUS_INVALID = "invalid"

REASON_THRESHOLD_NOT_MET = "threshold_not_met"
REASON_FILE_MISMATCH = "file_mismatch"

_POLICY_FIELDS = ("kind", "version", "threshold", "allowed_key_ids")


def load_policy(path) -> dict:
    """Read and strictly validate a threshold policy file."""
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise SealError(f"cannot read policy {path}: {error}") from error
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as error:
        raise SealError(f"policy is not UTF-8 JSON: {path}: {error}") from error
    return _validate_policy(document, path)


def _validate_policy(document: object, path: Path) -> dict:
    if not isinstance(document, dict):
        raise SealError(f"policy must be a JSON object: {path}")
    if set(document) != set(_POLICY_FIELDS):
        raise SealError(
            f"policy must contain exactly {', '.join(sorted(_POLICY_FIELDS))}: {path}"
        )
    if document.get("kind") != POLICY_KIND:
        raise SealError(f"not a release seal policy: {path}")
    version = document.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise SealError(f"policy field 'version' must be an integer: {path}")
    if version != POLICY_VERSION:
        raise SealError(
            f"policy version {version} is not supported "
            f"(supported: {POLICY_VERSION}): {path}"
        )
    threshold = document.get("threshold")
    if (
        not isinstance(threshold, int)
        or isinstance(threshold, bool)
        or threshold <= 0
    ):
        raise SealError(
            f"policy field 'threshold' must be a positive integer: {path}"
        )
    allowed = document.get("allowed_key_ids")
    if not isinstance(allowed, list) or not allowed:
        raise SealError(
            f"policy field 'allowed_key_ids' must be a non-empty list: {path}"
        )
    if not all(is_key_id(value) for value in allowed):
        raise SealError(
            f"policy field 'allowed_key_ids' must hold 64 lowercase hex "
            f"digits key ids: {path}"
        )
    if len(set(allowed)) != len(allowed):
        raise SealError(
            f"policy field 'allowed_key_ids' must not repeat key ids: {path}"
        )
    if threshold > len(allowed):
        raise SealError(
            f"policy threshold {threshold} exceeds {len(allowed)} allowed "
            f"key id(s): {path}"
        )
    return document


def _policy_failure(policy: dict, matched, statuses, reason, lists) -> dict:
    modified, missing, unexpected = lists
    return {
        "valid": False,
        "reason": reason,
        "threshold": policy["threshold"],
        "matched": len(matched),
        "matched_key_ids": sorted(matched),
        "keys": statuses,
        "modified": modified,
        "missing": missing,
        "unexpected": unexpected,
    }


def verify_policy(directory, manifest_path, store_path, policy_path) -> dict:
    """Verify a version 3 multisig manifest against a threshold policy.

    Only distinct store keys that are active, allowed by the policy and
    carry a valid signature count. Below the threshold the report is
    ``threshold_not_met`` and the directory is not inventoried; at the
    threshold the inventory is checked and a mismatch yields
    ``file_mismatch`` with the sorted modified/missing/unexpected lists.
    Format and I/O failures raise (exit status 2).
    """
    directory = Path(directory)
    manifest_path = Path(manifest_path)
    store_path = Path(store_path)
    policy_path = Path(policy_path)
    require_outside(directory, (manifest_path, store_path, policy_path))
    policy = load_policy(policy_path)
    store = load_store(store_path)
    version, files, signatures, _ = load_manifest(manifest_path)
    if version != VERSION_MULTI:
        raise SealError(
            f"verify-policy requires a version {VERSION_MULTI} multisig "
            f"manifest (got version {version}): {manifest_path}"
        )

    threshold = policy["threshold"]
    allowed = set(policy["allowed_key_ids"])
    keys = store["keys"]
    payload = canonical_payload(version, None, files)

    matched: set[str] = set()
    statuses: dict[str, str] = {}
    for signer_id in sorted(signatures):
        record = keys.get(signer_id)
        if record is None:
            statuses[signer_id] = STATUS_UNKNOWN
            continue
        if record["status"] == REVOKED:
            statuses[signer_id] = STATUS_REVOKED
            continue
        if signer_id not in allowed:
            statuses[signer_id] = STATUS_DISALLOWED
            continue
        # Active, allowed and present in the store: the signature decides.
        if record["status"] != ACTIVE:  # pragma: no cover - store validation
            statuses[signer_id] = STATUS_UNKNOWN
            continue
        key = _stored_public_key(record)
        try:
            key.verify(signatures[signer_id], payload)
        except InvalidSignature:
            statuses[signer_id] = STATUS_INVALID
            continue
        statuses[signer_id] = STATUS_VALID
        matched.add(signer_id)

    if len(matched) < threshold:
        return _policy_failure(
            policy,
            matched,
            statuses,
            REASON_THRESHOLD_NOT_MET,
            ([], [], []),
        )

    modified, missing, unexpected = diff_inventory(
        files, guarded_inventory(directory)
    )
    if modified or missing or unexpected:
        return _policy_failure(
            policy,
            matched,
            statuses,
            REASON_FILE_MISMATCH,
            (modified, missing, unexpected),
        )
    return {
        "valid": True,
        "threshold": threshold,
        "matched": len(matched),
        "matched_key_ids": sorted(matched),
        "keys": statuses,
    }
