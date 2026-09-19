"""Offline audit reports for batch verification.

``audit-batch BATCH REPORT`` runs a BATCH exactly like ``verify-batch``
— same format, relative-path base, input order, directory restrictions
and exit codes, empty array included — and additionally publishes an
immutable audit report. The report is UTF-8 JSON with exactly
``kind`` (``"release-seal-audit-report"``), ``version`` (``1``),
``batch_sha256`` (lowercase SHA-256 hex of the BATCH file's raw bytes),
``valid`` and ``summary`` (same meaning as the batch report) and
``results``. Results follow the input order; each item carries ``id``,
``command``, ``code`` and ``outcome`` (``passed``/``failed``/``error``
for codes 0/1/2). Codes 0 and 1 attach the original ``result``; code 2
attaches a non-empty ``error`` and a stable ``error_kind`` (one of
``input``, ``io``, ``unsafe``, ``changed``, ``internal``). Item
``args``, key material, signatures and tracebacks are never recorded.

The REPORT path must stay outside every item's delivery tree and is
never overwritten: the bytes land in a synced hidden temp file in the
same directory and are published with a single non-overwriting link,
then the directory is synced. A failure before publishing leaves no
residue; if the directory sync after publishing fails, the complete
report stays in place, the temp file is removed and the error reports
that durability is uncertain. On success the report is printed to
standard output and the exit code follows the batch result.
"""

import hashlib
import json
from pathlib import Path

from .batch import ARITY, batch_exit_code, execute_batch, parse_batch
from .seal import SealError, is_key_id, publish_new, require_outside

AUDIT_KIND = "release-seal-audit-report"
AUDIT_VERSION = 1

ERROR_KIND_INPUT = "input"
ERROR_KIND_IO = "io"
ERROR_KIND_UNSAFE = "unsafe"
ERROR_KIND_CHANGED = "changed"
ERROR_KIND_INTERNAL = "internal"
ERROR_KINDS = (
    ERROR_KIND_INPUT,
    ERROR_KIND_IO,
    ERROR_KIND_UNSAFE,
    ERROR_KIND_CHANGED,
    ERROR_KIND_INTERNAL,
)

_OUTCOME = {0: "passed", 1: "failed", 2: "error"}

_AUDIT_FIELDS = ("kind", "version", "batch_sha256", "valid", "summary", "results")
_SUMMARY_FIELDS = ("total", "passed", "failed", "errors")
_RESULT_FIELDS = ("id", "command", "code", "outcome")


def classify_error(error: Exception) -> str:
    """Map a per-item failure to a stable ``error_kind`` label.

    The classification is purely by exception type and message, so the
    same failure always yields the same kind: placement/safety refusals
    (outside-tree paths, symbolic links) are ``unsafe``; a tree modified
    during the scan is ``changed``; read/stat/publish failures are
    ``io``; malformed user-supplied documents and arguments are
    ``input``; anything unexpected is ``internal``.
    """
    message = str(error)
    if "outside the delivery tree" in message or "symbolic links" in message:
        return ERROR_KIND_UNSAFE
    if "changed while scanning" in message:
        return ERROR_KIND_CHANGED
    if isinstance(error, OSError):
        return ERROR_KIND_IO
    if isinstance(error, ValueError):
        # SealError is a ValueError; inventory raises plain ValueError.
        if any(
            marker in message
            for marker in ("cannot read", "cannot stat", "cannot publish")
        ):
            return ERROR_KIND_IO
        return ERROR_KIND_INPUT
    return ERROR_KIND_INTERNAL


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def validate_audit_document(document: object) -> dict:
    """Strictly validate a parsed audit report JSON document.

    Returns the document when it is a well-formed version 1 release seal
    audit report: exactly the fields ``kind``/``version``/
    ``batch_sha256``/``valid``/``summary``/``results``, a consistent
    summary, and per-item entries whose ``outcome`` matches ``code`` and
    whose payload follows the code (``result`` for 0/1, non-empty
    ``error`` plus a known ``error_kind`` for 2). Raises
    :class:`SealError` on any mismatch; merely similar documents fail
    validation and stay deliverable.
    """
    if not isinstance(document, dict):
        raise SealError("audit report must be a JSON object")
    if set(document) != set(_AUDIT_FIELDS):
        raise SealError(
            f"audit report must contain exactly "
            f"{', '.join(sorted(_AUDIT_FIELDS))}"
        )
    if document["kind"] != AUDIT_KIND:
        raise SealError("not a release seal audit report")
    version = document["version"]
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != AUDIT_VERSION
    ):
        raise SealError(f"audit report field 'version' must be {AUDIT_VERSION}")
    if not is_key_id(document["batch_sha256"]):
        raise SealError(
            "audit report field 'batch_sha256' must be 64 lowercase hex digits"
        )
    if not isinstance(document["valid"], bool):
        raise SealError("audit report field 'valid' must be a boolean")
    summary = document["summary"]
    if not isinstance(summary, dict) or set(summary) != set(_SUMMARY_FIELDS):
        raise SealError(
            f"audit report 'summary' must contain exactly "
            f"{', '.join(sorted(_SUMMARY_FIELDS))}"
        )
    if any(not _is_count(summary[field]) for field in _SUMMARY_FIELDS):
        raise SealError("audit report 'summary' counts must be non-negative integers")
    results = document["results"]
    if not isinstance(results, list):
        raise SealError("audit report field 'results' must be an array")
    passed = failed = errors = 0
    for entry in results:
        if not isinstance(entry, dict):
            raise SealError("audit report entries must be objects")
        base = set(_RESULT_FIELDS)
        if not base <= set(entry):
            raise SealError(
                f"audit report entry must contain "
                f"{', '.join(sorted(base))}"
            )
        item_id = entry["id"]
        if not isinstance(item_id, str) or item_id == "":
            raise SealError("audit report entry 'id' must be a non-empty string")
        if entry["command"] not in ARITY:
            raise SealError("audit report entry holds an unknown command")
        code = entry["code"]
        if not isinstance(code, int) or isinstance(code, bool) or code not in (0, 1, 2):
            raise SealError("audit report entry 'code' must be 0, 1 or 2")
        if entry["outcome"] != _OUTCOME[code]:
            raise SealError("audit report entry 'outcome' does not match 'code'")
        extra = set(entry) - base
        if code == 2:
            if extra != {"error", "error_kind"}:
                raise SealError(
                    "audit report error entries must hold exactly "
                    "'error' and 'error_kind'"
                )
            if not isinstance(entry["error"], str) or entry["error"] == "":
                raise SealError("audit report entry 'error' must be non-empty")
            if entry["error_kind"] not in ERROR_KINDS:
                raise SealError("audit report entry holds an unknown 'error_kind'")
            errors += 1
        else:
            if extra != {"result"}:
                raise SealError(
                    "audit report entries with code 0 or 1 must hold only 'result'"
                )
            if not isinstance(entry["result"], dict):
                raise SealError("audit report entry 'result' must be an object")
            if code == 0:
                passed += 1
            else:
                failed += 1
    if summary["total"] != len(results):
        raise SealError("audit report 'summary' does not match 'results'")
    if (summary["passed"], summary["failed"], summary["errors"]) != (
        passed,
        failed,
        errors,
    ):
        raise SealError("audit report 'summary' does not match 'results'")
    if document["valid"] != (passed == len(results)):
        raise SealError("audit report 'valid' does not match 'summary'")
    return document


def audit_batch(batch_path, report_path) -> tuple[int, dict]:
    """Run a BATCH and publish an immutable audit report.

    The BATCH obeys the same rules as ``verify-batch``: structural
    problems raise :class:`SealError` (standard error, exit code 2, no
    report created) and a sound BATCH runs every item in input order.
    The REPORT path must sit outside every item's delivery tree and must
    not exist yet; it is published atomically and never overwritten.
    Returns ``(exit_code, report)`` where the exit code follows the
    batch result.
    """
    batch_path = Path(batch_path)
    report_path = Path(report_path)
    try:
        raw = batch_path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read batch {batch_path}: {error}") from error
    items = parse_batch(raw, batch_path)
    digest = hashlib.sha256(raw).hexdigest()
    base = batch_path.resolve().parent
    # The report is a support file: like keys, manifests and the BATCH
    # itself it must never land inside a delivery tree.
    for item in items:
        require_outside(base / item["args"][0], (report_path,))
    results: list[dict] = []
    passed = failed = errors = 0
    for item, code, result, error in execute_batch(items, base, batch_path):
        entry: dict = {
            "id": item["id"],
            "command": item["command"],
            "code": code,
            "outcome": _OUTCOME[code],
        }
        if error is not None:
            # Never record args, key material, signatures or tracebacks:
            # only the message text and a stable kind.
            entry["error"] = str(error) or type(error).__name__
            entry["error_kind"] = classify_error(error)
            errors += 1
        else:
            entry["result"] = result
            if code == 0:
                passed += 1
            else:
                failed += 1
        results.append(entry)
    total = len(items)
    report = {
        "kind": AUDIT_KIND,
        "version": AUDIT_VERSION,
        "batch_sha256": digest,
        "valid": passed == total,
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "errors": errors,
        },
        "results": results,
    }
    data = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    publish_new(report_path, data, hint="audit-report", what="audit report")
    return batch_exit_code(passed, failed, errors), report
