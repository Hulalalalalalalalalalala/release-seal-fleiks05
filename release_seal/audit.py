"""Offline audit reports for batch verification.

``audit-batch BATCH REPORT`` runs a BATCH exactly like ``verify-batch``
— same file format, relative-path base, input order, directory
restrictions and exit codes — and additionally publishes an immutable
audit report to REPORT. The report is a UTF-8 JSON object with exactly
six fields: ``kind`` (``"release-seal-audit-report"``), ``version``
(``1``), ``batch_sha256`` (the lowercase SHA-256 hex of the BATCH file's
raw bytes), ``valid`` and ``summary`` (same meaning as the batch report)
and ``results``. Results follow the input order; each entry holds
``id``, ``command``, ``code`` and ``outcome`` (``passed``/``failed``/
``error`` for codes 0/1/2). Codes 0/1 attach the command's original
``result``; code 2 attaches a non-empty ``error`` and a stable
``error_kind`` (one of ``input``, ``io``, ``unsafe``, ``changed``,
``internal``). Entries never record arguments, key material, signatures
or tracebacks.

REPORT must stay outside every item's delivery tree and is never
overwritten: the bytes land in a synced hidden temp file in the same
directory and are published with a single non-overwriting link, then the
directory is synced. A failure before publishing leaves no residue; if
the directory sync after publishing fails, the complete report stays in
place, the temp file is removed and the command exits 2 reporting that
durability is uncertain. On success the report is printed to standard
output and the exit code follows the batch result.
"""

import hashlib
import json
from pathlib import Path

from .batch import (
    ARITY,
    ERROR_KINDS,
    OUTCOMES,
    batch_exit_code,
    execute_items,
    parse_batch,
    summarize,
)
from .seal import SealError, is_key_id, publish_new, require_outside

AUDIT_REPORT_KIND = "release-seal-audit-report"
AUDIT_REPORT_VERSION = 1

REPORT_FIELDS = ("kind", "version", "batch_sha256", "valid", "summary", "results")
SUMMARY_FIELDS = ("total", "passed", "failed", "errors")
_ENTRY_BASE = ("id", "command", "code", "outcome")


def _validate_entry(entry: object) -> None:
    if not isinstance(entry, dict):
        raise SealError("audit report entries must be JSON objects")
    code = entry.get("code")
    if (
        not isinstance(code, int)
        or isinstance(code, bool)
        or code not in OUTCOMES
    ):
        raise SealError("audit report entry 'code' must be 0, 1 or 2")
    extra = {"result"} if code != 2 else {"error", "error_kind"}
    if set(entry) != set(_ENTRY_BASE) | extra:
        raise SealError(
            "audit report entry must contain exactly "
            + ", ".join(sorted(set(_ENTRY_BASE) | extra))
        )
    if not isinstance(entry["id"], str) or entry["id"] == "":
        raise SealError("audit report entry 'id' must be a non-empty string")
    if entry["command"] not in ARITY:
        raise SealError("audit report entry holds an unknown command")
    if entry["outcome"] != OUTCOMES[code]:
        raise SealError("audit report entry 'outcome' does not match its code")
    if code == 2:
        if not isinstance(entry["error"], str) or entry["error"] == "":
            raise SealError(
                "audit report entry 'error' must be a non-empty string"
            )
        if entry["error_kind"] not in ERROR_KINDS:
            raise SealError("audit report entry holds an unknown error_kind")
    elif not isinstance(entry["result"], dict):
        raise SealError("audit report entry 'result' must be an object")


def validate_summary(summary: object) -> None:
    """Strictly validate an audit ``summary`` object.

    Shared by the version 1 audit report and the version 2 audit chain
    report: exactly ``total``/``passed``/``failed``/``errors``, all
    non-negative integers that add up.
    """
    if not isinstance(summary, dict) or set(summary) != set(SUMMARY_FIELDS):
        raise SealError(
            "audit report 'summary' must contain exactly "
            + ", ".join(SUMMARY_FIELDS)
        )
    for field in SUMMARY_FIELDS:
        value = summary[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise SealError(
                f"audit report summary field {field!r} must be a "
                "non-negative integer"
            )
    if (
        summary["passed"] + summary["failed"] + summary["errors"]
        != summary["total"]
    ):
        raise SealError("audit report summary counts do not add up")


def validate_results(results: object, summary: dict) -> None:
    """Strictly validate audit ``results`` against their ``summary``."""
    if not isinstance(results, list) or len(results) != summary["total"]:
        raise SealError("audit report 'results' must match summary 'total'")
    tallies = {0: 0, 1: 0, 2: 0}
    for entry in results:
        _validate_entry(entry)
        tallies[entry["code"]] += 1
    if (
        tallies[0] != summary["passed"]
        or tallies[1] != summary["failed"]
        or tallies[2] != summary["errors"]
    ):
        raise SealError("audit report summary does not match its results")


def validate_audit_report_document(document: object) -> dict:
    """Strictly validate a parsed audit report JSON document.

    Only a complete, self-consistent version 1 audit report passes:
    exactly the six report fields, a well-formed summary whose counts
    match the per-item results, and entries whose ``outcome`` and extra
    fields match their ``code``. Raises :class:`SealError` on any
    mismatch; a merely similar document does not validate.
    """
    if not isinstance(document, dict):
        raise SealError("audit report must be a JSON object")
    if set(document) != set(REPORT_FIELDS):
        raise SealError(
            "audit report must contain exactly " + ", ".join(REPORT_FIELDS)
        )
    if document["kind"] != AUDIT_REPORT_KIND:
        raise SealError("not a release seal audit report")
    version = document["version"]
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != AUDIT_REPORT_VERSION
    ):
        raise SealError(
            f"audit report field 'version' must be {AUDIT_REPORT_VERSION}"
        )
    if not is_key_id(document["batch_sha256"]):
        raise SealError(
            "audit report field 'batch_sha256' must be 64 lowercase hex digits"
        )
    if not isinstance(document["valid"], bool):
        raise SealError("audit report field 'valid' must be a boolean")
    validate_summary(document["summary"])
    if document["valid"] != (
        document["summary"]["passed"] == document["summary"]["total"]
    ):
        raise SealError("audit report field 'valid' contradicts its summary")
    validate_results(document["results"], document["summary"])
    return document


def audit_results(entries: list[dict]) -> list[dict]:
    """Project executed batch entries into audit report result entries.

    Each entry keeps ``id``, ``command``, ``code`` and ``outcome``; codes
    0/1 attach the command's original ``result``, code 2 a non-empty
    ``error`` and a stable ``error_kind``. Shared by the version 1 audit
    report and the version 2 audit chain report.
    """
    results: list[dict] = []
    for entry in entries:
        audited: dict = {
            "id": entry["id"],
            "command": entry["command"],
            "code": entry["code"],
            "outcome": OUTCOMES[entry["code"]],
        }
        if entry["code"] == 2:
            audited["error"] = entry["error"]
            audited["error_kind"] = entry["error_kind"]
        else:
            audited["result"] = entry["result"]
        results.append(audited)
    return results


def audit_batch(batch_path, report_path) -> tuple[int, dict]:
    """Run a BATCH and publish an immutable audit report of the run.

    Returns ``(exit_code, report)`` with the same exit code
    ``verify-batch`` would produce. Structural BATCH problems, a REPORT
    path inside a delivery tree, an existing REPORT or any publish
    failure raise :class:`SealError` (standard error, exit code 2) and
    leave no report behind.
    """
    batch_path = Path(batch_path)
    report_path = Path(report_path)
    try:
        raw = batch_path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read batch {batch_path}: {error}") from error
    items = parse_batch(raw, batch_path)
    base = batch_path.resolve().parent
    # The report must stay outside every delivery tree, exactly like the
    # BATCH file itself; check before running anything so a misplaced
    # REPORT never produces a run.
    for item in items:
        require_outside(base / item["args"][0], (report_path,))
    entries = execute_items(items, base, batch_path)
    summary = summarize(entries)
    report = {
        "kind": AUDIT_REPORT_KIND,
        "version": AUDIT_REPORT_VERSION,
        "batch_sha256": hashlib.sha256(raw).hexdigest(),
        "valid": summary["passed"] == summary["total"],
        "summary": summary,
        "results": audit_results(entries),
    }
    data = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    publish_new(report_path, data, hint="audit-report", noun="audit report")
    return batch_exit_code(summary), report
