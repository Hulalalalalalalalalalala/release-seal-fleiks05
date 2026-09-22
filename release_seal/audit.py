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

``audit-chain`` publishes version 2 chain reports
(``release-seal-audit-chain``). Each report additionally carries
``sequence`` and ``previous_sha256``: the first report starts the chain
(``sequence`` 1, ``previous_sha256`` null); every later report links to
the previous chain report by its raw-byte SHA-256 and increments the
sequence. ``audit-chain-verify`` checks a run of chain reports and the
head digest they imply.
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
AUDIT_CHAIN_KIND = "release-seal-audit-chain"
AUDIT_CHAIN_VERSION = 2

REPORT_FIELDS = ("kind", "version", "batch_sha256", "valid", "summary", "results")
CHAIN_REPORT_FIELDS = (
    "kind",
    "version",
    "sequence",
    "previous_sha256",
    "batch_sha256",
    "valid",
    "summary",
    "results",
)
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


def _validate_report_envelope(
    document: object, kind: str, version: int, fields: tuple[str, ...]
) -> dict:
    if not isinstance(document, dict):
        raise SealError("audit report must be a JSON object")
    if set(document) != set(fields):
        raise SealError(
            "audit report must contain exactly " + ", ".join(fields)
        )
    if document["kind"] != kind:
        raise SealError("not a release seal audit report")
    value = document["version"]
    if not isinstance(value, int) or isinstance(value, bool) or value != version:
        raise SealError(f"audit report field 'version' must be {version}")
    return document


def _validate_report_contents(document: dict) -> None:
    """Validate every field shared by v1 reports and v2 chain reports."""
    if not is_key_id(document["batch_sha256"]):
        raise SealError(
            "audit report field 'batch_sha256' must be 64 lowercase hex digits"
        )
    if not isinstance(document["valid"], bool):
        raise SealError("audit report field 'valid' must be a boolean")
    summary = document["summary"]
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
    if document["valid"] != (summary["passed"] == summary["total"]):
        raise SealError("audit report field 'valid' contradicts its summary")
    results = document["results"]
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
    document = _validate_report_envelope(
        document, AUDIT_REPORT_KIND, AUDIT_REPORT_VERSION, REPORT_FIELDS
    )
    _validate_report_contents(document)
    return document


def validate_chain_report_document(document: object) -> dict:
    """Strictly validate a parsed version 2 chain report JSON document.

    Beyond the shared audit-report contents (``batch_sha256``,
    ``valid``/``summary`` consistency and per-item results), a chain
    report must hold a positive integer ``sequence`` and a
    ``previous_sha256`` that is either null or 64 lowercase hex digits;
    sequence 1 is exactly the null-link genesis report, so a null link is
    valid only there and every later sequence must name a predecessor.
    Raises :class:`SealError` on any mismatch.
    """
    document = _validate_report_envelope(
        document, AUDIT_CHAIN_KIND, AUDIT_CHAIN_VERSION, CHAIN_REPORT_FIELDS
    )
    sequence = document["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise SealError("audit chain report field 'sequence' must be a positive integer")
    previous = document["previous_sha256"]
    if previous is not None and not is_key_id(previous):
        raise SealError(
            "audit chain report field 'previous_sha256' must be null or "
            "64 lowercase hex digits"
        )
    if (sequence == 1) != (previous is None):
        if previous is None:
            raise SealError(
                "audit chain report with a null previous_sha256 must be sequence 1"
            )
        raise SealError(
            "audit chain report sequence 1 must have a null previous_sha256"
        )
    _validate_report_contents(document)
    return document


def _run_batch(
    batch_path: Path, report_path: Path
) -> tuple[int, dict, list[dict], bytes]:
    """Validate and run BATCH like ``verify-batch``, projecting audit entries.

    Returns ``(exit_code, summary, results, raw_batch_bytes)``. Structural
    BATCH problems raise :class:`SealError`; per-item failures never do,
    they land in the results as code-2 entries. ``report_path`` is checked
    against every delivery tree before any item runs.
    """
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
    return batch_exit_code(summary), summary, results, raw


def _encode_report(report: dict) -> bytes:
    return (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


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
    exit_code, summary, results, raw = _run_batch(batch_path, report_path)
    report = {
        "kind": AUDIT_REPORT_KIND,
        "version": AUDIT_REPORT_VERSION,
        "batch_sha256": hashlib.sha256(raw).hexdigest(),
        "valid": summary["passed"] == summary["total"],
        "summary": summary,
        "results": results,
    }
    publish_new(report_path, _encode_report(report), hint="audit-report", noun="audit report")
    return exit_code, report


def _load_chain_predecessor(previous_path: Path) -> tuple[int, str]:
    """Validate the predecessor chain report, returning (sequence, digest).

    The digest is the lowercase SHA-256 hex of the report file's raw
    bytes. Any read, encoding or structural problem raises
    :class:`SealError`, so a non-chain or merely similar JSON file can
    never extend the chain.
    """
    try:
        raw = previous_path.read_bytes()
    except OSError as error:
        raise SealError(
            f"cannot read previous chain report {previous_path}: {error}"
        ) from error
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SealError(
            f"previous chain report is not UTF-8 JSON: {previous_path}: {error}"
        ) from error
    try:
        validate_chain_report_document(document)
    except SealError as error:
        raise SealError(f"{error}: {previous_path}") from error
    return document["sequence"], hashlib.sha256(raw).hexdigest()


def audit_chain(batch_path, previous, report_path) -> tuple[int, dict]:
    """Run a BATCH and publish the next immutable audit-chain report.

    ``previous`` is ``"-"`` for the genesis report (``sequence`` 1 and a
    null ``previous_sha256``); otherwise it names a valid preceding chain
    report and the new report takes the next sequence and the raw-byte
    SHA-256 of that predecessor. A structural BATCH problem, an invalid or
    unreadable predecessor, a REPORT path inside a delivery tree, an
    existing REPORT or any publish failure raises :class:`SealError`
    (standard error, exit code 2) and leaves no report behind.
    """
    batch_path = Path(batch_path)
    report_path = Path(report_path)
    if previous == "-":
        sequence = 1
        previous_sha256 = None
    else:
        # Validate the link before running anything: a bad predecessor
        # must never spend a batch run or produce a report.
        sequence, previous_sha256 = _load_chain_predecessor(Path(previous))
        sequence += 1
    exit_code, summary, results, raw = _run_batch(batch_path, report_path)
    report = {
        "kind": AUDIT_CHAIN_KIND,
        "version": AUDIT_CHAIN_VERSION,
        "sequence": sequence,
        "previous_sha256": previous_sha256,
        "batch_sha256": hashlib.sha256(raw).hexdigest(),
        "valid": summary["passed"] == summary["total"],
        "summary": summary,
        "results": results,
    }
    publish_new(
        report_path,
        _encode_report(report),
        hint="audit-chain-report",
        noun="audit chain report",
    )
    return exit_code, report


def audit_chain_verify(expected_head, report_paths) -> tuple[int, dict]:
    """Verify chain reports in chain order against an expected head digest.

    Every REPORT is read and strictly validated as a version 2 chain
    report first, so any parameter, format or I/O problem raises
    :class:`SealError` (standard error, exit code 2). The validated
    reports are then checked for a genesis first report (sequence 1 with
    a null link), consecutive sequences and links, and finally for the
    last report's raw-byte digest matching ``expected_head``.

    Returns ``(0, {"valid": True, "count", "head_sha256"})`` on success or
    ``(1, {"valid": False, "reason": "broken_chain", "index"})`` at the
    first mismatch, where ``index`` is the zero-based position of the
    first report that does not link as required.
    """
    if not is_key_id(expected_head):
        raise SealError(
            "EXPECTED_HEAD must be 64 lowercase hex digits"
        )
    report_paths = [Path(value) for value in report_paths]
    if not report_paths:
        raise SealError("audit-chain-verify needs at least one REPORT")
    loaded: list[tuple[Path, bytes, dict]] = []
    for path in report_paths:
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise SealError(f"cannot read chain report {path}: {error}") from error
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SealError(
                f"chain report is not UTF-8 JSON: {path}: {error}"
            ) from error
        try:
            validate_chain_report_document(document)
        except SealError as error:
            raise SealError(f"{error}: {path}") from error
        loaded.append((path, raw, document))
    _, _, first = loaded[0]
    # The validator makes sequence 1 the only report allowed a null link,
    # so any other start simply does not begin the chain.
    if first["sequence"] != 1:
        return 1, {"valid": False, "reason": "broken_chain", "index": 0}
    previous_digest = None
    for index, (_, raw, document) in enumerate(loaded):
        if index > 0:
            _, _, predecessor = loaded[index - 1]
            if document["sequence"] != predecessor["sequence"] + 1:
                return 1, {
                    "valid": False,
                    "reason": "broken_chain",
                    "index": index,
                }
            if document["previous_sha256"] != previous_digest:
                return 1, {
                    "valid": False,
                    "reason": "broken_chain",
                    "index": index,
                }
        previous_digest = hashlib.sha256(raw).hexdigest()
    if previous_digest != expected_head:
        return 1, {
            "valid": False,
            "reason": "broken_chain",
            "index": len(loaded) - 1,
        }
    return 0, {
        "valid": True,
        "count": len(loaded),
        "head_sha256": previous_digest,
    }
