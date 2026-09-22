"""Hash-chained audit reports for batch verification.

``audit-chain BATCH PREVIOUS REPORT`` runs a BATCH exactly like
``audit-batch`` — same file format, relative-path base, input order,
directory restrictions and exit codes — and additionally publishes an
immutable chain report to REPORT. PREVIOUS is either ``-`` to start a
new chain, or the path of an existing chain report this one builds on.
A malformed BATCH, an unreadable or invalid PREVIOUS or any I/O failure
is a command-level failure: the reason goes to standard error, the exit
code is 2 and no report is created.

The report is a UTF-8 JSON object with exactly eight fields: ``kind``
(``"release-seal-audit-chain"``), ``version`` (``2``), ``sequence``,
``previous_sha256``, ``batch_sha256``, ``valid``, ``summary`` and
``results``. A chain start has ``sequence`` 1 and ``previous_sha256``
``null``; a successor increments the previous report's sequence and
records the lowercase SHA-256 hex of the previous report file's raw
bytes. The remaining fields follow the version 1 audit report
semantics; an empty batch is legal and the report never records
arguments, key material, signatures or tracebacks.

``audit-chain-verify EXPECTED_HEAD REPORT...`` takes one or more
reports in chain order and checks the start (sequence 1, null previous
digest), consecutive sequences, the hash links and that the last
report's raw bytes hash to EXPECTED_HEAD. Success prints
``valid: true`` with ``count`` and ``head_sha256`` and exits 0; the
first mismatch prints ``valid: false`` with ``reason: "broken_chain"``
and the offending ``index`` and exits 1; argument, format or I/O
problems go to standard error with exit code 2.

REPORT (and PREVIOUS, when given) must stay outside every item's
delivery tree and REPORT is never overwritten: the bytes land in a
synced hidden temp file in the same directory and are published with a
single non-overwriting link, then the directory is synced — the same
durability semantics as ``audit-batch``. Valid chain reports are
recognized by content and forbidden inside a delivery tree; merely
similar JSON stays deliverable.
"""

import hashlib
import json
from pathlib import Path

from .audit import audit_results, validate_results, validate_summary
from .batch import batch_exit_code, execute_items, parse_batch, summarize
from .seal import SealError, is_key_id, publish_new, require_outside

CHAIN_REPORT_KIND = "release-seal-audit-chain"
CHAIN_REPORT_VERSION = 2

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


def validate_chain_report_document(document: object) -> dict:
    """Strictly validate a parsed audit chain report JSON document.

    Only a complete, self-consistent version 2 chain report passes:
    exactly the eight report fields, a positive ``sequence`` whose
    ``previous_sha256`` is ``null`` exactly on the chain start
    (sequence 1) and a digest everywhere else, and the version 1 audit
    semantics for ``batch_sha256``, ``valid``, ``summary`` and
    ``results``. Raises :class:`SealError` on any mismatch; a merely
    similar document does not validate.
    """
    if not isinstance(document, dict):
        raise SealError("audit chain report must be a JSON object")
    if set(document) != set(CHAIN_REPORT_FIELDS):
        raise SealError(
            "audit chain report must contain exactly "
            + ", ".join(CHAIN_REPORT_FIELDS)
        )
    if document["kind"] != CHAIN_REPORT_KIND:
        raise SealError("not a release seal audit chain report")
    version = document["version"]
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != CHAIN_REPORT_VERSION
    ):
        raise SealError(
            f"audit chain report field 'version' must be {CHAIN_REPORT_VERSION}"
        )
    sequence = document["sequence"]
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 1
    ):
        raise SealError(
            "audit chain report field 'sequence' must be a positive integer"
        )
    previous = document["previous_sha256"]
    if sequence == 1:
        if previous is not None:
            raise SealError(
                "audit chain report field 'previous_sha256' must be null "
                "on the chain start"
            )
    elif not is_key_id(previous):
        raise SealError(
            "audit chain report field 'previous_sha256' must be 64 "
            "lowercase hex digits"
        )
    if not is_key_id(document["batch_sha256"]):
        raise SealError(
            "audit chain report field 'batch_sha256' must be 64 lowercase "
            "hex digits"
        )
    if not isinstance(document["valid"], bool):
        raise SealError("audit chain report field 'valid' must be a boolean")
    validate_summary(document["summary"])
    if document["valid"] != (
        document["summary"]["passed"] == document["summary"]["total"]
    ):
        raise SealError(
            "audit chain report field 'valid' contradicts its summary"
        )
    validate_results(document["results"], document["summary"])
    return document


def _load_chain_report(path: Path) -> tuple[bytes, dict]:
    """Read a chain report file, returning its raw bytes and document."""
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SealError(
            f"cannot read audit chain report {path}: {error}"
        ) from error
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SealError(
            f"audit chain report is not UTF-8 JSON: {path}: {error}"
        ) from error
    try:
        return raw, validate_chain_report_document(document)
    except SealError as error:
        raise SealError(f"{error}: {path}") from error


def audit_chain(batch_path, previous, report_path) -> tuple[int, dict]:
    """Run a BATCH and publish an immutable hash-chained audit report.

    ``previous`` is ``-`` to start a new chain (sequence 1, null
    previous digest) or the path of a valid chain report to build on
    (sequence incremented, previous digest over its raw bytes). Returns
    ``(exit_code, report)`` with the same exit code ``verify-batch``
    would produce. Structural BATCH problems, an unreadable or invalid
    PREVIOUS, a REPORT or PREVIOUS path inside a delivery tree, an
    existing REPORT or any publish failure raise :class:`SealError`
    (standard error, exit code 2) and leave no report behind.
    """
    batch_path = Path(batch_path)
    report_path = Path(report_path)
    try:
        raw = batch_path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read batch {batch_path}: {error}") from error
    items = parse_batch(raw, batch_path)
    previous_path: Path | None = None
    if str(previous) == "-":
        sequence = 1
        previous_sha256 = None
    else:
        previous_path = Path(previous)
        previous_raw, previous_document = _load_chain_report(previous_path)
        sequence = previous_document["sequence"] + 1
        previous_sha256 = hashlib.sha256(previous_raw).hexdigest()
    base = batch_path.resolve().parent
    # The report and its predecessor must stay outside every delivery
    # tree, exactly like the BATCH file itself; check before running
    # anything so misplaced files never produce a run.
    outside = (report_path,) if previous_path is None else (report_path, previous_path)
    for item in items:
        require_outside(base / item["args"][0], outside)
    entries = execute_items(items, base, batch_path)
    summary = summarize(entries)
    report = {
        "kind": CHAIN_REPORT_KIND,
        "version": CHAIN_REPORT_VERSION,
        "sequence": sequence,
        "previous_sha256": previous_sha256,
        "batch_sha256": hashlib.sha256(raw).hexdigest(),
        "valid": summary["passed"] == summary["total"],
        "summary": summary,
        "results": audit_results(entries),
    }
    data = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    publish_new(report_path, data, hint="audit-chain", noun="audit chain report")
    return batch_exit_code(summary), report


def verify_chain(expected_head, report_paths) -> tuple[int, dict]:
    """Verify a chain of audit reports against an expected head digest.

    The reports must be non-empty and given in chain order: the first
    must be a chain start (sequence 1, null previous digest), every
    successor must increment the sequence and record the SHA-256 of the
    previous report file's raw bytes, and the last report's raw bytes
    must hash to ``expected_head``. Returns ``(0, {"valid": True,
    "count", "head_sha256"})`` on success and ``(1, {"valid": False,
    "reason": "broken_chain", "index"})`` for the first link that does
    not fit. Argument, format and I/O problems raise :class:`SealError`
    (standard error, exit code 2).
    """
    if not is_key_id(expected_head):
        raise SealError(
            "expected head must be 64 lowercase hex digits: "
            f"{expected_head!r}"
        )
    paths = [Path(path) for path in report_paths]
    if not paths:
        raise SealError("audit-chain-verify needs at least one report")
    previous_document: dict | None = None
    previous_raw = b""
    last_raw = b""
    for index, path in enumerate(paths):
        raw, document = _load_chain_report(path)
        if previous_document is None:
            broken = document["sequence"] != 1
        else:
            broken = (
                document["sequence"] != previous_document["sequence"] + 1
                or document["previous_sha256"]
                != hashlib.sha256(previous_raw).hexdigest()
            )
        if broken:
            return 1, {
                "valid": False,
                "reason": "broken_chain",
                "index": index,
            }
        previous_document = document
        previous_raw = raw
        last_raw = raw
    if hashlib.sha256(last_raw).hexdigest() != expected_head:
        return 1, {
            "valid": False,
            "reason": "broken_chain",
            "index": len(paths) - 1,
        }
    return 0, {
        "valid": True,
        "count": len(paths),
        "head_sha256": expected_head,
    }
