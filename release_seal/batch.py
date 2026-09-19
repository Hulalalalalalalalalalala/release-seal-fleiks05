"""Batch verification of several deliveries from one JSON file.

``verify-batch BATCH`` reads a UTF-8 JSON array whose items each name
one of the verification commands (``verify``, ``verify-trusted`` or
``verify-policy``) together with its arguments, runs every item in
input order and prints one aggregated report. Relative paths inside an
item resolve against the batch file's directory, and the batch file
itself must stay outside every delivery tree it mentions. A malformed
batch (bad structure, duplicate ids, wrong argument counts) is a
status-2 error reported on stderr with no summary; per-item failures
are captured in the report instead.
"""

import json
from pathlib import Path

from .policy import verify_policy
from .seal import SealError, verify_directory
from .trust import verify_trusted

BATCH_VERSION = 1

_COMMANDS = {
    "verify": (verify_directory, 3),
    "verify-trusted": (verify_trusted, 3),
    "verify-policy": (verify_policy, 4),
}

_ITEM_FIELDS = ("id", "command", "args")


def _load_batch(path: Path) -> list:
    """Read and strictly validate the batch description."""
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read batch {path}: {error}") from error
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SealError(f"batch is not UTF-8 JSON: {path}: {error}") from error
    if not isinstance(document, list):
        raise SealError(f"batch must be a JSON array: {path}")
    seen: set[str] = set()
    for index, item in enumerate(document):
        where = f"batch item {index}"
        if not isinstance(item, dict) or set(item) != set(_ITEM_FIELDS):
            raise SealError(
                f"{where} must contain exactly "
                f"{', '.join(sorted(_ITEM_FIELDS))}: {path}"
            )
        item_id = item["id"]
        if not isinstance(item_id, str) or item_id == "":
            raise SealError(f"{where} 'id' must be a non-empty string: {path}")
        if item_id in seen:
            raise SealError(f"duplicate batch id {item_id!r}: {path}")
        seen.add(item_id)
        command = item["command"]
        if command not in _COMMANDS:
            raise SealError(
                f"{where} 'command' must be one of "
                f"{', '.join(sorted(_COMMANDS))}: {path}"
            )
        args = item["args"]
        expected = _COMMANDS[command][1]
        if (
            not isinstance(args, list)
            or len(args) != expected
            or any(not isinstance(arg, str) for arg in args)
        ):
            raise SealError(
                f"{where} 'args' must be an array of {expected} strings "
                f"for {command!r}: {path}"
            )
    return document


def verify_batch(batch) -> tuple[dict, int]:
    """Run every check in batch in order; return (report, exit code).

    The report holds ``version``, ``valid`` (true only when every item
    passed), a ``summary`` counting items by exit code and one entry
    per item: ``id`` and ``code`` always, the command's original result
    for codes 0/1 and a non-empty ``error`` message for code 2. Item
    errors are captured in the report, never written to stderr.
    """
    batch = Path(batch)
    items = _load_batch(batch)
    base = batch.resolve().parent
    batch_resolved = batch.resolve()
    results: list[dict] = []
    counts = {0: 0, 1: 0, 2: 0}
    for item in items:
        function, _ = _COMMANDS[item["command"]]
        args = [base / arg for arg in item["args"]]
        try:
            if batch_resolved.is_relative_to(args[0].resolve()):
                raise SealError(
                    f"the batch file must stay outside the delivery tree: "
                    f"{batch}"
                )
            outcome = function(*args)
        except (OSError, ValueError) as error:
            code = 2
            message = str(error) or type(error).__name__
            results.append({"id": item["id"], "code": code, "error": message})
        else:
            code = 0 if outcome["valid"] else 1
            results.append({"id": item["id"], "code": code, "result": outcome})
        counts[code] += 1
    report = {
        "version": BATCH_VERSION,
        "valid": counts[1] == 0 and counts[2] == 0,
        "summary": {
            "total": len(items),
            "passed": counts[0],
            "failed": counts[1],
            "errors": counts[2],
        },
        "results": results,
    }
    code = 2 if counts[2] else (1 if counts[1] else 0)
    return report, code
