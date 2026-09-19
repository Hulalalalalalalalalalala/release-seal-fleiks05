"""Batch verification from a single BATCH file.

A BATCH is a UTF-8 JSON array; every item has exactly three fields:

* ``id`` — a unique, non-empty string naming the item in the report;
* ``command`` — one of ``verify``, ``verify-trusted`` or
  ``verify-policy``;
* ``args`` — an array of strings with the same length and meaning as the
  chosen command's positional arguments (3, 3 or 4).

Relative paths in ``args`` are resolved against the directory holding the
BATCH file; the BATCH file must sit outside every item's delivery tree,
and each item otherwise obeys the same restrictions as the corresponding
single command (support files outside the tree, ``O_NOFOLLOW`` reads and
before/after identity snapshots).

A malformed BATCH — bad structure, a duplicate id or a wrong argument
count — is a command-level failure: the reason goes to standard error,
the exit code is 2 and no summary is produced. A structurally sound
BATCH always runs every item, in input order; an item whose command
raises is reported with ``code`` 2 and a non-empty ``error`` instead of
writing to standard error.
"""

import json
from pathlib import Path

from .seal import SealError, require_outside

BATCH_VERSION = 1
ARITY = {
    "verify": 3,
    "verify-trusted": 3,
    "verify-policy": 4,
}
_ITEM_FIELDS = ("id", "command", "args")


def load_batch(path: Path) -> list[dict]:
    """Load and strictly validate a BATCH file.

    Returns the items as ``{"id", "command", "args"}`` dicts in input
    order. Raises :class:`SealError` for any structural problem: the file
    is not UTF-8 JSON, is not an array, an item is not an object with
    exactly ``id``/``command``/``args``, an id is empty or duplicated, a
    command is unknown, args are not strings or their count does not
    match the command.
    """
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
    items: list[dict] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(document):
        where = f"batch item {index}"
        if not isinstance(item, dict):
            raise SealError(f"{where}: each item must be a JSON object: {path}")
        if set(item) != set(_ITEM_FIELDS):
            raise SealError(
                f"{where}: item must contain exactly "
                f"{', '.join(_ITEM_FIELDS)}: {path}"
            )
        item_id = item["id"]
        command = item["command"]
        args = item["args"]
        if not isinstance(item_id, str) or item_id == "":
            raise SealError(
                f"{where}: 'id' must be a non-empty string: {path}"
            )
        if item_id in seen_ids:
            raise SealError(f"{where}: duplicate id {item_id!r}: {path}")
        seen_ids.add(item_id)
        if command not in ARITY:
            raise SealError(
                f"{where}: 'command' must be one of "
                f"{', '.join(sorted(ARITY))}: {path}"
            )
        if not isinstance(args, list) or any(
            not isinstance(value, str) for value in args
        ):
            raise SealError(
                f"{where}: 'args' must be an array of strings: {path}"
            )
        if len(args) != ARITY[command]:
            raise SealError(
                f"{where}: command {command!r} needs {ARITY[command]} "
                f"arguments, got {len(args)}: {path}"
            )
        items.append({"id": item_id, "command": command, "args": args})
    return items


def _run_item(command: str, args: list[Path]) -> dict:
    if command == "verify":
        from .seal import verify_directory

        return verify_directory(args[0], args[1], args[2])
    if command == "verify-trusted":
        from .trust import verify_trusted

        return verify_trusted(args[0], args[1], args[2])
    from .policy import verify_policy

    return verify_policy(args[0], args[1], args[2], args[3])


def verify_batch(batch_path) -> tuple[int, dict]:
    """Validate and execute a BATCH, returning ``(exit_code, report)``.

    Structural validation happens first and propagates as
    :class:`SealError` (standard error, exit code 2, no report). Once the
    BATCH is sound, every item runs in input order. An item whose result
    has ``valid: true`` gets ``code`` 0; ``valid: false`` gets code 1; any
    error raised while running it gets code 2 and a non-empty ``error``
    string and is never written to standard error. The report holds
    ``version``, ``valid`` (true only when every item returned 0), a
    ``summary`` of ``total``/``passed``/``failed``/``errors`` and the
    per-item ``results``. The exit code is 2 if any item errored,
    otherwise 1 if any item failed, otherwise 0.
    """
    batch_path = Path(batch_path)
    items = load_batch(batch_path)
    base = batch_path.resolve().parent
    results: list[dict] = []
    passed = failed = errors = 0
    for item in items:
        resolved = [base / value for value in item["args"]]
        entry: dict = {"id": item["id"]}
        try:
            # The BATCH file itself must not live inside a delivery tree;
            # each command additionally enforces its own outside-tree
            # rules, O_NOFOLLOW reads and snapshot protection.
            require_outside(resolved[0], (batch_path,))
            result = _run_item(item["command"], resolved)
            if result.get("valid") is True:
                entry["code"] = 0
                passed += 1
            else:
                entry["code"] = 1
                failed += 1
            entry["result"] = result
        except Exception as error:
            # Once the BATCH is structurally valid, any per-item failure is
            # a code-2 item result, never a command-level abort: the run
            # still reports every item and writes nothing to stderr.
            entry["code"] = 2
            entry["error"] = str(error) or type(error).__name__
            errors += 1
        results.append(entry)
    total = len(items)
    report = {
        "version": BATCH_VERSION,
        "valid": passed == total,
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "errors": errors,
        },
        "results": results,
    }
    if errors:
        exit_code = 2
    elif failed:
        exit_code = 1
    else:
        exit_code = 0
    return exit_code, report
