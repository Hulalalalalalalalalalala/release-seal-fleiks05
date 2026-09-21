"""Sign and verify a directory inventory with Ed25519.

Manifests exist in four versions:

* version 1 holds ``version``, ``algorithm``, ``hash``, ``files`` and
  ``signature``;
* version 2 adds ``key_id``, the lowercase SHA-256 hex of the signer's
  DER SubjectPublicKeyInfo;
* version 3 replaces ``signature`` with ``signatures``, an object keyed
  by signer ``key_id`` holding one Base64 signature per key;
* version 4 is an incremental manifest (a *delta*): it holds
  ``version``, ``algorithm``, ``hash``, ``key_id``, ``base_sha256``,
  ``changes``, ``removed`` and ``signature``, where ``changes`` lists
  added/modified inventory records relative to a version 2 base and
  ``removed`` lists deleted paths.

The signature covers every field except ``signature`` (versions 1, 2
and 4) or ``signatures`` (version 3), serialized with keys sorted, no
whitespace and no Unicode escaping. ``verify`` accepts versions 1 and
2; ``sign`` always emits version 2. Version 3 manifests are produced by
``sign-multi`` and checked by ``verify-policy``. Version 4 deltas are
produced by ``sign-incremental`` and checked by
``verify-incremental``.
"""

import base64
import binascii
import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from .inventory import inventory, stat_snapshot

VERSION = 1
VERSION_CURRENT = 2
VERSION_MULTI = 3
VERSION_INCREMENTAL = 4
SUPPORTED_VERSIONS = (1, 2)
BASE_VERSIONS = (VERSION_CURRENT,)
ALL_MANIFEST_VERSIONS = (1, 2, 3)
MULTI_VERSIONS = (VERSION_MULTI,)
ALGORITHM = "Ed25519"
HASH = "SHA-256"
TRUST_STORE_KIND = "release-seal-trust-store"
V1_FIELDS = ("version", "algorithm", "hash", "files", "signature")
V2_FIELDS = ("version", "algorithm", "hash", "key_id", "files", "signature")
V3_FIELDS = ("version", "algorithm", "hash", "files", "signatures")
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
POLICY_FIELDS = ("version", "threshold", "allowed_key_ids")

_PUBLIC_PEM_MARKERS = (b"-----BEGIN PUBLIC KEY-----", b"-----END PUBLIC KEY-----")
_PRIVATE_PEM_MARKERS = (b"-----BEGIN PRIVATE KEY-----", b"-----END PRIVATE KEY-----")


class SealError(ValueError):
    """A user-facing failure: print the message and exit with status 2."""


def key_id_of(key: Ed25519PublicKey) -> str:
    """Return the lowercase SHA-256 hex of a public key's DER SPKI."""
    der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def is_key_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def canonical_payload(version: int, key_id: str | None, files: list[dict]) -> bytes:
    """Return the canonical UTF-8 JSON the signature covers.

    The signed body holds every manifest field except ``signature``
    (versions 1 and 2) or ``signatures`` (version 3) — ``key_id`` is
    included on version 2 only — with keys sorted, no whitespace and
    no Unicode escaping.
    """
    body: dict = {
        "version": version,
        "algorithm": ALGORITHM,
        "hash": HASH,
        "files": files,
    }
    if version == 2:
        body["key_id"] = key_id
    return json.dumps(
        body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def canonical_delta_payload(
    key_id: str,
    base_sha256: str,
    changes: list[dict],
    removed: list[str],
) -> bytes:
    """Return the canonical UTF-8 JSON a version 4 signature covers.

    The body holds every delta field except ``signature`` —
    ``version``, ``algorithm``, ``hash``, ``key_id``, ``base_sha256``,
    ``changes`` and ``removed`` — serialized with the same rules as the
    version 2 body: keys sorted, no whitespace and no Unicode escaping.
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


def _is_sorted_strings(values: list[str]) -> bool:
    return all(values[index] < values[index + 1] for index in range(len(values) - 1))


def validate_delta_document(document: object):
    """Strictly validate a parsed version 4 delta document.

    Returns ``(key_id, base_sha256, changes, removed, signature)`` with
    the signature Base64-decoded. The document must hold exactly the
    eight version 4 fields; ``changes`` must be inventory records sorted
    by unique path and ``removed`` sorted, unique and disjoint from
    ``changes``. Raises :class:`SealError` on any mismatch.
    """
    if not isinstance(document, dict):
        raise SealError("delta manifest must be a JSON object")
    if set(document) != set(V4_FIELDS):
        raise SealError(
            "delta manifest must contain exactly "
            + ", ".join(sorted(V4_FIELDS))
        )
    version = document["version"]
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != VERSION_INCREMENTAL
    ):
        raise SealError(
            f"delta manifest field 'version' must be {VERSION_INCREMENTAL}"
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
    if len(set(change_paths)) != len(change_paths):
        raise SealError("delta manifest lists duplicate change paths")
    if not _is_sorted_strings(change_paths):
        raise SealError("delta manifest field 'changes' must be sorted by path")
    removed = document["removed"]
    if not isinstance(removed, list) or any(
        not isinstance(path, str) or path == "" for path in removed
    ):
        raise SealError(
            "delta manifest field 'removed' must be a list of non-empty strings"
        )
    if len(set(removed)) != len(removed):
        raise SealError("delta manifest lists duplicate removed paths")
    if not _is_sorted_strings(removed):
        raise SealError("delta manifest field 'removed' must be sorted")
    if set(change_paths) & set(removed):
        raise SealError(
            "delta manifest 'removed' paths must not overlap 'changes'"
        )
    signature = _decode_signature_obj(document["signature"], field="'signature'")
    return key_id, base_sha256, changes, removed, signature


def _read_json_bytes(path: Path, *, noun: str) -> tuple[bytes, object]:
    """Read path and parse it as UTF-8 JSON, labelling errors with noun."""
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read {noun} {path}: {error}") from error
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SealError(f"{noun} is not UTF-8 JSON: {path}: {error}") from error
    return raw, document


def load_base_manifest(path: Path):
    """Return ``(raw, files, signature, key_id)`` for a version 2 base.

    The raw bytes are returned so callers can hash them for
    ``base_sha256``; only version 2 manifests are accepted as a base.
    """
    raw, document = _read_json_bytes(path, noun="base manifest")
    try:
        version, files, signature, key_id = validate_manifest_document(
            document, BASE_VERSIONS
        )
    except SealError as error:
        raise SealError(f"{error}: {path}") from error
    return raw, files, signature, key_id


def load_delta_manifest(path: Path):
    """Return the validated tuple from :func:`validate_delta_document`."""
    _, document = _read_json_bytes(path, noun="delta manifest")
    try:
        return validate_delta_document(document)
    except SealError as error:
        raise SealError(f"{error}: {path}") from error


def apply_delta(base_files: list[dict], changes: list[dict], removed: list[str]):
    """Apply a delta to base records, returning the expected full inventory.

    ``changes`` replace or add records by path; ``removed`` drops paths.
    The result is sorted by path, exactly like :func:`inventory`.
    """
    merged = {record["path"]: record for record in base_files}
    for path in removed:
        merged.pop(path, None)
    for record in changes:
        merged[record["path"]] = record
    return sorted(merged.values(), key=lambda record: str(record["path"]))


def require_outside(directory: Path, paths: tuple[Path, ...]) -> None:
    root = directory.resolve()
    for path in paths:
        if path.resolve().is_relative_to(root):
            raise SealError(
                f"keys, manifests, trust stores, policies, batch files and "
                f"audit reports must stay outside the delivery tree: {path}"
            )


def load_private_key(path: Path) -> Ed25519PrivateKey:
    # The key is only read into memory for signing; it is never printed,
    # copied into the manifest or written anywhere else.
    try:
        data = path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read private key {path}: {error}") from error
    if not all(marker in data for marker in _PRIVATE_PEM_MARKERS):
        raise SealError(f"expected a PEM Ed25519 private key: {path}")
    try:
        key = load_pem_private_key(data, password=None)
    except Exception as error:
        raise SealError(f"cannot load PEM private key {path}: {error}") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise SealError(f"expected an Ed25519 private key: {path}")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read public key {path}: {error}") from error
    return decode_public_key(data, where=str(path))


def decode_public_key(data: bytes, *, where: str) -> Ed25519PublicKey:
    """Strictly decode a PEM Ed25519 SubjectPublicKeyInfo blob."""
    if not all(marker in data for marker in _PUBLIC_PEM_MARKERS):
        raise SealError(f"expected a PEM Ed25519 public key: {where}")
    try:
        key = load_pem_public_key(data)
    except Exception as error:
        raise SealError(f"cannot load PEM public key {where}: {error}") from error
    if not isinstance(key, Ed25519PublicKey):
        raise SealError(f"expected an Ed25519 public key: {where}")
    return key


def valid_record(record: object) -> bool:
    if not isinstance(record, dict):
        return False
    fields = set(record)
    if fields != {"path", "size", "sha256"}:
        return False
    size = record["size"]
    digest = record["sha256"]
    return (
        isinstance(record["path"], str)
        and record["path"] != ""
        and isinstance(size, int)
        and not isinstance(size, bool)
        and size >= 0
        and isinstance(digest, str)
        and len(digest) == 64
        and all(char in "0123456789abcdef" for char in digest)
    )


_MANIFEST_FIELDS = {1: V1_FIELDS, 2: V2_FIELDS, 3: V3_FIELDS}


def validate_manifest_document(document: object, versions: tuple = SUPPORTED_VERSIONS):
    """Validate a parsed manifest JSON document.

    Returns ``(version, files, signatures, key_id)`` exactly like
    :func:`load_manifest`: for versions 1 and 2 ``signatures`` is the
    single decoded signature and ``key_id`` the manifest's key id (``None``
    on version 1); for version 3 ``signatures`` maps signer key id to
    decoded signature and ``key_id`` is ``None``. Only the given
    ``versions`` are accepted. Raises :class:`SealError` on any mismatch.
    """
    if not isinstance(document, dict):
        raise SealError("manifest must be a JSON object")
    version = document.get("version")
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version not in versions
    ):
        supported = " or ".join(str(value) for value in versions)
        raise SealError(f"manifest field 'version' must be {supported}")
    expected = set(_MANIFEST_FIELDS[version])
    if set(document) != expected:
        raise SealError(
            f"manifest version {version} must contain exactly "
            f"{', '.join(sorted(expected))}"
        )
    if document["algorithm"] != ALGORITHM:
        raise SealError(f"manifest field 'algorithm' must be {ALGORITHM!r}")
    if document["hash"] != HASH:
        raise SealError(f"manifest field 'hash' must be {HASH!r}")
    key_id = None
    if version == 2:
        key_id = document["key_id"]
        if not is_key_id(key_id):
            raise SealError(
                "manifest field 'key_id' must be 64 lowercase hex digits"
            )
    files = document["files"]
    if not isinstance(files, list) or any(not valid_record(r) for r in files):
        raise SealError("manifest field 'files' holds invalid records")
    paths = [record["path"] for record in files]
    if len(set(paths)) != len(paths):
        raise SealError("manifest lists duplicate paths")
    if version == VERSION_MULTI:
        signatures = document["signatures"]
        if not isinstance(signatures, dict) or not signatures:
            raise SealError(
                "manifest field 'signatures' must be a non-empty object"
            )
        decoded_multi = {}
        for signer_id, signature in signatures.items():
            if not is_key_id(signer_id):
                raise SealError("manifest 'signatures' holds an invalid key id")
            decoded_multi[signer_id] = _decode_signature_obj(
                signature, field="'signatures'"
            )
        return version, files, decoded_multi, None
    decoded = _decode_signature_obj(document["signature"], field="'signature'")
    return version, files, decoded, key_id


def _decode_signature_obj(value: object, *, field: str) -> bytes:
    if not isinstance(value, str):
        raise SealError(f"manifest field {field} must be Base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise SealError("manifest signature is not Base64") from error
    if len(decoded) != 64:
        raise SealError("manifest signature must be 64 bytes")
    return decoded


def load_manifest(path: Path, versions: tuple = SUPPORTED_VERSIONS):
    """Return (version, files, signatures, key_id) from a manifest file.

    For versions 1 and 2 ``signatures`` is the single decoded signature
    and ``key_id`` the manifest's key id (``None`` on version 1). For
    version 3 ``signatures`` is a dict mapping signer key id to decoded
    signature and ``key_id`` is ``None``. Only the given ``versions``
    are accepted.
    """
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SealError(f"cannot read manifest {path}: {error}") from error
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SealError(f"manifest is not UTF-8 JSON: {path}: {error}") from error
    try:
        return validate_manifest_document(document, versions)
    except SealError as error:
        raise SealError(f"{error}: {path}") from error


def diff_inventory(expected: list[dict], actual: list[dict]) -> tuple[list, list, list]:
    expected_by_path = {record["path"]: record for record in expected}
    actual_by_path = {record["path"]: record for record in actual}
    common = expected_by_path.keys() & actual_by_path.keys()
    modified = sorted(
        path
        for path in common
        if (expected_by_path[path]["size"], expected_by_path[path]["sha256"])
        != (actual_by_path[path]["size"], actual_by_path[path]["sha256"])
    )
    missing = sorted(expected_by_path.keys() - actual_by_path.keys())
    unexpected = sorted(actual_by_path.keys() - expected_by_path.keys())
    return modified, missing, unexpected


def _looks_like_pem_key(data: bytes) -> bool:
    """Whether ``data`` is a real PEM key that must stay out of the tree.

    Probing is purely by content and independent of the file name. The
    bytes are tried, in order, with :func:`load_pem_public_key` and then
    :func:`load_pem_private_key` with ``password=None``:

    * a successful load of either kind, for any algorithm (Ed25519, RSA,
      EC, ...), marks a real key;
    * the explicit ``TypeError`` reporting that an encrypted private key
      needs a password marks a real (encrypted) key;
    * every other failure (certificates and other non-key PEM, malformed
      armor, DER, OpenSSH, PKCS#12, plain text) means the file is not a
      PEM key and stays deliverable.
    """
    try:
        load_pem_public_key(data)
    except Exception:
        pass
    else:
        return True
    try:
        load_pem_private_key(data, password=None)
    except TypeError as error:
        # The only TypeError expected with password=None is the explicit
        # "Password was not given but private key is encrypted": treat
        # only that clear encrypted-key report as a forbidden key.
        if "encrypted" in str(error).lower() and "password" in str(error).lower():
            return True
        return False
    except Exception:
        return False
    return True


def _forbidden_json_document(document: object) -> str | None:
    """Rejection message for a parsed JSON object, or ``None`` if deliverable.

    Only a document that *fully* validates as a version 1/2/3 manifest, a
    version 4 delta manifest, a version 1 trust store, a three-field
    version 1 policy or a version 1 audit report is forbidden. A merely
    similar object (right field names but invalid values, a foreign
    ``kind`` or ``version``) passes. Imports live here to avoid an import
    cycle: ``trust``, ``policy`` and ``audit`` import from this module.
    """
    if not isinstance(document, dict):
        return None
    try:
        validate_manifest_document(document, ALL_MANIFEST_VERSIONS)
    except SealError:
        pass
    else:
        return "manifests must stay outside the delivery tree"
    try:
        validate_delta_document(document)
    except SealError:
        pass
    else:
        return "delta manifests must stay outside the delivery tree"
    from .trust import validate_store_document

    try:
        validate_store_document(document)
    except SealError:
        pass
    else:
        return "trust stores must stay outside the delivery tree"
    from .policy import validate_policy_document

    try:
        validate_policy_document(document)
    except SealError:
        pass
    else:
        return "policies must stay outside the delivery tree"
    from .audit import validate_audit_report_document

    try:
        validate_audit_report_document(document)
    except SealError:
        return None
    return "audit reports must stay outside the delivery tree"


_PEM_MARKER = b"-----BEGIN"
_JSON_WHITESPACE = b" \t\r\n"


def _scan_forbidden_kind(path: Path) -> tuple[str, bytes] | None:
    """Stream a file once to see whether it may hold PEM or JSON content.

    Returns ``("pem", data)`` when a ``-----BEGIN`` marker appears
    anywhere, ``("json", data)`` when the first non-whitespace byte opens
    a JSON object, and ``None`` for an ordinary file. The full bytes are
    buffered only for the two interesting kinds, so a large plain binary
    is scanned with constant memory rather than read whole. Reads never
    follow a swapped-in symlink (``O_NOFOLLOW``).
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise SealError(f"cannot read {path}: {error}") from error
    first_non_ws: int | None = None
    marker_seen = False
    overlap = b""
    with os.fdopen(fd, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            if first_non_ws is None:
                for byte in chunk:
                    if byte not in _JSON_WHITESPACE:
                        first_non_ws = byte
                        break
            window = overlap + chunk
            if _PEM_MARKER in window:
                marker_seen = True
            overlap = window[-len(_PEM_MARKER) + 1:]
        if marker_seen:
            source.seek(0)
            return "pem", source.read()
        # Every forbidden JSON document (manifest/store/policy) is an
        # object, so a non-object start is never worth buffering.
        if first_non_ws == ord("{"):
            source.seek(0)
            return "json", source.read()
    return None


def reject_forbidden_files(directory: Path, files: list[dict]) -> None:
    """Reject keys, manifests, stores, policies or audit reports in the tree.

    Detection is by content, not by name or extension. A file is refused
    when its bytes load as a PEM key of any algorithm (or clearly are an
    encrypted PEM private key missing its password), or when they parse as
    UTF-8 JSON fully validating as a version 1/2/3 manifest, a version 4
    delta manifest, a version 1 trust store, a three-field version 1
    policy or a version 1 audit report. Certificates, ordinary PEM,
    DER/OpenSSH/PKCS#12 blobs and malformed-but-similar JSON are all
    deliverable, whatever the file is called.
    """
    for record in files:
        rel = record["path"]
        path = directory / rel
        kind = _scan_forbidden_kind(path)
        if kind is None:
            continue
        flavor, data = kind
        if flavor == "pem" and _looks_like_pem_key(data):
            raise SealError(f"keys must stay outside the delivery tree: {path}")
        try:
            document = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        message = _forbidden_json_document(document)
        if message is not None:
            raise SealError(f"{message}: {path}")


def guarded_inventory(directory: Path) -> list[dict]:
    """Inventory directory, proving it did not change during the scan.

    Identity snapshots taken before and after cover paths, file types,
    ``(dev, ino)`` identity, sizes and nanosecond mtimes. Every content
    read (hashing and forbidden-file classification) happens between the
    two snapshots, so a swapped or modified file is always caught. The
    tree is also refused if it contains keys, manifests, trust stores,
    policies or audit reports.
    """
    before = stat_snapshot(directory)
    files = inventory(directory)
    reject_forbidden_files(directory, files)
    after = stat_snapshot(directory)
    if before != after:
        raise SealError(f"directory changed while scanning: {directory}")
    return files


def _sync_directory(directory: Path) -> None:
    """fsync a directory; tolerate filesystems that reject it (EINVAL)."""
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    except OSError as error:
        if error.errno != errno.EINVAL:
            raise
    finally:
        os.close(fd)


def _staged_temp(parent: Path, hint: str, data: bytes) -> Path:
    """Write data to a synced hidden temp file in parent; fsync it."""
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{hint}.", suffix=".tmp", dir=parent
    )
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp


def publish_new(target: Path, data: bytes, *, hint: str = "manifest", noun: str = "manifest") -> None:
    """Publish data once, never overwriting an existing target.

    The bytes land in a synced temp file in target's directory and are
    published with a single non-overwriting hard link. An existing
    target is left byte-for-byte untouched; on failure no temp file or
    half-written target remains. If the directory sync after publishing
    fails, the complete new target stays in place, the temp file is
    removed and the error reports that durability is uncertain. ``noun``
    names the artifact in error messages.
    """
    parent = target.parent
    tmp = _staged_temp(parent, hint, data)
    published = False
    try:
        try:
            os.link(tmp, target)
        except FileExistsError as error:
            raise SealError(f"{noun} already exists: {target}") from error
        except OSError as error:
            raise SealError(f"cannot publish {noun} {target}: {error}") from error
        published = True
        try:
            _sync_directory(parent)
        except OSError as error:
            raise SealError(
                f"{noun} published but directory sync failed; durability "
                f"is uncertain: {target}: {error}"
            ) from error
    finally:
        if not published:
            tmp.unlink(missing_ok=True)
        else:
            # The hard link keeps the inode alive under target.
            tmp.unlink(missing_ok=True)


def publish_replace(target: Path, data: bytes, *, hint: str) -> None:
    """Atomically replace target with synced data; clean up on failure.

    A failure before the replace leaves the old content untouched. If
    the directory sync after the replace fails, the complete new target
    stays in place, the temp file is removed and the error reports that
    durability is uncertain.
    """
    parent = target.parent
    tmp = _staged_temp(parent, hint, data)
    replaced = False
    try:
        try:
            os.replace(tmp, target)
        except OSError as error:
            raise SealError(f"cannot publish {target}: {error}") from error
        replaced = True
        try:
            _sync_directory(parent)
        except OSError as error:
            raise SealError(
                f"{target} published but directory sync failed; durability "
                f"is uncertain: {error}"
            ) from error
    finally:
        if not replaced:
            tmp.unlink(missing_ok=True)
        else:
            tmp.unlink(missing_ok=True)


def sign_directory(directory, private_key, manifest) -> dict:
    """Sign the inventory of directory and atomically create manifest."""
    directory = Path(directory)
    private_key = Path(private_key)
    manifest = Path(manifest)
    require_outside(directory, (private_key, manifest))
    key = load_private_key(private_key)
    public = key.public_key()
    key_id = key_id_of(public)
    files = guarded_inventory(directory)
    document = {
        "version": VERSION_CURRENT,
        "algorithm": ALGORITHM,
        "hash": HASH,
        "key_id": key_id,
        "files": files,
        "signature": base64.b64encode(
            key.sign(canonical_payload(VERSION_CURRENT, key_id, files))
        ).decode("ascii"),
    }
    data = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    publish_new(manifest, data)
    return document


def sign_multi_directory(directory, manifest, private_keys) -> dict:
    """Sign the inventory of directory with several Ed25519 keys.

    Emits a version 3 manifest whose ``signatures`` object maps each
    signer's key id (sorted) to its Base64 signature; every key signs
    the full canonical manifest excluding ``signatures``. The key list
    must be non-empty and hold distinct Ed25519 keys; private keys are
    only read, never copied anywhere. The manifest is published without
    overwriting, exactly like ``sign``.
    """
    directory = Path(directory)
    manifest = Path(manifest)
    privates = [Path(private) for private in private_keys]
    if not privates:
        raise SealError("sign-multi needs at least one private key")
    require_outside(directory, (manifest, *privates))
    keys = [load_private_key(private) for private in privates]
    key_ids: list[str] = []
    for key in keys:
        key_id = key_id_of(key.public_key())
        if key_id in key_ids:
            raise SealError(f"duplicate signing key: {key_id}")
        key_ids.append(key_id)
    files = guarded_inventory(directory)
    payload = canonical_payload(VERSION_MULTI, None, files)
    signatures = {
        key_id: base64.b64encode(key.sign(payload)).decode("ascii")
        for key_id, key in sorted(zip(key_ids, keys))
    }
    document = {
        "version": VERSION_MULTI,
        "algorithm": ALGORITHM,
        "hash": HASH,
        "files": files,
        "signatures": signatures,
    }
    data = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    publish_new(manifest, data)
    return document


def verify_directory(directory, manifest, public_key) -> dict:
    """Verify a signed manifest against directory using only public_key.

    Accepts manifest versions 1 and 2. The result keeps the original
    shape: ``{"valid": true}`` or ``valid: false`` with sorted
    ``modified`` / ``missing`` / ``unexpected`` lists.
    """
    directory = Path(directory)
    manifest = Path(manifest)
    public_key = Path(public_key)
    require_outside(directory, (manifest, public_key))
    key = load_public_key(public_key)
    version, files, signature, key_id = load_manifest(manifest)
    if version == 2 and key_id != key_id_of(key):
        return {"valid": False, "modified": [], "missing": [], "unexpected": []}
    try:
        key.verify(signature, canonical_payload(version, key_id, files))
    except InvalidSignature:
        return {"valid": False, "modified": [], "missing": [], "unexpected": []}
    modified, missing, unexpected = diff_inventory(
        files, guarded_inventory(directory)
    )
    if modified or missing or unexpected:
        return {
            "valid": False,
            "modified": modified,
            "missing": missing,
            "unexpected": unexpected,
        }
    return {"valid": True}


def _empty_invalid() -> dict:
    return {"valid": False, "modified": [], "missing": [], "unexpected": []}


def sign_incremental_directory(directory, private_key, base, delta) -> dict:
    """Sign the inventory changes of directory relative to a version 2 base.

    Emits a version 4 delta listing records added or modified since BASE
    (``changes``, sorted by path) and paths present in BASE but missing
    from the directory (``removed``, sorted and unique); an empty delta
    is legal. ``base_sha256`` is the lowercase SHA-256 hex of BASE's raw
    bytes. BASE must be a version 2 manifest whose signature verifies
    under the given private key. The delta is published without
    overwriting, exactly like ``sign``.
    """
    directory = Path(directory)
    private_key = Path(private_key)
    base = Path(base)
    delta = Path(delta)
    require_outside(directory, (private_key, base, delta))
    key = load_private_key(private_key)
    public = key.public_key()
    signer_id = key_id_of(public)
    base_raw, base_files, base_signature, base_key_id = load_base_manifest(base)
    if base_key_id != signer_id:
        raise SealError(
            f"base manifest key_id {base_key_id} does not match the "
            f"given private key {signer_id}: {base}"
        )
    try:
        public.verify(
            base_signature, canonical_payload(VERSION_CURRENT, base_key_id, base_files)
        )
    except InvalidSignature as error:
        raise SealError(f"base manifest signature is invalid: {base}") from error
    base_sha256 = hashlib.sha256(base_raw).hexdigest()
    current = guarded_inventory(directory)
    base_by_path = {record["path"]: record for record in base_files}
    current_paths = {record["path"] for record in current}
    changes = [
        record for record in current if base_by_path.get(record["path"]) != record
    ]
    removed = sorted(base_by_path.keys() - current_paths)
    signature = base64.b64encode(
        key.sign(canonical_delta_payload(signer_id, base_sha256, changes, removed))
    ).decode("ascii")
    document = {
        "version": VERSION_INCREMENTAL,
        "algorithm": ALGORITHM,
        "hash": HASH,
        "key_id": signer_id,
        "base_sha256": base_sha256,
        "changes": changes,
        "removed": removed,
        "signature": signature,
    }
    data = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    publish_new(delta, data, hint="delta-manifest", noun="delta manifest")
    return document


def verify_incremental_directory(directory, base, delta, public_key) -> dict:
    """Verify a version 4 delta against BASE and directory using one key.

    Only the PEM Ed25519 public key on the command line is trusted.
    BASE's and DELTA's structure, key ids, the ``base_sha256`` digest and
    both signatures are checked first; only then is the directory
    inventoried and compared against BASE with the delta applied. Any
    trust or file mismatch returns ``valid: false`` (exit 1); malformed
    inputs or I/O/scan problems raise :class:`SealError` (exit 2).
    """
    directory = Path(directory)
    base = Path(base)
    delta = Path(delta)
    public_key = Path(public_key)
    require_outside(directory, (base, delta, public_key))
    key = load_public_key(public_key)
    trusted_id = key_id_of(key)
    base_raw, base_files, base_signature, base_key_id = load_base_manifest(base)
    (
        delta_key_id,
        base_sha256,
        changes,
        removed,
        delta_signature,
    ) = load_delta_manifest(delta)
    if base_sha256 != hashlib.sha256(base_raw).hexdigest():
        return _empty_invalid()
    if base_key_id != trusted_id:
        return _empty_invalid()
    try:
        key.verify(
            base_signature, canonical_payload(VERSION_CURRENT, base_key_id, base_files)
        )
    except InvalidSignature:
        return _empty_invalid()
    if delta_key_id != trusted_id:
        return _empty_invalid()
    try:
        key.verify(
            delta_signature,
            canonical_delta_payload(
                delta_key_id, base_sha256, changes, removed
            ),
        )
    except InvalidSignature:
        return _empty_invalid()
    expected = apply_delta(base_files, changes, removed)
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
