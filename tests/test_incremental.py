import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_public_key,
)

from release_seal.incremental import (
    sign_incremental_directory,
    validate_delta_document,
    verify_incremental,
)
from release_seal.seal import SealError, sign_directory, sign_multi_directory


def write_keypair(work: Path, name: str = "") -> tuple[Path, Path]:
    key = Ed25519PrivateKey.generate()
    private = work / f"{name}private.pem"
    private.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    public = work / f"{name}public.pem"
    public.write_bytes(
        key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    return private, public


def make_delivery(root: Path) -> Path:
    delivery = root / "delivery"
    (delivery / "docs").mkdir(parents=True)
    (delivery / "docs" / "readme.txt").write_bytes(b"hello")
    (delivery / "café.txt").write_bytes("café\n".encode("utf-8"))
    return delivery


def run_cli(*args) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "release_seal", *map(str, args)],
        capture_output=True, text=True,
    )


class IncrementalTestCase(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.work = Path(self.workspace.name)
        self.delivery = make_delivery(self.work)
        self.private, self.public = write_keypair(self.work)
        self.base = self.work / "base.json"
        sign_directory(self.delivery, self.private, self.base)
        self.delta = self.work / "delta.json"

    def mutate(self):
        """Add, modify and delete one file each, then sign the delta."""
        (self.delivery / "docs" / "readme.txt").write_bytes(b"hello v2")
        (self.delivery / "new.txt").write_bytes(b"brand new")
        (self.delivery / "café.txt").unlink()
        return sign_incremental_directory(
            self.delivery, self.private, self.base, self.delta
        )


class SignIncrementalTests(IncrementalTestCase):
    def test_delta_holds_exactly_the_eight_version_4_fields(self):
        document = self.mutate()
        self.assertEqual(
            set(document),
            {
                "version",
                "algorithm",
                "hash",
                "key_id",
                "base_sha256",
                "changes",
                "removed",
                "signature",
            },
        )
        self.assertEqual(document["version"], 4)
        self.assertEqual(document["algorithm"], "Ed25519")
        self.assertEqual(document["hash"], "SHA-256")
        on_disk = json.loads(self.delta.read_text(encoding="utf-8"))
        self.assertEqual(on_disk, document)

    def test_delta_records_only_changes_and_removals(self):
        document = self.mutate()
        self.assertEqual(
            [record["path"] for record in document["changes"]],
            ["docs/readme.txt", "new.txt"],
        )
        self.assertEqual(document["removed"], ["café.txt"])
        readme = document["changes"][0]
        self.assertEqual(readme["size"], len(b"hello v2"))
        self.assertEqual(
            readme["sha256"], hashlib.sha256(b"hello v2").hexdigest()
        )

    def test_base_sha256_covers_raw_base_bytes(self):
        document = self.mutate()
        self.assertEqual(
            document["base_sha256"],
            hashlib.sha256(self.base.read_bytes()).hexdigest(),
        )

    def test_empty_delta_is_legal(self):
        document = sign_incremental_directory(
            self.delivery, self.private, self.base, self.delta
        )
        self.assertEqual(document["changes"], [])
        self.assertEqual(document["removed"], [])
        self.assertEqual(verify_incremental(
            self.delivery, self.base, self.delta, self.public
        ), {"valid": True})

    def test_signature_covers_canonical_payload(self):
        document = self.mutate()
        payload = json.dumps(
            {key: document[key] for key in document if key != "signature"},
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        key = load_pem_public_key(self.public.read_bytes())
        key.verify(base64.b64decode(document["signature"]), payload)

    def test_sign_refuses_to_overwrite_delta(self):
        self.mutate()
        with self.assertRaises(SealError):
            sign_incremental_directory(
                self.delivery, self.private, self.base, self.delta
            )
        result = run_cli(
            "sign-incremental",
            self.delivery, self.private, self.base, self.delta,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("already exists", result.stderr)

    def test_sign_refuses_files_inside_delivery(self):
        cases = (
            (self.delivery / "private.pem", self.base, self.delta),
            (self.private, self.delivery / "base.json", self.delta),
            (self.private, self.base, self.delivery / "delta.json"),
        )
        for private, base, delta in cases:
            with self.subTest(private=private, base=base, delta=delta):
                with self.assertRaises(SealError):
                    sign_incremental_directory(
                        self.delivery, private, base, delta
                    )

    def test_sign_requires_a_version_2_base(self):
        multi = self.work / "multi.json"
        sign_multi_directory(self.delivery, multi, [self.private])
        with self.assertRaises(SealError):
            sign_incremental_directory(
                self.delivery, self.private, multi, self.delta
            )
        self.assertFalse(self.delta.exists())

    def test_sign_requires_base_signed_by_the_same_key(self):
        other_private, _ = write_keypair(self.work, "other-")
        with self.assertRaises(SealError):
            sign_incremental_directory(
                self.delivery, other_private, self.base, self.delta
            )
        self.assertFalse(self.delta.exists())

    def test_sign_rejects_tampered_base(self):
        document = json.loads(self.base.read_text(encoding="utf-8"))
        document["files"][0]["size"] += 1
        self.base.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SealError):
            sign_incremental_directory(
                self.delivery, self.private, self.base, self.delta
            )
        self.assertFalse(self.delta.exists())


class VerifyIncrementalTests(IncrementalTestCase):
    def test_verify_accepts_matching_directory(self):
        self.mutate()
        self.assertEqual(
            verify_incremental(self.delivery, self.base, self.delta, self.public),
            {"valid": True},
        )
        result = run_cli(
            "verify-incremental",
            self.delivery, self.base, self.delta, self.public,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {"valid": True})

    def test_verify_reports_sorted_differences(self):
        self.mutate()
        (self.delivery / "docs" / "readme.txt").write_bytes(b"hello v3")
        (self.delivery / "new.txt").unlink()
        (self.delivery / "extra.txt").write_bytes(b"extra")
        result = verify_incremental(
            self.delivery, self.base, self.delta, self.public
        )
        self.assertEqual(
            result,
            {
                "valid": False,
                "modified": ["docs/readme.txt"],
                "missing": ["new.txt"],
                "unexpected": ["extra.txt"],
            },
        )
        completed = run_cli(
            "verify-incremental",
            self.delivery, self.base, self.delta, self.public,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(json.loads(completed.stdout), result)

    def test_verify_rejects_wrong_public_key(self):
        self.mutate()
        _, other_public = write_keypair(self.work, "other-")
        self.assertEqual(
            verify_incremental(
                self.delivery, self.base, self.delta, other_public
            ),
            {"valid": False, "modified": [], "missing": [], "unexpected": []},
        )

    def test_verify_rejects_base_sha256_mismatch(self):
        self.mutate()
        other_base = self.work / "other-base.json"
        sign_directory(self.delivery, self.private, other_base)
        document = json.loads(self.delta.read_text(encoding="utf-8"))
        document["base_sha256"] = hashlib.sha256(
            other_base.read_bytes()
        ).hexdigest()
        # Re-sign so only the digest check can fail.
        from release_seal.incremental import canonical_delta_payload
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
        )

        key = load_pem_private_key(self.private.read_bytes(), password=None)
        payload = canonical_delta_payload(
            document["key_id"],
            document["base_sha256"],
            document["changes"],
            document["removed"],
        )
        document["signature"] = base64.b64encode(key.sign(payload)).decode("ascii")
        self.delta.write_text(json.dumps(document), encoding="utf-8")
        self.assertEqual(
            verify_incremental(self.delivery, self.base, self.delta, self.public),
            {"valid": False, "modified": [], "missing": [], "unexpected": []},
        )

    def test_verify_rejects_tampered_delta_signature(self):
        self.mutate()
        document = json.loads(self.delta.read_text(encoding="utf-8"))
        document["removed"] = []
        self.delta.write_text(json.dumps(document), encoding="utf-8")
        self.assertEqual(
            verify_incremental(self.delivery, self.base, self.delta, self.public),
            {"valid": False, "modified": [], "missing": [], "unexpected": []},
        )

    def test_verify_rejects_malformed_delta_with_status_2(self):
        self.mutate()
        document = json.loads(self.delta.read_text(encoding="utf-8"))
        cases = (
            {key: value for key, value in document.items() if key != "removed"},
            {**document, "removed": ["b.txt", "a.txt"]},
            {**document, "removed": ["a.txt", "a.txt"]},
            {**document, "removed": ["new.txt"]},
            {**document, "changes": list(reversed(document["changes"]))},
            {**document, "version": 5},
        )
        for broken in cases:
            with self.subTest(broken=broken):
                self.delta.write_text(json.dumps(broken), encoding="utf-8")
                with self.assertRaises(SealError):
                    verify_incremental(
                        self.delivery, self.base, self.delta, self.public
                    )
                result = run_cli(
                    "verify-incremental",
                    self.delivery, self.base, self.delta, self.public,
                )
                self.assertEqual(result.returncode, 2)

    def test_verify_rejects_files_inside_delivery(self):
        self.mutate()
        cases = (
            (self.delivery / "base.json", self.delta, self.public),
            (self.base, self.delivery / "delta.json", self.public),
            (self.base, self.delta, self.delivery / "public.pem"),
        )
        for base, delta, public in cases:
            with self.subTest(base=base, delta=delta, public=public):
                with self.assertRaises(SealError):
                    verify_incremental(self.delivery, base, delta, public)

    def test_valid_delta_inside_tree_is_refused(self):
        document = self.mutate()
        (self.delivery / "notes.json").write_text(
            json.dumps(document), encoding="utf-8"
        )
        result = run_cli(
            "verify-incremental",
            self.delivery, self.base, self.delta, self.public,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("delta manifests", result.stderr)

    def test_similar_but_invalid_delta_json_is_deliverable(self):
        document = self.mutate()
        almost = {**document, "version": 5}
        (self.delivery / "almost.json").write_text(
            json.dumps(almost), encoding="utf-8"
        )
        # The look-alike file is deliverable: re-sign over the tree that
        # now contains it and verification still succeeds.
        base2 = self.work / "base2.json"
        sign_directory(self.delivery, self.private, base2)
        delta2 = self.work / "delta2.json"
        sign_incremental_directory(self.delivery, self.private, base2, delta2)
        result = run_cli(
            "verify-incremental",
            self.delivery, base2, delta2, self.public,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"valid": True})


class ValidateDeltaDocumentTests(unittest.TestCase):
    def test_empty_delta_document_validates(self):
        document = {
            "version": 4,
            "algorithm": "Ed25519",
            "hash": "SHA-256",
            "key_id": "0" * 64,
            "base_sha256": "f" * 64,
            "changes": [],
            "removed": [],
            "signature": base64.b64encode(b"\0" * 64).decode("ascii"),
        }
        key_id, base_sha256, changes, removed, signature = (
            validate_delta_document(document)
        )
        self.assertEqual(key_id, "0" * 64)
        self.assertEqual(base_sha256, "f" * 64)
        self.assertEqual(changes, [])
        self.assertEqual(removed, [])
        self.assertEqual(signature, b"\0" * 64)

    def test_non_object_and_bad_signature_are_rejected(self):
        with self.assertRaises(SealError):
            validate_delta_document([])
        document = {
            "version": 4,
            "algorithm": "Ed25519",
            "hash": "SHA-256",
            "key_id": "0" * 64,
            "base_sha256": "f" * 64,
            "changes": [],
            "removed": [],
            "signature": base64.b64encode(b"\0" * 63).decode("ascii"),
        }
        with self.assertRaises(SealError):
            validate_delta_document(document)


if __name__ == "__main__":
    unittest.main()
