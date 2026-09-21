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
    load_pem_private_key,
    load_pem_public_key,
)

from release_seal.inventory import inventory
from release_seal.seal import (
    SealError,
    canonical_delta_payload,
    sign_directory,
    sign_incremental_directory,
    validate_delta_document,
    verify_directory,
    verify_incremental_directory,
)


def write_keypair(work: Path) -> tuple[Path, Path]:
    key = Ed25519PrivateKey.generate()
    private = work / "private.pem"
    private.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    public = work / "public.pem"
    public.write_bytes(
        key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    return private, public


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
        self.delivery = self.work / "delivery"
        (self.delivery / "docs").mkdir(parents=True)
        (self.delivery / "docs" / "readme.txt").write_bytes(b"hello")
        (self.delivery / "café.txt").write_bytes("café\n".encode("utf-8"))
        (self.delivery / "removed-later.txt").write_bytes(b"bye")
        self.private, self.public = write_keypair(self.work)
        self.base = self.work / "base.json"
        sign_directory(self.delivery, self.private, self.base)
        self.delta = self.work / "delta.json"

    def sign_delta(self):
        return sign_incremental_directory(
            self.delivery, self.private, self.base, self.delta
        )

    def verify_delta(self, *, public=None, base=None, delta=None):
        return verify_incremental_directory(
            self.delivery,
            base or self.base,
            delta or self.delta,
            public or self.public,
        )


class SignIncrementalTests(IncrementalTestCase):
    def evolve(self):
        """Add, modify and remove relative to the base."""
        (self.delivery / "new.txt").write_bytes(b"brand new")
        (self.delivery / "docs" / "readme.txt").write_bytes(b"hello changed")
        (self.delivery / "removed-later.txt").unlink()

    def test_empty_delta_when_directory_matches_base(self):
        document = self.sign_delta()
        self.assertEqual(document["version"], 4)
        self.assertEqual(document["algorithm"], "Ed25519")
        self.assertEqual(document["hash"], "SHA-256")
        self.assertEqual(document["changes"], [])
        self.assertEqual(document["removed"], [])
        self.assertEqual(
            document["base_sha256"],
            hashlib.sha256(self.base.read_bytes()).hexdigest(),
        )
        on_disk = json.loads(self.delta.read_text(encoding="utf-8"))
        self.assertEqual(on_disk, document)

    def test_delta_has_exactly_eight_fields(self):
        self.evolve()
        document = self.sign_delta()
        self.assertEqual(
            set(document),
            {
                "version", "algorithm", "hash", "key_id", "base_sha256",
                "changes", "removed", "signature",
            },
        )

    def test_changes_and_removed_are_computed(self):
        self.evolve()
        document = self.sign_delta()
        self.assertEqual(
            [record["path"] for record in document["changes"]],
            ["docs/readme.txt", "new.txt"],
        )
        self.assertEqual(document["removed"], ["removed-later.txt"])
        new_record = next(
            r for r in document["changes"] if r["path"] == "new.txt"
        )
        self.assertEqual(new_record["size"], len(b"brand new"))
        self.assertEqual(
            new_record["sha256"],
            hashlib.sha256(b"brand new").hexdigest(),
        )

    def test_signature_covers_canonical_delta_payload(self):
        self.evolve()
        (self.delivery / "café.txt").write_bytes("café changed\n".encode("utf-8"))
        document = self.sign_delta()
        payload = canonical_delta_payload(
            document["key_id"],
            document["base_sha256"],
            document["changes"],
            document["removed"],
        )
        self.assertIn("café".encode("utf-8"), payload)
        key = load_pem_public_key(self.public.read_bytes())
        key.verify(base64.b64decode(document["signature"]), payload)

    def test_key_id_matches_private_key(self):
        document = self.sign_delta()
        der = load_pem_public_key(self.public.read_bytes()).public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        self.assertEqual(document["key_id"], hashlib.sha256(der).hexdigest())

    def test_base_must_be_version_2(self):
        # A version 1 manifest with the same content is not an acceptable base.
        files = inventory(self.delivery)
        private_key = load_pem_private_key(
            self.private.read_bytes(), password=None
        )
        payload = json.dumps(
            {
                "version": 1,
                "algorithm": "Ed25519",
                "hash": "SHA-256",
                "files": files,
            },
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        v1 = {
            "version": 1,
            "algorithm": "Ed25519",
            "hash": "SHA-256",
            "files": files,
            "signature": base64.b64encode(
                private_key.sign(payload)
            ).decode("ascii"),
        }
        v1_path = self.work / "v1.json"
        v1_path.write_text(json.dumps(v1), encoding="utf-8")
        with self.assertRaises(SealError):
            sign_incremental_directory(
                self.delivery, self.private, v1_path, self.delta
            )

    def test_base_key_id_must_match_private_key(self):
        other = self.work / "other"
        other.mkdir()
        other_private, _ = write_keypair(other)
        with self.assertRaises(SealError) as caught:
            sign_incremental_directory(
                self.delivery, other_private, self.base, self.delta
            )
        self.assertIn("key_id", str(caught.exception))
        self.assertFalse(self.delta.exists())

    def test_tampered_base_signature_is_rejected(self):
        document = json.loads(self.base.read_text(encoding="utf-8"))
        signature = bytearray(base64.b64decode(document["signature"]))
        signature[0] ^= 1
        document["signature"] = base64.b64encode(bytes(signature)).decode()
        self.base.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SealError):
            self.sign_delta()

    def test_delta_is_never_overwritten(self):
        self.sign_delta()
        original = self.delta.read_bytes()
        with self.assertRaises(SealError):
            self.sign_delta()
        self.assertEqual(self.delta.read_bytes(), original)

    def test_refuses_support_files_inside_tree(self):
        cases = (
            (self.delivery / "private.pem", self.base, self.delta),
            (self.private, self.delivery / "base.json", self.delta),
            (self.private, self.base, self.delivery / "delta.json"),
        )
        for key_path, base_path, delta_path in cases:
            with self.subTest(key=key_path, base=base_path, delta=delta_path):
                with self.assertRaises(SealError):
                    sign_incremental_directory(
                        self.delivery, key_path, base_path, delta_path
                    )


class VerifyIncrementalTests(IncrementalTestCase):
    def test_empty_delta_verifies(self):
        self.sign_delta()
        self.assertEqual(self.verify_delta(), {"valid": True})
        result = run_cli(
            "verify-incremental", self.delivery, self.base, self.delta,
            self.public,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"valid": True})

    def test_add_modify_remove_verifies(self):
        (self.delivery / "new.txt").write_bytes(b"brand new")
        (self.delivery / "docs" / "readme.txt").write_bytes(b"hello changed")
        (self.delivery / "removed-later.txt").unlink()
        self.sign_delta()
        self.assertEqual(self.verify_delta(), {"valid": True})

    def test_expected_full_inventory_matches_plain_verify(self):
        # The applied delta must describe exactly what a fresh full
        # manifest of the evolved directory would.
        (self.delivery / "new.txt").write_bytes(b"brand new")
        (self.delivery / "removed-later.txt").unlink()
        self.sign_delta()
        full = self.work / "full.json"
        sign_directory(self.delivery, self.private, full)
        self.assertEqual(self.verify_delta(), {"valid": True})
        # Plain verify of the freshly signed full manifest agrees.
        self.assertEqual(
            verify_directory(self.delivery, full, self.public), {"valid": True}
        )

    def test_unexpected_file_is_reported(self):
        self.sign_delta()
        (self.delivery / "extra.txt").write_bytes(b"extra")
        self.assertEqual(self.verify_delta(), {
            "valid": False,
            "modified": [],
            "missing": [],
            "unexpected": ["extra.txt"],
        })

    def test_modified_file_is_reported(self):
        self.sign_delta()
        (self.delivery / "café.txt").write_bytes(b"different")
        self.assertEqual(self.verify_delta(), {
            "valid": False,
            "modified": ["café.txt"],
            "missing": [],
            "unexpected": [],
        })

    def test_missing_file_is_reported(self):
        self.sign_delta()
        (self.delivery / "café.txt").unlink()
        self.assertEqual(self.verify_delta(), {
            "valid": False,
            "modified": [],
            "missing": ["café.txt"],
            "unexpected": [],
        })

    def test_changed_but_not_rescanned_file_is_unexpected(self):
        # A change that is part of the delta must match the directory; if
        # the recorded change differs from what is on disk it is modified.
        (self.delivery / "new.txt").write_bytes(b"brand new")
        self.sign_delta()
        (self.delivery / "new.txt").write_bytes(b"tampered")
        self.assertEqual(self.verify_delta(), {
            "valid": False,
            "modified": ["new.txt"],
            "missing": [],
            "unexpected": [],
        })

    def test_wrong_public_key_is_invalid(self):
        self.sign_delta()
        other = self.work / "other"
        other.mkdir()
        _, other_public = write_keypair(other)
        self.assertEqual(self.verify_delta(public=other_public), {
            "valid": False, "modified": [], "missing": [], "unexpected": [],
        })
        result = run_cli(
            "verify-incremental", self.delivery, self.base, self.delta,
            other_public,
        )
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)["valid"])

    def test_base_bytes_changed_after_signing_is_invalid(self):
        self.sign_delta()
        document = json.loads(self.base.read_text(encoding="utf-8"))
        # Re-serialize the same document with different whitespace: the
        # base_sha256 in the delta no longer matches the raw bytes.
        self.base.write_text(
            json.dumps(document, separators=(",", ":")), encoding="utf-8"
        )
        self.assertEqual(self.verify_delta(), {
            "valid": False, "modified": [], "missing": [], "unexpected": [],
        })

    def test_delta_signed_by_other_key_is_invalid(self):
        self.sign_delta()
        other = self.work / "other"
        other.mkdir()
        other_private, other_public = write_keypair(other)
        # Build a delta whose key_id/signature come from the other key but
        # whose base_sha256 is honest: trust check must reject it.
        other_private_key = load_pem_private_key(
            other_private.read_bytes(), password=None
        )
        other_id = hashlib.sha256(
            load_pem_public_key(other_public.read_bytes()).public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
        ).hexdigest()
        document = json.loads(self.delta.read_text(encoding="utf-8"))
        document["key_id"] = other_id
        payload = canonical_delta_payload(
            other_id, document["base_sha256"],
            document["changes"], document["removed"],
        )
        document["signature"] = base64.b64encode(
            other_private_key.sign(payload)
        ).decode("ascii")
        foreign = self.work / "foreign-delta.json"
        foreign.write_text(json.dumps(document), encoding="utf-8")
        self.assertEqual(self.verify_delta(delta=foreign), {
            "valid": False, "modified": [], "missing": [], "unexpected": [],
        })

    def test_tampered_delta_signature_is_invalid(self):
        self.sign_delta()
        document = json.loads(self.delta.read_text(encoding="utf-8"))
        signature = bytearray(base64.b64decode(document["signature"]))
        signature[0] ^= 1
        document["signature"] = base64.b64encode(bytes(signature)).decode()
        self.delta.write_text(json.dumps(document), encoding="utf-8")
        self.assertEqual(self.verify_delta(), {
            "valid": False, "modified": [], "missing": [], "unexpected": [],
        })

    def test_tampered_delta_body_is_invalid(self):
        self.sign_delta()
        document = json.loads(self.delta.read_text(encoding="utf-8"))
        document["removed"] = ["café.txt"]
        self.delta.write_text(json.dumps(document), encoding="utf-8")
        # The signature no longer covers the body: invalid, exit 1.
        result = run_cli(
            "verify-incremental", self.delivery, self.base, self.delta,
            self.public,
        )
        self.assertEqual(result.returncode, 1)

    def test_malformed_delta_is_format_error(self):
        self.sign_delta()
        self.delta.write_bytes(b"not json")
        with self.assertRaises(SealError):
            self.verify_delta()
        result = run_cli(
            "verify-incremental", self.delivery, self.base, self.delta,
            self.public,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")

    def test_malformed_base_is_format_error(self):
        self.sign_delta()
        self.base.write_bytes(b"not json")
        with self.assertRaises(SealError):
            self.verify_delta()

    def test_base_wrong_version_is_format_error(self):
        self.sign_delta()
        document = json.loads(self.base.read_text(encoding="utf-8"))
        document["version"] = 3
        self.base.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SealError):
            self.verify_delta()

    def test_unparseable_public_key_is_format_error(self):
        self.sign_delta()
        self.public.write_bytes(b"not a pem")
        result = run_cli(
            "verify-incremental", self.delivery, self.base, self.delta,
            self.public,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")

    def test_missing_input_file_is_format_error(self):
        self.sign_delta()
        result = run_cli(
            "verify-incremental", self.delivery, self.base,
            self.work / "absent.json", self.public,
        )
        self.assertEqual(result.returncode, 2)

    def test_refuses_support_files_inside_tree(self):
        self.sign_delta()
        with self.assertRaises(SealError):
            verify_incremental_directory(
                self.delivery, self.delivery / "base.json",
                self.delta, self.public,
            )
        with self.assertRaises(SealError):
            verify_incremental_directory(
                self.delivery, self.base,
                self.delivery / "delta.json", self.public,
            )
        with self.assertRaises(SealError):
            verify_incremental_directory(
                self.delivery, self.base,
                self.delta, self.delivery / "public.pem",
            )


class DeltaDocumentValidationTests(unittest.TestCase):
    def _document(self, **overrides):
        document = {
            "version": 4,
            "algorithm": "Ed25519",
            "hash": "SHA-256",
            "key_id": "a" * 64,
            "base_sha256": "b" * 64,
            "changes": [],
            "removed": [],
            "signature": base64.b64encode(b"\x00" * 64).decode("ascii"),
        }
        document.update(overrides)
        return document

    def test_empty_changes_and_removed_are_valid(self):
        key_id, base_sha256, changes, removed, signature = (
            validate_delta_document(self._document())
        )
        self.assertEqual(key_id, "a" * 64)
        self.assertEqual(base_sha256, "b" * 64)
        self.assertEqual(changes, [])
        self.assertEqual(removed, [])
        self.assertEqual(len(signature), 64)

    def assert_invalid(self, document):
        with self.assertRaises(SealError):
            validate_delta_document(document)

    def test_wrong_field_set(self):
        document = self._document()
        del document["removed"]
        self.assert_invalid(document)
        document = self._document(extra=1)
        self.assert_invalid(document)

    def test_wrong_version_algorithm_hash(self):
        self.assert_invalid(self._document(version=3))
        self.assert_invalid(self._document(algorithm="RSA"))
        self.assert_invalid(self._document(hash="SHA-512"))

    def test_bad_key_id_and_base_sha256(self):
        self.assert_invalid(self._document(key_id="z" * 64))
        self.assert_invalid(self._document(key_id="a" * 63))
        self.assert_invalid(self._document(base_sha256="B" * 64))

    def test_changes_must_be_sorted_unique_records(self):
        record = lambda path: {  # noqa: E731
            "path": path, "size": 1,
            "sha256": "c" * 64,
        }
        self.assert_invalid(self._document(changes=[record("b"), record("a")]))
        self.assert_invalid(self._document(changes=[record("a"), record("a")]))
        bad = {"path": "a", "size": -1, "sha256": "c" * 64}
        self.assert_invalid(self._document(changes=[bad]))

    def test_removed_must_be_sorted_unique_strings(self):
        self.assert_invalid(self._document(removed=["b", "a"]))
        self.assert_invalid(self._document(removed=["a", "a"]))
        self.assert_invalid(self._document(removed=[""]))
        self.assert_invalid(self._document(removed=[1]))

    def test_removed_must_not_overlap_changes(self):
        record = {"path": "a", "size": 1, "sha256": "c" * 64}
        self.assert_invalid(self._document(changes=[record], removed=["a"]))

    def test_signature_must_be_64_base64_bytes(self):
        self.assert_invalid(
            self._document(signature=base64.b64encode(b"short").decode())
        )
        self.assert_invalid(self._document(signature=1234))


class ForbiddenDeltaContentTests(IncrementalTestCase):
    """A valid v4 delta is forbidden in-tree; look-alikes are deliverable."""

    def test_valid_delta_inside_tree_is_rejected(self):
        document = self.sign_delta()
        (self.delivery / "embedded.json").write_text(
            json.dumps(document), encoding="utf-8"
        )
        second = self.work / "second.json"
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, second)

    def test_lookalike_delta_inside_tree_is_deliverable(self):
        document = self.sign_delta()
        # Right shape, invalid version: must not classify as a real delta.
        lookalike = dict(document)
        lookalike["version"] = 9
        (self.delivery / "almost.json").write_text(
            json.dumps(lookalike), encoding="utf-8"
        )
        second = self.work / "second.json"
        signed = sign_directory(self.delivery, self.private, second)
        self.assertIn(
            "almost.json", [record["path"] for record in signed["files"]]
        )


if __name__ == "__main__":
    unittest.main()
