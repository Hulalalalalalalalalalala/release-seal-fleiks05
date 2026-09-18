import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from release_seal.seal import SealError, sign_directory
from release_seal.trust import import_key, load_store, revoke_key, verify_trusted


def write_keypair(work: Path, name: str) -> tuple[Path, Path]:
    key = Ed25519PrivateKey.generate()
    private = work / f"{name}-private.pem"
    private.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    public = work / f"{name}-public.pem"
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


class TrustTestCase(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.work = Path(self.workspace.name)
        self.delivery = make_delivery(self.work)
        self.private, self.public = write_keypair(self.work, "main")
        self.manifest = self.work / "manifest.json"
        self.store = self.work / "trust-store.json"
        sign_directory(self.delivery, self.private, self.manifest)
        self.key_id = json.loads(self.manifest.read_text(encoding="utf-8"))["key_id"]


class ImportTests(TrustTestCase):
    def test_import_creates_versioned_store_with_active_key(self):
        result = import_key(self.public, self.store)
        self.assertEqual(result, {
            "key_id": self.key_id, "status": "active", "reason": None,
        })
        document = json.loads(self.store.read_text(encoding="utf-8"))
        self.assertEqual(document["version"], 1)
        entry = document["keys"][self.key_id]
        self.assertEqual(entry["status"], "active")
        self.assertIsNone(entry["reason"])
        self.assertTrue(entry["public_key"].startswith("-----BEGIN PUBLIC KEY-----"))

    def test_import_is_idempotent_and_leaves_store_untouched(self):
        import_key(self.public, self.store)
        before = self.store.read_bytes()
        result = import_key(self.public, self.store)
        self.assertEqual(result["status"], "active")
        self.assertEqual(self.store.read_bytes(), before)

    def test_import_never_revives_a_revoked_key(self):
        import_key(self.public, self.store)
        revoke_key(self.store, self.key_id, "compromised")
        before = self.store.read_bytes()
        result = import_key(self.public, self.store)
        self.assertEqual(result, {
            "key_id": self.key_id, "status": "revoked", "reason": "compromised",
        })
        self.assertEqual(self.store.read_bytes(), before)

    def test_import_rejects_non_ed25519_key(self):
        rsa = self.work / "rsa.pem"
        rsa.write_bytes(
            generate_private_key(public_exponent=65537, key_size=2048)
            .public_key()
            .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )
        with self.assertRaises(SealError):
            import_key(rsa, self.store)
        self.assertFalse(self.store.exists())

    def test_import_rejects_unreadable_key_via_cli(self):
        result = run_cli(
            "trust", "import", self.work / "missing.pem", self.store
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")

    def test_import_via_cli(self):
        result = run_cli("trust", "import", self.public, self.store)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["key_id"], self.key_id)


class RevokeTests(TrustTestCase):
    def test_revoke_marks_key_with_reason(self):
        import_key(self.public, self.store)
        result = revoke_key(self.store, self.key_id, "key rotated")
        self.assertEqual(result, {
            "key_id": self.key_id, "status": "revoked", "reason": "key rotated",
        })
        entry = load_store(self.store)["keys"][self.key_id]
        self.assertEqual(entry["status"], "revoked")
        self.assertEqual(entry["reason"], "key rotated")

    def test_revoke_without_reason_stores_null(self):
        import_key(self.public, self.store)
        result = revoke_key(self.store, self.key_id)
        self.assertEqual(result["status"], "revoked")
        self.assertIsNone(result["reason"])

    def test_revoke_is_idempotent(self):
        import_key(self.public, self.store)
        revoke_key(self.store, self.key_id, "first")
        before = self.store.read_bytes()
        result = revoke_key(self.store, self.key_id)
        self.assertEqual(result["reason"], "first")
        self.assertEqual(self.store.read_bytes(), before)

    def test_revoke_unknown_key_is_an_error(self):
        import_key(self.public, self.store)
        with self.assertRaises(SealError):
            revoke_key(self.store, "f" * 64)
        result = run_cli("trust", "revoke", self.store, "f" * 64)
        self.assertEqual(result.returncode, 2)

    def test_revoke_rejects_malformed_key_id(self):
        import_key(self.public, self.store)
        for bad in ("XYZ", "A" * 64, "f" * 63):
            with self.subTest(key_id=bad):
                with self.assertRaises(SealError):
                    revoke_key(self.store, bad)

    def test_revoke_missing_store_is_an_error(self):
        result = run_cli("trust", "revoke", self.store, self.key_id)
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")

    def test_revoke_via_cli_with_reason(self):
        run_cli("trust", "import", self.public, self.store)
        result = run_cli("trust", "revoke", self.store, self.key_id, "retired")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["reason"], "retired")


class StoreValidationTests(TrustTestCase):
    def test_corrupted_store_is_an_error(self):
        self.store.write_bytes(b"not json")
        with self.assertRaises(SealError):
            load_store(self.store)

    def test_store_entry_must_match_its_key_id(self):
        import_key(self.public, self.store)
        _, other_public = write_keypair(self.work, "other")
        document = json.loads(self.store.read_text(encoding="utf-8"))
        document["keys"][self.key_id]["public_key"] = other_public.read_text(
            encoding="utf-8"
        )
        self.store.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SealError):
            load_store(self.store)

    def test_store_with_wrong_version_is_an_error(self):
        import_key(self.public, self.store)
        document = json.loads(self.store.read_text(encoding="utf-8"))
        document["version"] = 99
        self.store.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SealError):
            load_store(self.store)


class VerifyTrustedTests(TrustTestCase):
    def setUp(self):
        super().setUp()
        import_key(self.public, self.store)

    def test_valid_delivery(self):
        self.assertEqual(
            verify_trusted(self.delivery, self.manifest, self.store),
            {"valid": True, "key_id": self.key_id},
        )
        result = run_cli(
            "verify-trusted", self.delivery, self.manifest, self.store
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout), {"valid": True, "key_id": self.key_id}
        )

    def test_unknown_key(self):
        other = self.work / "other"
        other.mkdir()
        other_private, _ = write_keypair(other, "other")
        other_manifest = other / "manifest.json"
        sign_directory(self.delivery, other_private, other_manifest)
        outcome = verify_trusted(self.delivery, other_manifest, self.store)
        self.assertEqual(outcome, {
            "valid": False,
            "key_id": outcome["key_id"],
            "reason": "unknown_key",
            "modified": [],
            "missing": [],
            "unexpected": [],
        })
        result = run_cli(
            "verify-trusted", self.delivery, other_manifest, self.store
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["reason"], "unknown_key")

    def test_revoked_key(self):
        revoke_key(self.store, self.key_id, "compromised")
        self.assertEqual(verify_trusted(self.delivery, self.manifest, self.store), {
            "valid": False,
            "key_id": self.key_id,
            "reason": "revoked",
            "detail": "compromised",
            "modified": [],
            "missing": [],
            "unexpected": [],
        })
        result = run_cli(
            "verify-trusted", self.delivery, self.manifest, self.store
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["reason"], "revoked")

    def test_invalid_signature(self):
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        document["files"][0]["size"] += 1
        self.manifest.write_text(
            json.dumps(document, ensure_ascii=False), encoding="utf-8"
        )
        self.assertEqual(verify_trusted(self.delivery, self.manifest, self.store), {
            "valid": False,
            "key_id": self.key_id,
            "reason": "invalid_signature",
            "modified": [],
            "missing": [],
            "unexpected": [],
        })

    def test_modified_missing_and_unexpected_files(self):
        (self.delivery / "docs" / "readme.txt").write_bytes(b"changed")
        (self.delivery / "café.txt").unlink()
        (self.delivery / "extra.txt").write_bytes(b"extra")
        self.assertEqual(verify_trusted(self.delivery, self.manifest, self.store), {
            "valid": False,
            "key_id": self.key_id,
            "reason": "mismatch",
            "modified": ["docs/readme.txt"],
            "missing": ["café.txt"],
            "unexpected": ["extra.txt"],
        })
        result = run_cli(
            "verify-trusted", self.delivery, self.manifest, self.store
        )
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)["valid"])

    def test_version_1_manifest_is_a_format_error(self):
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        del document["key_id"]
        document["version"] = 1
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SealError):
            verify_trusted(self.delivery, self.manifest, self.store)

    def test_store_inside_delivery_is_refused(self):
        with self.assertRaises(SealError):
            verify_trusted(
                self.delivery, self.manifest, self.delivery / "store.json"
            )

    def test_missing_store_is_an_error(self):
        result = run_cli(
            "verify-trusted", self.delivery, self.manifest, self.work / "none.json"
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
