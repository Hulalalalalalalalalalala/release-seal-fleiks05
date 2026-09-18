import base64
import hashlib
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
    load_pem_public_key,
)

from release_seal.seal import SealError, key_id_of, sign_directory
from release_seal.trust import (
    ACTIVE,
    REVOKED,
    import_key,
    revoke_key,
    verify_trusted,
)


def run_cli(*args) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "release_seal", *map(str, args)],
        capture_output=True, text=True,
    )


def write_keypair(work: Path, name: str = "key"):
    key = Ed25519PrivateKey.generate()
    private = work / f"{name}-private.pem"
    private.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    public = work / f"{name}-public.pem"
    public.write_bytes(
        key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    return key, private, public


def make_delivery(root: Path) -> Path:
    delivery = root / "delivery"
    (delivery / "docs").mkdir(parents=True)
    (delivery / "docs" / "readme.txt").write_bytes(b"hello")
    (delivery / "café.txt").write_bytes("café\n".encode("utf-8"))
    return delivery


class TrustTestCase(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.work = Path(self.workspace.name)
        self.delivery = make_delivery(self.work)
        self.key, self.private, self.public = write_keypair(self.work, "signer")
        self.key_id = key_id_of(self.key.public_key())
        self.store = self.work / "trust.json"
        self.manifest = self.work / "manifest.json"


class ImportTests(TrustTestCase):
    def test_import_creates_versioned_store_with_active_key(self):
        result = import_key(self.public, self.store)
        self.assertEqual(result, {
            "key_id": self.key_id, "status": ACTIVE, "changed": True,
        })
        document = json.loads(self.store.read_text(encoding="utf-8"))
        self.assertEqual(document["kind"], "release-seal-trust-store")
        self.assertEqual(document["version"], 1)
        self.assertEqual(document["algorithm"], "Ed25519")
        entry = document["keys"][self.key_id]
        self.assertEqual(entry["status"], ACTIVE)
        self.assertIsNone(entry["revoked_reason"])
        self.assertIn("-----BEGIN PUBLIC KEY-----", entry["public_key_pem"])
        stored = load_pem_public_key(entry["public_key_pem"].encode("ascii"))
        self.assertEqual(key_id_of(stored), self.key_id)

    def test_key_id_is_sha256_of_der_spki(self):
        import_key(self.public, self.store)
        der = self.key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        self.assertEqual(self.key_id, hashlib.sha256(der).hexdigest())
        self.assertEqual(self.key_id, self.key_id.lower())

    def test_duplicate_import_is_idempotent(self):
        first = import_key(self.public, self.store)
        on_disk = self.store.read_bytes()
        second = import_key(self.public, self.store)
        self.assertEqual(first["key_id"], second["key_id"])
        self.assertFalse(second["changed"])
        self.assertEqual(self.store.read_bytes(), on_disk)

    def test_import_rejects_non_pem_and_non_ed25519(self):
        bogus = self.work / "bogus.pem"
        bogus.write_bytes(b"not pem at all")
        with self.assertRaises(SealError):
            import_key(bogus, self.store)
        rsa = self.work / "rsa-public.pem"
        rsa.write_bytes(
            generate_private_key(public_exponent=65537, key_size=2048)
            .public_key()
            .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )
        with self.assertRaises(SealError):
            import_key(rsa, self.store)
        self.assertFalse(self.store.exists())

    def test_import_multiple_keys_keeps_both(self):
        _, _, public_b = write_keypair(self.work, "b")
        import_key(self.public, self.store)
        import_key(public_b, self.store)
        document = json.loads(self.store.read_text(encoding="utf-8"))
        self.assertEqual(len(document["keys"]), 2)

    def test_cli_import_exit_codes(self):
        ok = run_cli("trust", "import", self.public, self.store)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(json.loads(ok.stdout)["status"], ACTIVE)
        again = run_cli("trust", "import", self.public, self.store)
        self.assertEqual(again.returncode, 0)
        bad = run_cli("trust", "import", self.work / "missing.pem", self.store)
        self.assertEqual(bad.returncode, 2)
        self.assertNotEqual(bad.stderr, "")

    def test_no_temp_files_left_in_store_directory(self):
        import_key(self.public, self.store)
        leftovers = [
            p.name for p in self.work.iterdir()
            if "trust" in p.name and p.name != self.store.name
        ]
        self.assertEqual(leftovers, [])


class RevokeTests(TrustTestCase):
    def test_revoke_records_status_and_reason(self):
        import_key(self.public, self.store)
        result = revoke_key(self.store, self.key_id, "key compromise")
        self.assertEqual(result, {
            "key_id": self.key_id,
            "status": REVOKED,
            "reason": "key compromise",
            "changed": True,
        })
        entry = json.loads(self.store.read_text())["keys"][self.key_id]
        self.assertEqual(entry["status"], REVOKED)
        self.assertEqual(entry["revoked_reason"], "key compromise")

    def test_revoke_without_reason(self):
        import_key(self.public, self.store)
        result = revoke_key(self.store, self.key_id)
        self.assertEqual(result["status"], REVOKED)
        self.assertIsNone(result["reason"])

    def test_revoke_is_idempotent_and_preserves_reason(self):
        import_key(self.public, self.store)
        revoke_key(self.store, self.key_id, "original reason")
        on_disk = self.store.read_bytes()
        result = revoke_key(self.store, self.key_id, "different reason")
        self.assertFalse(result["changed"])
        self.assertEqual(result["reason"], "original reason")
        self.assertEqual(self.store.read_bytes(), on_disk)

    def test_revoked_key_cannot_be_reimported(self):
        import_key(self.public, self.store)
        revoke_key(self.store, self.key_id, "rotated")
        with self.assertRaises(SealError):
            import_key(self.public, self.store)
        entry = json.loads(self.store.read_text())["keys"][self.key_id]
        self.assertEqual(entry["status"], REVOKED)
        self.assertEqual(entry["revoked_reason"], "rotated")

    def test_revoke_unknown_key_and_bad_id_fail(self):
        import_key(self.public, self.store)
        _, _, other_public = write_keypair(self.work, "other")
        other_id = hashlib.sha256(
            load_pem_public_key(other_public.read_bytes()).public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
        ).hexdigest()
        with self.assertRaises(SealError):
            revoke_key(self.store, other_id)
        with self.assertRaises(SealError):
            revoke_key(self.store, "not-a-key-id")
        with self.assertRaises(SealError):
            revoke_key(self.work / "missing-store.json", self.key_id)

    def test_cli_revoke(self):
        run_cli("trust", "import", self.public, self.store)
        result = run_cli(
            "trust", "revoke", self.store, self.key_id, "retired 2026"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["reason"], "retired 2026")
        bad = run_cli("trust", "revoke", self.store, "deadbeef")
        self.assertEqual(bad.returncode, 2)


class VerifyTrustedTests(TrustTestCase):
    def setUp(self):
        super().setUp()
        import_key(self.public, self.store)
        sign_directory(self.delivery, self.private, self.manifest)

    def verify_trusted(self):
        return verify_trusted(self.delivery, self.manifest, self.store)

    def test_valid_manifest(self):
        self.assertEqual(self.verify_trusted(), {
            "valid": True, "key_id": self.key_id,
        })
        result = run_cli(
            "verify-trusted", self.delivery, self.manifest, self.store
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            "valid": True, "key_id": self.key_id,
        })

    def test_unknown_key_id(self):
        _, other_private, _ = write_keypair(self.work, "unknown")
        other_manifest = self.work / "other-manifest.json"
        sign_directory(self.delivery, other_private, other_manifest)
        document = json.loads(other_manifest.read_text(encoding="utf-8"))
        result = self.verify_trusted_from(document)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "unknown_key")
        self.assertEqual(result["key_id"], document["key_id"])
        self.assertEqual(result["modified"], [])
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["unexpected"], [])

    def verify_trusted_from(self, document, path=None):
        target = path or self.work / "candidate.json"
        target.write_text(json.dumps(document), encoding="utf-8")
        return verify_trusted(self.delivery, target, self.store)

    def test_revoked_key_is_rejected_before_signature_checks(self):
        # Sign with a second key, import then revoke it.
        _, rev_private, rev_public = write_keypair(self.work, "revoked")
        import_key(rev_public, self.store)
        rev_id = key_id_of(
            load_pem_public_key(rev_public.read_bytes())
        )
        revoke_key(self.store, rev_id, "compromised")
        rev_manifest = self.work / "revoked-manifest.json"
        sign_directory(self.delivery, rev_private, rev_manifest)
        result = verify_trusted(self.delivery, rev_manifest, self.store)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "revoked")
        self.assertEqual(result["key_id"], rev_id)
        cli = run_cli(
            "verify-trusted", self.delivery, rev_manifest, self.store
        )
        self.assertEqual(cli.returncode, 1)
        self.assertEqual(json.loads(cli.stdout)["reason"], "revoked")

    def test_invalid_signature_is_distinct_from_unknown(self):
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        document["signature"] = base64.b64encode(b"\x00" * 64).decode("ascii")
        result = self.verify_trusted_from(document)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "invalid_signature")
        self.assertEqual(result["key_id"], self.key_id)

    def test_file_mismatch_lists_sorted_paths(self):
        (self.delivery / "docs" / "readme.txt").write_bytes(b"changed")
        (self.delivery / "extra.txt").write_bytes(b"extra")
        result = self.verify_trusted()
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "file_mismatch")
        self.assertEqual(result["modified"], ["docs/readme.txt"])
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["unexpected"], ["extra.txt"])
        cli = run_cli(
            "verify-trusted", self.delivery, self.manifest, self.store
        )
        self.assertEqual(cli.returncode, 1)

    def test_missing_file_is_file_mismatch(self):
        (self.delivery / "café.txt").unlink()
        result = self.verify_trusted()
        self.assertEqual(result["reason"], "file_mismatch")
        self.assertEqual(result["missing"], ["café.txt"])

    def test_tampered_manifest_payload_is_invalid_signature(self):
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        document["files"][0]["size"] += 1
        result = self.verify_trusted_from(document)
        self.assertEqual(result["reason"], "invalid_signature")

    def test_failure_never_reports_success_and_order_is_stable(self):
        _, other_private, _ = write_keypair(self.work, "intruder")
        intruder_manifest = self.work / "intruder.json"
        sign_directory(self.delivery, other_private, intruder_manifest)
        first = json.dumps(
            verify_trusted(self.delivery, intruder_manifest, self.store),
            sort_keys=True,
        )
        second = json.dumps(
            verify_trusted(self.delivery, intruder_manifest, self.store),
            sort_keys=True,
        )
        self.assertEqual(first, second)
        self.assertIn('"valid": false', first)

    def test_store_inside_delivery_is_rejected(self):
        inside = self.delivery / "trust.json"
        with self.assertRaises(SealError):
            verify_trusted(self.delivery, self.manifest, inside)

    def test_malformed_store_and_manifest_are_status_2(self):
        self.store.write_bytes(b"not json")
        with self.assertRaises(SealError):
            self.verify_trusted()
        result = run_cli(
            "verify-trusted", self.delivery, self.manifest, self.store
        )
        self.assertEqual(result.returncode, 2)

    def test_store_with_key_mismatched_to_id_is_status_2(self):
        document = json.loads(self.store.read_text(encoding="utf-8"))
        _, _, other_public = write_keypair(self.work, "mismatch")
        document["keys"][self.key_id]["public_key_pem"] = other_public.read_text()
        self.store.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SealError):
            self.verify_trusted()


class Version1TrustedTests(TrustTestCase):
    def test_version_1_manifest_matches_active_key(self):
        from release_seal.inventory import inventory as take_inventory
        from release_seal.seal import canonical_payload

        import_key(self.public, self.store)
        files = take_inventory(self.delivery)
        payload = canonical_payload(1, None, files)
        document = {
            "version": 1,
            "algorithm": "Ed25519",
            "hash": "SHA-256",
            "files": files,
            "signature": base64.b64encode(self.key.sign(payload)).decode("ascii"),
        }
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        result = verify_trusted(self.delivery, self.manifest, self.store)
        self.assertTrue(result["valid"])
        self.assertEqual(result["key_id"], self.key_id)

    def test_version_1_signed_by_revoked_key_is_revoked(self):
        from release_seal.inventory import inventory as take_inventory
        from release_seal.seal import canonical_payload

        import_key(self.public, self.store)
        revoke_key(self.store, self.key_id, "old release key")
        files = take_inventory(self.delivery)
        payload = canonical_payload(1, None, files)
        document = {
            "version": 1,
            "algorithm": "Ed25519",
            "hash": "SHA-256",
            "files": files,
            "signature": base64.b64encode(self.key.sign(payload)).decode("ascii"),
        }
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        result = verify_trusted(self.delivery, self.manifest, self.store)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "revoked")
        self.assertEqual(result["key_id"], self.key_id)


if __name__ == "__main__":
    unittest.main()
