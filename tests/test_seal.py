import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from release_seal import seal
from release_seal.inventory import inventory
from release_seal.seal import SealError, key_id_of, sign_directory, verify_directory


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


class SealTestCase(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.work = Path(self.workspace.name)
        self.delivery = make_delivery(self.work)
        self.private, self.public = write_keypair(self.work)
        self.manifest = self.work / "manifest.json"


class SignTests(SealTestCase):
    def test_sign_writes_signed_version_2_manifest(self):
        document = sign_directory(self.delivery, self.private, self.manifest)
        self.assertEqual(document["version"], 2)
        self.assertEqual(document["algorithm"], "Ed25519")
        self.assertEqual(document["hash"], "SHA-256")
        self.assertEqual(
            [record["path"] for record in document["files"]],
            ["café.txt", "docs/readme.txt"],
        )
        der = load_pem_public_key(self.public.read_bytes()).public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        self.assertEqual(document["key_id"], hashlib.sha256(der).hexdigest())
        signature = base64.b64decode(document["signature"], validate=True)
        self.assertEqual(len(signature), 64)
        on_disk = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(on_disk, document)

    def test_signature_covers_everything_but_signature(self):
        document = sign_directory(self.delivery, self.private, self.manifest)
        payload = json.dumps(
            {
                "version": 2,
                "algorithm": "Ed25519",
                "hash": "SHA-256",
                "files": document["files"],
                "key_id": document["key_id"],
            },
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        self.assertIn("café".encode("utf-8"), payload)
        key = load_pem_public_key(self.public.read_bytes())
        key.verify(base64.b64decode(document["signature"]), payload)

    def test_tampered_key_id_invalidates_signature(self):
        document = sign_directory(self.delivery, self.private, self.manifest)
        document["key_id"] = "0" * 64
        self.manifest.write_text(
            json.dumps(document, ensure_ascii=False), encoding="utf-8"
        )
        self.assertEqual(verify_directory(self.delivery, self.manifest, self.public), {
            "valid": False, "modified": [], "missing": [], "unexpected": [],
        })

    def test_sign_refuses_to_overwrite_manifest(self):
        sign_directory(self.delivery, self.private, self.manifest)
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, self.manifest)
        result = run_cli("sign", self.delivery, self.private, self.manifest)
        self.assertEqual(result.returncode, 2)
        self.assertIn("already exists", result.stderr)

    def test_sign_leaves_existing_manifest_untouched_and_no_residue(self):
        self.manifest.write_bytes(b"keep me")
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, self.manifest)
        self.assertEqual(self.manifest.read_bytes(), b"keep me")
        leftovers = [
            path for path in self.work.iterdir()
            if path.name.startswith(self.manifest.name + ".")
        ]
        self.assertEqual(leftovers, [])

    def test_sign_refuses_when_directory_changes_mid_scan(self):
        original = seal.inventory

        def mutating(directory):
            (self.delivery / "mid-scan.txt").write_bytes(b"sneaky")
            return original(directory)

        with mock.patch.object(seal, "inventory", mutating):
            with self.assertRaises(SealError):
                sign_directory(self.delivery, self.private, self.manifest)
        self.assertFalse(self.manifest.exists())

    def test_sign_refuses_key_or_manifest_inside_delivery(self):
        cases = (
            (self.delivery / "private.pem", self.manifest),
            (self.private, self.delivery / "manifest.json"),
        )
        for key_path, manifest_path in cases:
            with self.subTest(key=key_path, manifest=manifest_path):
                with self.assertRaises(SealError):
                    sign_directory(self.delivery, key_path, manifest_path)

    def test_sign_rejects_non_ed25519_key(self):
        rsa = self.work / "rsa.pem"
        rsa.write_bytes(
            generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
        )
        with self.assertRaises(SealError):
            sign_directory(self.delivery, rsa, self.manifest)

    def test_sign_rejects_unreadable_key(self):
        result = run_cli(
            "sign", self.delivery, self.work / "missing.pem", self.manifest
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")


class VerifyTests(SealTestCase):
    def setUp(self):
        super().setUp()
        sign_directory(self.delivery, self.private, self.manifest)

    def verify(self, public=None):
        return verify_directory(self.delivery, self.manifest, public or self.public)

    def test_valid_delivery(self):
        self.assertEqual(self.verify(), {"valid": True})
        result = run_cli("verify", self.delivery, self.manifest, self.public)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"valid": True})

    def test_version_1_manifest_still_verifies(self):
        files = inventory(self.delivery)
        body = {
            "version": 1,
            "algorithm": "Ed25519",
            "hash": "SHA-256",
            "files": files,
        }
        payload = json.dumps(
            body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        key = load_pem_private_key(self.private.read_bytes(), password=None)
        document = {
            **body,
            "signature": base64.b64encode(key.sign(payload)).decode("ascii"),
        }
        self.manifest.write_text(
            json.dumps(document, ensure_ascii=False), encoding="utf-8"
        )
        self.assertEqual(self.verify(), {"valid": True})

    def test_modified_file(self):
        (self.delivery / "docs" / "readme.txt").write_bytes(b"changed")
        self.assertEqual(self.verify(), {
            "valid": False,
            "modified": ["docs/readme.txt"],
            "missing": [],
            "unexpected": [],
        })
        result = run_cli("verify", self.delivery, self.manifest, self.public)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)["valid"])

    def test_missing_file(self):
        (self.delivery / "café.txt").unlink()
        self.assertEqual(self.verify(), {
            "valid": False,
            "modified": [],
            "missing": ["café.txt"],
            "unexpected": [],
        })

    def test_unexpected_file(self):
        (self.delivery / "extra.txt").write_bytes(b"extra")
        self.assertEqual(self.verify(), {
            "valid": False,
            "modified": [],
            "missing": [],
            "unexpected": ["extra.txt"],
        })

    def test_wrong_public_key(self):
        other = self.work / "other"
        other.mkdir()
        _, other_public = write_keypair(other)
        self.assertEqual(self.verify(other_public), {
            "valid": False, "modified": [], "missing": [], "unexpected": [],
        })
        result = run_cli("verify", self.delivery, self.manifest, other_public)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)["valid"])

    def test_tampered_manifest_invalidates_signature(self):
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        document["files"][0]["size"] += 1
        self.manifest.write_text(
            json.dumps(document, ensure_ascii=False), encoding="utf-8"
        )
        self.assertEqual(self.verify(), {
            "valid": False, "modified": [], "missing": [], "unexpected": [],
        })

    def test_malformed_manifest_is_a_format_error(self):
        self.manifest.write_bytes(b"not json")
        with self.assertRaises(SealError):
            self.verify()
        result = run_cli("verify", self.delivery, self.manifest, self.public)
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")

    def test_manifest_with_unsupported_version_is_a_format_error(self):
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        document["version"] = 3
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SealError):
            self.verify()

    def test_version_2_manifest_without_key_id_is_a_format_error(self):
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        del document["key_id"]
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SealError):
            self.verify()

    def test_unparseable_public_key_is_a_format_error(self):
        self.public.write_bytes(b"not a pem")
        result = run_cli("verify", self.delivery, self.manifest, self.public)
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")

    def test_verify_refuses_manifest_or_key_inside_delivery(self):
        inside = self.delivery / "manifest.json"
        with self.assertRaises(SealError):
            verify_directory(self.delivery, inside, self.public)
        with self.assertRaises(SealError):
            verify_directory(self.delivery, self.manifest, self.delivery / "public.pem")


class KeyIdTests(unittest.TestCase):
    def test_key_id_is_sha256_of_der_subject_public_key_info(self):
        key = Ed25519PrivateKey.generate().public_key()
        der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(key_id_of(key), hashlib.sha256(der).hexdigest())


class DemoTests(unittest.TestCase):
    def test_demo_signs_verifies_and_rejects_tampering(self):
        result = run_cli("demo")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"valid": true', result.stdout)
        self.assertIn('"valid": false', result.stdout)
        self.assertIn('"reason": "revoked"', result.stdout)
        self.assertIn("private key has been removed", result.stdout)


if __name__ == "__main__":
    unittest.main()
