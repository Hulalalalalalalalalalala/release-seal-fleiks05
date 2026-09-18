import base64
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

from release_seal import sign_directory, verify_directory


def write_keypair(folder):
    private = Ed25519PrivateKey.generate()
    private_path = Path(folder) / "private.pem"
    public_path = Path(folder) / "public.pem"
    private_path.write_bytes(private.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ))
    public_path.write_bytes(private.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ))
    return private_path, public_path


def make_delivery(folder):
    root = Path(folder) / "delivery"
    root.mkdir()
    (root / "notes.txt").write_bytes(b"release notes\n")
    (root / "data").mkdir()
    (root / "data" / "measurements.csv").write_bytes(b"a,b\n1,2\n")
    return root


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "release_seal", *args],
        capture_output=True, text=True,
    )


class SignTests(unittest.TestCase):
    def test_sign_then_verify_roundtrip(self):
        with tempfile.TemporaryDirectory() as folder:
            delivery = make_delivery(folder)
            private_path, public_path = write_keypair(folder)
            manifest = Path(folder) / "manifest.json"
            document = sign_directory(delivery, private_path, manifest)
            self.assertEqual(document["version"], 1)
            self.assertEqual(document["algorithm"], "Ed25519")
            self.assertEqual(document["hash"], "SHA-256")
            self.assertEqual(len(document["files"]), 2)
            base64.b64decode(document["signature"], validate=True)
            self.assertEqual(json.loads(manifest.read_text("utf-8")), document)
            self.assertEqual(
                verify_directory(delivery, manifest, public_path), {"valid": True}
            )

    def test_signature_covers_canonical_payload(self):
        with tempfile.TemporaryDirectory() as folder:
            delivery = make_delivery(folder)
            private_path, public_path = write_keypair(folder)
            manifest = Path(folder) / "manifest.json"
            document = sign_directory(delivery, private_path, manifest)
            payload = json.dumps(
                {key: document[key] for key in ("version", "algorithm", "hash", "files")},
                ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
            public = load_pem_public_key(public_path.read_bytes())
            public.verify(base64.b64decode(document["signature"]), payload)

    def test_sign_refuses_to_overwrite_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            delivery = make_delivery(folder)
            private_path, _ = write_keypair(folder)
            manifest = Path(folder) / "manifest.json"
            sign_directory(delivery, private_path, manifest)
            before = manifest.read_bytes()
            result = run_cli(
                "sign", str(delivery), str(private_path), str(manifest)
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("already exists", result.stderr)
            self.assertEqual(manifest.read_bytes(), before)

    def test_sign_refuses_key_or_manifest_inside_delivery(self):
        with tempfile.TemporaryDirectory() as folder:
            delivery = make_delivery(folder)
            private_path, _ = write_keypair(folder)
            inside_key = delivery / "key.pem"
            inside_key.write_bytes(private_path.read_bytes())
            result = run_cli(
                "sign", str(delivery), str(inside_key), str(Path(folder) / "m.json")
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("inside the delivery tree", result.stderr)
            result = run_cli(
                "sign", str(delivery), str(private_path), str(delivery / "m.json")
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("inside the delivery tree", result.stderr)

    def test_sign_rejects_broken_private_key(self):
        with tempfile.TemporaryDirectory() as folder:
            delivery = make_delivery(folder)
            broken = Path(folder) / "broken.pem"
            broken.write_bytes(b"not a pem\n")
            result = run_cli(
                "sign", str(delivery), str(broken), str(Path(folder) / "m.json")
            )
            self.assertEqual(result.returncode, 2)
            self.assertNotEqual(result.stderr, "")


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        folder = Path(self.temp.name)
        self.delivery = make_delivery(folder)
        self.private_path, self.public_path = write_keypair(folder)
        self.manifest = folder / "manifest.json"
        sign_directory(self.delivery, self.private_path, self.manifest)
        self.document = json.loads(self.manifest.read_text("utf-8"))

    def tearDown(self):
        self.temp.cleanup()

    def verify(self, directory=None, public=None):
        return verify_directory(
            directory or self.delivery,
            self.manifest,
            public or self.public_path,
        )

    def test_modified_file_is_reported(self):
        (self.delivery / "notes.txt").write_bytes(b"tampered\n")
        self.assertEqual(self.verify(), {
            "valid": False,
            "modified": ["notes.txt"],
            "missing": [],
            "unexpected": [],
        })

    def test_missing_and_unexpected_files_are_reported_sorted(self):
        (self.delivery / "notes.txt").unlink()
        (self.delivery / "extra.txt").write_bytes(b"extra")
        (self.delivery / "data" / "another.txt").write_bytes(b"more")
        self.assertEqual(self.verify(), {
            "valid": False,
            "modified": [],
            "missing": ["notes.txt"],
            "unexpected": ["data/another.txt", "extra.txt"],
        })

    def test_wrong_public_key_fails_verification(self):
        with tempfile.TemporaryDirectory() as folder:
            _, other_public = write_keypair(folder)
            self.assertEqual(self.verify(public=other_public), {
                "valid": False, "modified": [], "missing": [], "unexpected": [],
            })

    def test_tampered_manifest_fails_verification(self):
        document = json.loads(self.manifest.read_text("utf-8"))
        document["files"][0]["sha256"] = "0" * 64
        self.manifest.write_text(json.dumps(document), "utf-8")
        self.assertEqual(self.verify(), {
            "valid": False, "modified": [], "missing": [], "unexpected": [],
        })

    def test_cli_success_and_failure_exit_codes(self):
        result = run_cli(
            "verify", str(self.delivery), str(self.manifest), str(self.public_path)
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {"valid": True})
        (self.delivery / "notes.txt").write_bytes(b"tampered\n")
        result = run_cli(
            "verify", str(self.delivery), str(self.manifest), str(self.public_path)
        )
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertFalse(report["valid"])
        self.assertEqual(report["modified"], ["notes.txt"])

    def test_malformed_manifest_is_an_error(self):
        self.manifest.write_bytes(b"not json")
        result = run_cli(
            "verify", str(self.delivery), str(self.manifest), str(self.public_path)
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")
        document = dict(self.document)
        del document["signature"]
        self.manifest.write_text(json.dumps(document), "utf-8")
        result = run_cli(
            "verify", str(self.delivery), str(self.manifest), str(self.public_path)
        )
        self.assertEqual(result.returncode, 2)

    def test_verify_refuses_manifest_or_key_inside_delivery(self):
        inside_manifest = self.delivery / "manifest.json"
        inside_manifest.write_bytes(self.manifest.read_bytes())
        result = run_cli(
            "verify", str(self.delivery), str(inside_manifest), str(self.public_path)
        )
        self.assertEqual(result.returncode, 2)
        inside_public = self.delivery / "public.pem"
        inside_public.write_bytes(self.public_path.read_bytes())
        result = run_cli(
            "verify", str(self.delivery), str(self.manifest), str(inside_public)
        )
        self.assertEqual(result.returncode, 2)

    def test_verify_rejects_symlink_in_delivery(self):
        link = self.delivery / "linked"
        try:
            link.symlink_to(self.delivery / "notes.txt")
        except OSError:
            self.skipTest("symbolic links unavailable")
        result = run_cli(
            "verify", str(self.delivery), str(self.manifest), str(self.public_path)
        )
        self.assertEqual(result.returncode, 2)


class DemoTests(unittest.TestCase):
    def test_demo_signs_verifies_and_removes_private_key(self):
        result = run_cli("demo")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"valid": true', result.stdout)
        self.assertIn('"valid": false', result.stdout)
        self.assertIn("notes.txt", result.stdout)
        self.assertIn("private key removed", result.stdout)


if __name__ == "__main__":
    unittest.main()
