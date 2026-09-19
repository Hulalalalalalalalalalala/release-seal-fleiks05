import base64
import hashlib
import json
import os
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
    load_pem_private_key,
    load_pem_public_key,
)

from release_seal.inventory import inventory, stat_snapshot
from release_seal.seal import SealError, sign_directory, verify_directory


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
    def test_sign_writes_signed_manifest(self):
        document = sign_directory(self.delivery, self.private, self.manifest)
        self.assertEqual(document["version"], 2)
        self.assertEqual(document["algorithm"], "Ed25519")
        self.assertEqual(document["hash"], "SHA-256")
        self.assertEqual(
            [record["path"] for record in document["files"]],
            ["café.txt", "docs/readme.txt"],
        )
        key = load_pem_public_key(self.public.read_bytes())
        der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(document["key_id"], hashlib.sha256(der).hexdigest())
        signature = base64.b64decode(document["signature"], validate=True)
        self.assertEqual(len(signature), 64)
        on_disk = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(on_disk, document)

    def test_signature_covers_canonical_payload(self):
        document = sign_directory(self.delivery, self.private, self.manifest)
        payload = json.dumps(
            {
                "version": 2,
                "algorithm": "Ed25519",
                "hash": "SHA-256",
                "key_id": document["key_id"],
                "files": document["files"],
            },
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        self.assertIn("café".encode("utf-8"), payload)
        key = load_pem_public_key(self.public.read_bytes())
        key.verify(base64.b64decode(document["signature"]), payload)

    def test_sign_refuses_to_overwrite_manifest(self):
        sign_directory(self.delivery, self.private, self.manifest)
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, self.manifest)
        result = run_cli("sign", self.delivery, self.private, self.manifest)
        self.assertEqual(result.returncode, 2)
        self.assertIn("already exists", result.stderr)

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

    def test_failed_sign_leaves_no_residue(self):
        rsa = self.work / "rsa.pem"
        rsa.write_bytes(
            generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
        )
        with self.assertRaises(SealError):
            sign_directory(self.delivery, rsa, self.manifest)
        self.assertFalse(self.manifest.exists())
        self.assertEqual(
            [p.name for p in self.work.iterdir() if p.name.startswith(".")],
            [],
        )

    def test_existing_manifest_is_never_overwritten_or_truncated(self):
        sign_directory(self.delivery, self.private, self.manifest)
        original = self.manifest.read_bytes()
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, self.manifest)
        self.assertEqual(self.manifest.read_bytes(), original)
        self.assertEqual(
            [p.name for p in self.work.iterdir() if p.suffix == ".tmp"],
            [],
        )

    def test_sign_rejects_keys_and_manifests_inside_tree(self):
        public_in_tree = self.delivery / "embedded.pem"
        public_in_tree.write_bytes(self.public.read_bytes())
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, self.manifest)
        public_in_tree.unlink()
        manifest_in_tree = self.delivery / "embedded-manifest.json"
        sign_directory(self.delivery, self.private, self.manifest)
        manifest_in_tree.write_bytes(self.manifest.read_bytes())
        second = self.work / "second.json"
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, second)

    def test_ordinary_pem_and_json_files_are_deliverable(self):
        # Detection is by content, not by name: a certificate-style PEM
        # and ordinary JSON documents must not block the delivery.
        (self.delivery / "cert.pem").write_bytes(
            b"-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIB\n"
            b"-----END CERTIFICATE-----\n"
        )
        (self.delivery / "notes.pem").write_bytes(b"not a key at all\n")
        (self.delivery / "config.json").write_text(
            json.dumps({"version": 2, "threshold": 1}), encoding="utf-8"
        )
        (self.delivery / "data.json").write_text(
            json.dumps({"kind": "something-else", "keys": [1, 2]}),
            encoding="utf-8",
        )
        document = sign_directory(self.delivery, self.private, self.manifest)
        paths = [record["path"] for record in document["files"]]
        self.assertIn("cert.pem", paths)
        self.assertIn("notes.pem", paths)
        self.assertIn("config.json", paths)
        self.assertIn("data.json", paths)

    def test_real_keys_are_rejected_whatever_the_name(self):
        (self.delivery / "payload.txt").write_bytes(self.private.read_bytes())
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, self.manifest)
        (self.delivery / "payload.txt").unlink()
        (self.delivery / "bundle.pem").write_bytes(self.public.read_bytes())
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, self.manifest)

    def test_trust_store_and_policy_structures_are_rejected_inside_tree(self):
        (self.delivery / "store.json").write_text(
            json.dumps({
                "kind": "release-seal-trust-store",
                "version": 1,
                "algorithm": "Ed25519",
                "keys": {},
            }),
            encoding="utf-8",
        )
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, self.manifest)
        (self.delivery / "store.json").unlink()
        (self.delivery / "policy.json").write_text(
            json.dumps({
                "version": 1,
                "threshold": 1,
                "allowed_key_ids": ["0" * 64],
            }),
            encoding="utf-8",
        )
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, self.manifest)

    def test_forbidden_content_is_rejected_whatever_the_extension(self):
        sign_directory(self.delivery, self.private, self.manifest)
        manifest_bytes = self.manifest.read_bytes()
        self.manifest.unlink()
        (self.delivery / "payload.bin").write_bytes(manifest_bytes)
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, self.manifest)
        (self.delivery / "payload.bin").unlink()
        (self.delivery / "store.txt").write_text(
            json.dumps({
                "kind": "release-seal-trust-store",
                "version": 1,
                "algorithm": "Ed25519",
                "keys": {},
            }),
            encoding="utf-8",
        )
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, self.manifest)
        (self.delivery / "store.txt").unlink()
        (self.delivery / "policy").write_text(
            json.dumps({
                "version": 1,
                "threshold": 1,
                "allowed_key_ids": ["0" * 64],
            }),
            encoding="utf-8",
        )
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, self.manifest)

    def test_malformed_lookalikes_are_deliverable(self):
        sign_directory(self.delivery, self.private, self.manifest)
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.manifest.unlink()
        lookalike = dict(document, signature="not-base64!!!")
        (self.delivery / "lookalike.json").write_text(
            json.dumps(lookalike), encoding="utf-8"
        )
        extra_field = dict(document, extra=1)
        (self.delivery / "extra.json").write_text(
            json.dumps(extra_field), encoding="utf-8"
        )
        (self.delivery / "store.json").write_text(
            json.dumps({
                "kind": "release-seal-trust-store",
                "version": 1,
                "algorithm": "Ed25519",
                "keys": {"not-a-key-id": {}},
            }),
            encoding="utf-8",
        )
        (self.delivery / "policy.json").write_text(
            json.dumps({
                "version": 1,
                "threshold": 5,
                "allowed_key_ids": ["0" * 64],
            }),
            encoding="utf-8",
        )
        result = sign_directory(self.delivery, self.private, self.manifest)
        paths = [record["path"] for record in result["files"]]
        self.assertIn("lookalike.json", paths)
        self.assertIn("extra.json", paths)
        self.assertIn("store.json", paths)
        self.assertIn("policy.json", paths)

    def test_encrypted_and_foreign_algorithm_pem_keys_are_rejected(self):
        from cryptography.hazmat.primitives.serialization import (
            BestAvailableEncryption,
        )

        key = load_pem_private_key(self.private.read_bytes(), password=None)
        (self.delivery / "enc.pem").write_bytes(
            key.private_bytes(
                Encoding.PEM,
                PrivateFormat.PKCS8,
                BestAvailableEncryption(b"secret"),
            )
        )
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, self.manifest)
        (self.delivery / "enc.pem").unlink()
        rsa_public = generate_private_key(
            public_exponent=65537, key_size=2048
        ).public_key()
        (self.delivery / "rsa.pub").write_bytes(
            rsa_public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, self.manifest)

    def test_der_and_openssh_keys_are_not_inspected(self):
        key = load_pem_private_key(self.private.read_bytes(), password=None)
        (self.delivery / "key.der").write_bytes(
            key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        )
        (self.delivery / "id_ssh").write_bytes(
            key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
        )
        result = sign_directory(self.delivery, self.private, self.manifest)
        paths = [record["path"] for record in result["files"]]
        self.assertIn("key.der", paths)
        self.assertIn("id_ssh", paths)

    def test_directory_sync_failure_keeps_target_and_reports_durability(self):
        from release_seal import seal as seal_module

        original = seal_module._sync_directory

        def failing(directory):
            raise OSError("sync rejected")

        seal_module._sync_directory = failing
        try:
            with self.assertRaises(SealError) as caught:
                sign_directory(self.delivery, self.private, self.manifest)
        finally:
            seal_module._sync_directory = original
        self.assertIn("durability", str(caught.exception))
        # The complete manifest stays in place and no temp file remains.
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(document["version"], 2)
        self.assertEqual(
            [p.name for p in self.work.iterdir() if p.suffix == ".tmp"], []
        )

    def test_replace_sync_failure_keeps_new_store_and_reports_durability(self):
        from release_seal import seal as seal_module
        from release_seal.trust import import_key

        import_key(self.public, self.work / "trust.json")
        other = self.work / "other"
        other.mkdir()
        _, other_public = write_keypair(other)
        original = seal_module._sync_directory

        def failing(directory):
            raise OSError("sync rejected")

        seal_module._sync_directory = failing
        try:
            with self.assertRaises(SealError) as caught:
                import_key(other_public, self.work / "trust.json")
        finally:
            seal_module._sync_directory = original
        self.assertIn("durability", str(caught.exception))
        document = json.loads((self.work / "trust.json").read_text())
        self.assertEqual(len(document["keys"]), 2)
        self.assertEqual(
            [p.name for p in self.work.iterdir() if p.suffix == ".tmp"], []
        )

    def test_sign_rejects_directory_whose_mtime_changes_mid_scan(self):
        # Touching a file updates its mtime: the before/after identity
        # snapshots must disagree and force a status-2 failure.
        from release_seal import seal as seal_module

        target = self.delivery / "notes-touch.txt"
        target.write_bytes(b"x")
        original = seal_module.inventory
        calls = {"n": 0}

        def racing(directory):
            result = original(directory)
            calls["n"] += 1
            if calls["n"] == 1:
                target.write_bytes(b"xy")
            return result

        seal_module.inventory = racing
        try:
            with self.assertRaises(SealError):
                sign_directory(self.delivery, self.private, self.manifest)
        finally:
            seal_module.inventory = original
        self.assertFalse(self.manifest.exists())

    def test_stat_snapshot_detects_inode_replacement(self):
        other = self.work / "replacement-source"
        other.write_bytes(b"other")
        target = self.delivery / "docs" / "readme.txt"
        before = stat_snapshot(self.delivery)
        os.replace(other, target)
        after = stat_snapshot(self.delivery)
        self.assertNotEqual(before, after)

    def test_stat_snapshot_rejects_symlinks_and_special_files(self):
        target = self.work / "outside"
        target.write_bytes(b"x")
        link = self.delivery / "loop"
        link.symlink_to(target)
        try:
            with self.assertRaises(ValueError):
                stat_snapshot(self.delivery)
        finally:
            link.unlink()
        self.assertEqual(stat_snapshot(self.delivery)["."][0], "dir")


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

    def test_manifest_with_unknown_version_is_a_format_error(self):
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        document["version"] = 3
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SealError):
            self.verify()
        result = run_cli("verify", self.delivery, self.manifest, self.public)
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")

    def test_version_1_manifest_is_still_accepted(self):
        files = inventory(self.delivery)
        key = load_pem_public_key(self.public.read_bytes())
        private_key = load_pem_private_key(self.private.read_bytes(), password=None)
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
            "signature": base64.b64encode(private_key.sign(payload)).decode("ascii"),
        }
        self.manifest.write_text(json.dumps(v1), encoding="utf-8")
        self.assertEqual(self.verify(), {"valid": True})
        result = run_cli("verify", self.delivery, self.manifest, self.public)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"valid": True})

    def test_key_id_mismatch_fails_without_trusting_any_key(self):
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        other_dir = self.work / "other"
        other_dir.mkdir()
        other_private, other_public = write_keypair(other_dir)
        other_key = load_pem_private_key(
            other_private.read_bytes(), password=None
        )
        other_id = hashlib.sha256(
            load_pem_public_key(other_public.read_bytes()).public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
        ).hexdigest()
        document["key_id"] = other_id
        payload = json.dumps(
            {
                "version": 2,
                "algorithm": "Ed25519",
                "hash": "SHA-256",
                "key_id": other_id,
                "files": document["files"],
            },
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        document["signature"] = base64.b64encode(
            other_key.sign(payload)
        ).decode("ascii")
        # Signed by the other key but verified against the original key:
        # key_id mismatch alone must already force failure.
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        self.assertEqual(self.verify(), {
            "valid": False, "modified": [], "missing": [], "unexpected": [],
        })

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


class DemoTests(unittest.TestCase):
    def test_demo_signs_verifies_and_rejects_tampering(self):
        result = run_cli("demo")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"valid": true', result.stdout)
        self.assertIn('"valid": false', result.stdout)
        self.assertIn("private key has been removed", result.stdout)


if __name__ == "__main__":
    unittest.main()
