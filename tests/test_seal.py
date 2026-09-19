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


def _certificate_pem():
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
    from cryptography.x509.oid import NameOID

    rsa = generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(rsa.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .sign(rsa, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


class ForbiddenContentTests(SealTestCase):
    """Content (not extension/name) classification inside a delivery tree."""

    def place(self, name, data):
        target = self.delivery / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            target.write_text(data, encoding="utf-8")
        else:
            target.write_bytes(data)
        return target

    def assertRefused(self, name, data):
        target = self.place(name, data)
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, self.manifest)
        target.unlink()

    def assertDeliverable(self, name, data):
        self.place(name, data)
        document = sign_directory(self.delivery, self.private, self.manifest)
        paths = [record["path"] for record in document["files"]]
        self.assertIn(name, paths)
        self.manifest.unlink()

    def test_pem_keys_of_any_algorithm_are_rejected_whatever_the_name(self):
        from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP256R1,
            generate_private_key as generate_ec,
        )
        from cryptography.hazmat.primitives.serialization import (
            PrivateFormat,
            PublicFormat,
        )

        rsa = generate_private_key(public_exponent=65537, key_size=2048)
        ec = generate_ec(SECP256R1())
        cases = {
            "rsa-private.bin": rsa.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            ),
            "nested/rsa-public.dat": rsa.public_key().public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            ),
            "rsa-pkcs1-public.txt": rsa.public_key().public_bytes(
                Encoding.PEM, PublicFormat.PKCS1
            ),
            "ec-private": ec.private_bytes(
                Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
            ),
            "payload.txt": self.private.read_bytes(),
            "bundle.bak": self.public.read_bytes(),
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                target = self.place(name, data)
                with self.assertRaises(SealError):
                    sign_directory(self.delivery, self.private, self.manifest)
                target.unlink()

    def test_encrypted_pem_private_keys_are_rejected(self):
        from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
        from cryptography.hazmat.primitives.serialization import (
            BestAvailableEncryption,
            PrivateFormat,
        )

        rsa = generate_private_key(public_exponent=65537, key_size=2048)
        for fmt in (PrivateFormat.PKCS8, PrivateFormat.TraditionalOpenSSL):
            encrypted = rsa.private_bytes(
                Encoding.PEM, fmt, BestAvailableEncryption(b"password"),
            )
            with self.subTest(fmt=fmt):
                target = self.place("locked.key", encrypted)
                with self.assertRaises(SealError):
                    sign_directory(self.delivery, self.private, self.manifest)
                target.unlink()

    def test_certificates_and_non_key_pem_are_deliverable(self):
        self.assertDeliverable("cert.pem", _certificate_pem())
        self.assertDeliverable("cert-as-text.txt", _certificate_pem())
        self.assertDeliverable("notes.pem", b"not a key at all\n")
        self.assertDeliverable(
            "fake.pem",
            b"-----BEGIN MADE UP THING-----\nAAAA\n-----END MADE UP THING-----\n",
        )
        self.assertDeliverable(
            "garbage-armored.pem",
            b"-----BEGIN PUBLIC KEY-----\n@@@@bad@@@@\n"
            b"-----END PUBLIC KEY-----\n",
        )

    def test_der_openssh_and_pkcs12_are_not_checked(self):
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography.x509.oid import NameOID

        ed_public_der = load_pem_public_key(self.public.read_bytes()).public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        ed_private_der = load_pem_private_key(
            self.private.read_bytes(), password=None
        ).private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        openssh_private = load_pem_private_key(
            self.private.read_bytes(), password=None
        ).private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
        rsa = generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(rsa.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
            .sign(rsa, hashes.SHA256())
        )
        p12 = pkcs12.serialize_key_and_certificates(
            b"n", rsa, cert, None,
            serialization.BestAvailableEncryption(b"pw"),
        )
        for name_, data in (
            ("pub.der", ed_public_der),
            ("priv.der", ed_private_der),
            ("id_openssh", openssh_private),
            ("bundle.p12", p12),
        ):
            with self.subTest(name=name_):
                self.assertDeliverable(name_, data)

    def test_marker_and_json_are_found_past_large_preamble(self):
        # The streaming pre-scan must catch a PEM marker or JSON object
        # even when it starts far into the file / straddles a chunk edge.
        chunk = 1024 * 1024
        for offset in range(-12, 1):
            target = self.delivery / f"late-{offset}"
            target.write_bytes(b"x" * (chunk + offset) + self.private.read_bytes())
            with self.assertRaises(SealError):
                sign_directory(self.delivery, self.private, self.manifest)
            target.unlink()
        policy = json.dumps({
            "version": 1, "threshold": 1, "allowed_key_ids": ["a" * 64],
        }).encode("utf-8")
        target = self.directory_late_json(policy)
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.private, self.manifest)
        target.unlink()
        # A large ordinary binary (no marker, not an object) delivers.
        big = self.delivery / "big.bin"
        big.write_bytes(b"\x00" * (3 * chunk))
        document = sign_directory(self.delivery, self.private, self.manifest)
        self.assertIn("big.bin", [r["path"] for r in document["files"]])
        self.manifest.unlink()
        big.unlink()

    def directory_late_json(self, payload: bytes) -> Path:
        chunk = 1024 * 1024
        target = self.delivery / "late.json"
        target.write_bytes(b" " * (2 * chunk + 3) + payload)
        return target

    def test_real_manifests_stores_and_policies_rejected_any_extension(self):
        sig = base64.b64encode(b"\x00" * 64).decode("ascii")
        cases = {
            "m-v1.log": json.dumps({
                "version": 1, "algorithm": "Ed25519", "hash": "SHA-256",
                "files": [], "signature": sig,
            }),
            "m-v2.txt": json.dumps({
                "version": 2, "algorithm": "Ed25519", "hash": "SHA-256",
                "key_id": "a" * 64, "files": [], "signature": sig,
            }),
            "m-v3.cfg": json.dumps({
                "version": 3, "algorithm": "Ed25519", "hash": "SHA-256",
                "files": [], "signatures": {"a" * 64: sig},
            }),
            "store": json.dumps({
                "kind": "release-seal-trust-store", "version": 1,
                "algorithm": "Ed25519", "keys": {},
            }),
            "policy.blob": json.dumps({
                "version": 1, "threshold": 1, "allowed_key_ids": ["a" * 64],
            }),
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                self.assertRefused(name, data)

    def test_extension_does_not_matter_for_similar_json(self):
        # Shape-similar but invalid documents are deliverable under ANY
        # extension, including .json.
        sig = base64.b64encode(b"\x00" * 64).decode("ascii")
        cases = {
            "a.json": json.dumps({
                "version": 1, "algorithm": "Ed25519", "hash": "SHA-256",
                "files": [], "signature": "short",
            }),
            "b.json": json.dumps({
                "version": 9, "algorithm": "Ed25519", "hash": "SHA-256",
                "files": [], "signature": sig,
            }),
            "c.json": json.dumps({
                "version": 1, "algorithm": "RSA", "hash": "SHA-256",
                "files": [], "signature": sig,
            }),
            "d.json": json.dumps({
                "kind": "something-else", "version": 1,
                "algorithm": "Ed25519", "keys": {},
            }),
            "e.json": json.dumps({
                "kind": "release-seal-trust-store", "version": 2,
                "algorithm": "Ed25519", "keys": {},
            }),
            "f.json": json.dumps({"version": 1, "threshold": 0,
                                  "allowed_key_ids": ["a" * 64]}),
            "g.json": json.dumps({"version": 1, "threshold": 1,
                                  "allowed_key_ids": ["a" * 64], "x": 1}),
            "h.policy": json.dumps({"version": 2, "threshold": 1,
                                    "allowed_key_ids": ["a" * 64]}),
            "i.txt": json.dumps([1, 2, 3]),
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                self.assertDeliverable(name, data)


if __name__ == "__main__":
    unittest.main()
