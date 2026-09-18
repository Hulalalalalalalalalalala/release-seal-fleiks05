import base64
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

from release_seal.policy import load_policy, verify_policy
from release_seal.seal import (
    SealError,
    canonical_payload,
    key_id_of,
    sign_multi_directory,
)
from release_seal.trust import import_key, revoke_key


def run_cli(*args) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "release_seal", *map(str, args)],
        capture_output=True, text=True,
    )


def write_keypair(work: Path, name: str):
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


class MultiTestCase(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.work = Path(self.workspace.name)
        self.delivery = make_delivery(self.work)
        self.manifest = self.work / "manifest.json"
        self.store = self.work / "trust.json"
        self.policy_path = self.work / "policy.json"
        self.keys = []
        self.privates = []
        self.key_ids = []
        for name in ("alpha", "beta", "gamma"):
            key, private, public = write_keypair(self.work, name)
            self.keys.append(key)
            self.privates.append(private)
            self.key_ids.append(key_id_of(key.public_key()))
            import_key(public, self.store)

    def write_policy(self, threshold=2, allowed=None, **extra):
        document = {
            "version": 1,
            "threshold": threshold,
            "allowed_key_ids": (
                list(self.key_ids) if allowed is None else list(allowed)
            ),
        }
        document.update(extra)
        self.policy_path.write_text(json.dumps(document), encoding="utf-8")
        return document

    def sign_multi(self, *privates, manifest=None):
        return sign_multi_directory(
            self.delivery,
            manifest or self.manifest,
            privates if privates else self.privates,
        )

    def verify_policy(self):
        return verify_policy(
            self.delivery, self.manifest, self.store, self.policy_path
        )


class SignMultiTests(MultiTestCase):
    def test_sign_multi_writes_sorted_version_3_manifest(self):
        document = self.sign_multi()
        self.assertEqual(document["version"], 3)
        self.assertEqual(document["algorithm"], "Ed25519")
        self.assertEqual(document["hash"], "SHA-256")
        self.assertNotIn("signature", document)
        self.assertNotIn("key_id", document)
        self.assertEqual(
            list(document["signatures"]), sorted(self.key_ids)
        )
        for signature in document["signatures"].values():
            self.assertEqual(len(base64.b64decode(signature, validate=True)), 64)
        on_disk = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(on_disk, document)

    def test_each_signature_covers_the_same_canonical_payload(self):
        document = self.sign_multi()
        payload = canonical_payload(3, None, document["files"])
        self.assertNotIn(b"signatures", payload)
        self.assertNotIn(b"key_id", payload)
        for key, key_id in zip(self.keys, self.key_ids):
            key.public_key().verify(
                base64.b64decode(document["signatures"][key_id]), payload
            )

    def test_sign_multi_cli(self):
        result = run_cli(
            "sign-multi", self.delivery, self.manifest, *self.privates
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["version"], 3)

    def test_sign_multi_rejects_duplicate_keys(self):
        with self.assertRaises(SealError):
            self.sign_multi(self.privates[0], self.privates[1], self.privates[0])
        self.assertFalse(self.manifest.exists())
        result = run_cli(
            "sign-multi",
            self.delivery,
            self.manifest,
            self.privates[0],
            self.privates[0],
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("duplicate", result.stderr)

    def test_sign_multi_rejects_empty_key_list(self):
        with self.assertRaises(SealError):
            sign_multi_directory(self.delivery, self.manifest, [])
        self.assertFalse(self.manifest.exists())
        result = run_cli("sign-multi", self.delivery, self.manifest)
        self.assertEqual(result.returncode, 2)

    def test_sign_multi_rejects_non_ed25519_key(self):
        rsa = self.work / "rsa.pem"
        rsa.write_bytes(
            generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
        )
        with self.assertRaises(SealError):
            self.sign_multi(self.privates[0], rsa)
        self.assertFalse(self.manifest.exists())
        self.assertEqual(
            [p.name for p in self.work.iterdir() if p.suffix == ".tmp"], []
        )

    def test_sign_multi_refuses_to_overwrite_manifest(self):
        self.sign_multi()
        original = self.manifest.read_bytes()
        with self.assertRaises(SealError):
            self.sign_multi()
        self.assertEqual(self.manifest.read_bytes(), original)

    def test_sign_multi_refuses_key_or_manifest_inside_delivery(self):
        with self.assertRaises(SealError):
            self.sign_multi(self.delivery / "inside.pem")
        with self.assertRaises(SealError):
            sign_multi_directory(
                self.delivery, self.delivery / "manifest.json", self.privates
            )

    def test_version_3_manifest_is_rejected_by_verify_and_verify_trusted(self):
        self.sign_multi()
        public = self.work / "alpha-public.pem"
        result = run_cli("verify", self.delivery, self.manifest, public)
        self.assertEqual(result.returncode, 2)
        result = run_cli(
            "verify-trusted", self.delivery, self.manifest, self.store
        )
        self.assertEqual(result.returncode, 2)


class LoadPolicyTests(MultiTestCase):
    def test_valid_policy_loads(self):
        self.write_policy(threshold=2)
        policy = load_policy(self.policy_path)
        self.assertEqual(policy["version"], 1)
        self.assertEqual(policy["threshold"], 2)
        self.assertEqual(policy["allowed_key_ids"], self.key_ids)

    def test_rejects_bad_version_threshold_and_key_ids(self):
        bad_documents = [
            {"version": 2},
            {"version": "1"},
            {"threshold": 0},
            {"threshold": -1},
            {"threshold": 1.5},
            {"threshold": True},
            {"threshold": 4},  # exceeds allowed_key_ids
            {"allowed_key_ids": []},
            {"allowed_key_ids": "not-a-list"},
            {"allowed_key_ids": ["not-a-key-id"]},
            {"allowed_key_ids": [self.key_ids[0], self.key_ids[0]]},
        ]
        for override in bad_documents:
            with self.subTest(override=override):
                self.write_policy(**override)
                with self.assertRaises(SealError):
                    load_policy(self.policy_path)

    def test_rejects_missing_and_extra_fields(self):
        self.policy_path.write_text(
            json.dumps({"version": 1, "threshold": 1}), encoding="utf-8"
        )
        with self.assertRaises(SealError):
            load_policy(self.policy_path)
        self.write_policy(kind="release-seal-policy")
        with self.assertRaises(SealError):
            load_policy(self.policy_path)

    def test_malformed_policy_is_status_2(self):
        self.policy_path.write_bytes(b"not json")
        with self.assertRaises(SealError):
            load_policy(self.policy_path)
        self.sign_multi()
        result = run_cli(
            "verify-policy",
            self.delivery,
            self.manifest,
            self.store,
            self.policy_path,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")


class VerifyPolicyTests(MultiTestCase):
    def setUp(self):
        super().setUp()
        self.sign_multi()

    def test_threshold_met_and_files_match(self):
        self.write_policy(threshold=2)
        result = self.verify_policy()
        self.assertEqual(result, {
            "valid": True,
            "threshold": 2,
            "verified": 3,
            "signatures": {key_id: "valid" for key_id in self.key_ids},
        })
        cli = run_cli(
            "verify-policy",
            self.delivery,
            self.manifest,
            self.store,
            self.policy_path,
        )
        self.assertEqual(cli.returncode, 0, cli.stderr)
        self.assertTrue(json.loads(cli.stdout)["valid"])

    def test_threshold_not_met(self):
        # Two allowed keys, but one is revoked: only one counts.
        revoke_key(self.store, self.key_ids[1], "compromised")
        self.write_policy(threshold=2, allowed=self.key_ids[:2])
        result = self.verify_policy()
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "threshold_not_met")
        self.assertEqual(result["verified"], 1)
        self.assertEqual(result["signatures"][self.key_ids[1]], "revoked")
        self.assertEqual(
            result["signatures"][self.key_ids[2]], "disallowed"
        )
        self.assertEqual(result["modified"], [])
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["unexpected"], [])
        cli = run_cli(
            "verify-policy",
            self.delivery,
            self.manifest,
            self.store,
            self.policy_path,
        )
        self.assertEqual(cli.returncode, 1)
        self.assertEqual(json.loads(cli.stdout)["reason"], "threshold_not_met")

    def test_statuses_are_labeled_and_sorted_by_key_id(self):
        # unknown: a fourth key never imported into the store signs too
        _, extra_private, _ = write_keypair(self.work, "extra")
        other_manifest = self.work / "other.json"
        sign_multi_directory(
            self.delivery, other_manifest, [*self.privates, extra_private]
        )
        # revoked: first key; invalid: corrupt the third signature
        revoke_key(self.store, self.key_ids[0], "compromised")
        document = json.loads(other_manifest.read_text(encoding="utf-8"))
        document["signatures"][self.key_ids[2]] = base64.b64encode(
            b"\x00" * 64
        ).decode("ascii")
        other_manifest.write_text(json.dumps(document), encoding="utf-8")
        self.write_policy(threshold=1)
        result = verify_policy(
            self.delivery, other_manifest, self.store, self.policy_path
        )
        self.assertEqual(result["signatures"][self.key_ids[0]], "revoked")
        self.assertEqual(result["signatures"][self.key_ids[1]], "valid")
        self.assertEqual(result["signatures"][self.key_ids[2]], "invalid")
        extra_id = key_id_of(
            load_pem_public_key(
                (self.work / "extra-public.pem").read_bytes()
            )
        )
        self.assertEqual(result["signatures"][extra_id], "unknown")
        self.assertEqual(list(result["signatures"]), sorted(result["signatures"]))
        self.assertEqual(result["verified"], 1)
        self.assertTrue(result["valid"])

    def test_disallowed_active_key_does_not_count(self):
        self.write_policy(threshold=2, allowed=self.key_ids[1:])
        result = self.verify_policy()
        self.assertEqual(result["signatures"][self.key_ids[0]], "disallowed")
        self.assertEqual(result["verified"], 2)
        self.assertTrue(result["valid"])

    def test_file_mismatch_after_threshold_met(self):
        (self.delivery / "docs" / "readme.txt").write_bytes(b"changed")
        (self.delivery / "extra.txt").write_bytes(b"extra")
        (self.delivery / "café.txt").unlink()
        self.write_policy(threshold=1)
        result = self.verify_policy()
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "file_mismatch")
        self.assertEqual(result["modified"], ["docs/readme.txt"])
        self.assertEqual(result["missing"], ["café.txt"])
        self.assertEqual(result["unexpected"], ["extra.txt"])
        cli = run_cli(
            "verify-policy",
            self.delivery,
            self.manifest,
            self.store,
            self.policy_path,
        )
        self.assertEqual(cli.returncode, 1)
        self.assertEqual(json.loads(cli.stdout)["reason"], "file_mismatch")

    def test_threshold_not_met_never_scans_directory(self):
        # A changed tree must not matter while the threshold is unmet.
        (self.delivery / "docs" / "readme.txt").write_bytes(b"changed")
        revoke_key(self.store, self.key_ids[1], "compromised")
        self.write_policy(threshold=2, allowed=self.key_ids[:2])
        result = self.verify_policy()
        self.assertEqual(result["reason"], "threshold_not_met")
        self.assertEqual(result["modified"], [])

    def test_malformed_manifest_and_store_are_status_2(self):
        self.write_policy(threshold=1)
        self.manifest.write_bytes(b"not json")
        with self.assertRaises(SealError):
            self.verify_policy()
        self.sign_multi(manifest=self.work / "fresh.json")
        self.manifest.write_bytes((self.work / "fresh.json").read_bytes())
        self.store.write_bytes(b"not json")
        with self.assertRaises(SealError):
            self.verify_policy()

    def test_policy_inside_delivery_is_rejected(self):
        self.write_policy(threshold=1)
        inside = self.delivery / "policy.json"
        with self.assertRaises(SealError):
            verify_policy(self.delivery, self.manifest, self.store, inside)

    def test_version_1_or_2_manifest_is_status_2(self):
        from release_seal.seal import sign_directory

        v2 = self.work / "v2.json"
        sign_directory(self.delivery, self.privates[0], v2)
        self.write_policy(threshold=1)
        with self.assertRaises(SealError):
            verify_policy(self.delivery, v2, self.store, self.policy_path)
        result = run_cli(
            "verify-policy", self.delivery, v2, self.store, self.policy_path
        )
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
