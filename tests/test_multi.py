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
)

from release_seal.seal import (
    DurabilityError,
    SealError,
    canonical_payload,
    key_id_of,
    sign_directory,
    sign_multi,
)
from release_seal.trust import import_key, revoke_key, verify_trusted
from release_seal.policy import load_policy, verify_policy


def run_cli(*args) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "release_seal", *map(str, args)],
        capture_output=True, text=True,
    )


def make_key(work: Path, name: str):
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


def write_policy(path: Path, threshold: int, allowed: list[str]) -> dict:
    document = {
        "kind": "release-seal-policy",
        "version": 1,
        "threshold": threshold,
        "allowed_key_ids": allowed,
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    return document


def b64sig(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


class MultiTestCase(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.work = Path(self.workspace.name)
        self.delivery = make_delivery(self.work)
        self.keys = {}
        self.privates = {}
        self.publics = {}
        self.ids = {}
        for name in ("a", "b", "c", "d", "e"):
            key, private, public = make_key(self.work, name)
            self.keys[name] = key
            self.privates[name] = private
            self.publics[name] = public
            self.ids[name] = key_id_of(key.public_key())
        self.manifest = self.work / "manifest.json"
        self.store = self.work / "trust.json"
        self.policy = self.work / "policy.json"

    def sign(self, names, target=None):
        return sign_multi(
            self.delivery,
            target or self.manifest,
            [self.privates[name] for name in names],
        )

    def import_keys(self, names):
        for name in names:
            import_key(self.publics[name], self.store)

    def no_temp_residue(self):
        self.assertEqual(
            [p.name for p in self.work.iterdir() if p.name.endswith(".tmp")],
            [],
        )


class SignMultiTests(MultiTestCase):
    def test_version_3_manifest_has_sorted_signatures_over_full_body(self):
        document = self.sign(["c", "a", "b"])  # unsorted on purpose
        self.assertEqual(document["version"], 3)
        self.assertEqual(document["algorithm"], "Ed25519")
        self.assertEqual(document["hash"], "SHA-256")
        self.assertEqual(
            set(document),
            {"version", "algorithm", "hash", "files", "signatures"},
        )
        self.assertEqual(
            list(document["signatures"]),
            sorted(self.ids[n] for n in ("a", "b", "c")),
        )
        # Signatures cover the complete normalized manifest EXCEPT the
        # signatures object: version/algorithm/hash/files only.
        expected_payload = json.dumps(
            {
                "version": 3,
                "algorithm": "Ed25519",
                "hash": "SHA-256",
                "files": document["files"],
            },
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(canonical_payload(3, None, document["files"]),
                         expected_payload)
        for name in ("a", "b", "c"):
            raw = base64.b64decode(document["signatures"][self.ids[name]],
                                   validate=True)
            self.assertEqual(len(raw), 64)
            self.keys[name].public_key().verify(raw, expected_payload)
        on_disk = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(on_disk, document)

    def test_cli_sign_multi(self):
        result = run_cli(
            "sign-multi", self.delivery, self.manifest,
            self.privates["a"], self.privates["b"],
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual(document["version"], 3)
        self.assertEqual(len(document["signatures"]), 2)

    def test_single_key_sign_multi_then_policy_verify(self):
        self.sign(["a"])
        self.import_keys(["a"])
        write_policy(self.policy, 1, [self.ids["a"]])
        result = verify_policy(self.delivery, self.manifest, self.store, self.policy)
        self.assertTrue(result["valid"])
        self.assertEqual(result["matched"], 1)

    def test_duplicate_key_is_rejected_with_residue_cleanup(self):
        with self.assertRaises(SealError):
            sign_multi(
                self.delivery, self.manifest,
                [self.privates["a"], self.privates["a"]],
            )
        # Same key material in two different files is still a duplicate.
        copy = self.work / "a-copy.pem"
        copy.write_bytes(self.privates["a"].read_bytes())
        with self.assertRaises(SealError):
            sign_multi(
                self.delivery, self.manifest,
                [self.privates["a"], copy],
            )
        self.assertFalse(self.manifest.exists())
        self.no_temp_residue()

    def test_wrong_key_type_is_rejected_with_residue_cleanup(self):
        rsa = self.work / "rsa.pem"
        rsa.write_bytes(
            generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
        )
        with self.assertRaises(SealError):
            sign_multi(
                self.delivery, self.manifest,
                [self.privates["a"], rsa],
            )
        self.assertFalse(self.manifest.exists())
        self.no_temp_residue()

    def test_missing_private_key_is_status_2(self):
        result = run_cli(
            "sign-multi", self.delivery, self.manifest,
            self.privates["a"], self.work / "missing.pem",
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")
        self.assertFalse(self.manifest.exists())

    def test_cli_requires_at_least_one_key(self):
        result = run_cli("sign-multi", self.delivery, self.manifest)
        self.assertEqual(result.returncode, 2)

    def test_refuses_keys_and_manifest_inside_delivery(self):
        inside_private = self.delivery / "private.pem"
        inside_private.write_bytes(self.privates["a"].read_bytes())
        with self.assertRaises(SealError):
            self.sign(["a"])
        inside_private.unlink()
        with self.assertRaises(SealError):
            sign_multi(
                self.delivery, self.delivery / "manifest.json",
                [self.privates["a"]],
            )

    def test_never_overwrites_existing_manifest(self):
        self.sign(["a"])
        original = self.manifest.read_bytes()
        with self.assertRaises(SealError):
            self.sign(["b"])
        self.assertEqual(self.manifest.read_bytes(), original)
        self.no_temp_residue()


class VerifyPolicyTests(MultiTestCase):
    def setUp(self):
        super().setUp()
        # Five signers: a/b/c allowed, d active in store but not allowed,
        # e unknown to the store. c is revoked after signing.
        self.sign(["a", "b", "c", "d", "e"])
        self.import_keys(["a", "b", "c", "d"])
        revoke_key(self.store, self.ids["c"], "compromised")
        self.allowed = [self.ids[n] for n in ("a", "b", "c")]

    def corrupt_signature(self, name):
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        document["signatures"][self.ids[name]] = b64sig(b"\x00" * 64)
        self.manifest.write_text(json.dumps(document), encoding="utf-8")

    def verify(self):
        return verify_policy(self.delivery, self.manifest, self.store, self.policy)

    def test_threshold_met_is_valid_with_all_statuses_classified(self):
        write_policy(self.policy, 1, self.allowed)
        result = self.verify()
        self.assertTrue(result["valid"])
        self.assertEqual(result["threshold"], 1)
        # a and b are active, allowed and carry valid signatures.
        self.assertEqual(result["matched"], 2)
        self.assertEqual(
            result["matched_key_ids"],
            sorted([self.ids["a"], self.ids["b"]]),
        )
        self.assertEqual(result["keys"][self.ids["a"]], "valid")
        self.assertEqual(result["keys"][self.ids["b"]], "valid")
        self.assertEqual(result["keys"][self.ids["c"]], "revoked")
        self.assertEqual(result["keys"][self.ids["d"]], "disallowed")
        self.assertEqual(result["keys"][self.ids["e"]], "unknown")
        # keys are reported sorted by key id
        self.assertEqual(list(result["keys"]), sorted(result["keys"]))

    def test_threshold_not_met_reports_1_and_skips_inventory(self):
        write_policy(self.policy, 3, self.allowed)
        # Make the directory diverge: below threshold it must never be
        # inventoried, so the lists stay empty.
        (self.delivery / "extra.txt").write_bytes(b"extra")
        result = self.verify()
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "threshold_not_met")
        self.assertEqual(result["threshold"], 3)
        self.assertEqual(result["matched"], 2)
        self.assertEqual(
            result["matched_key_ids"],
            sorted([self.ids["a"], self.ids["b"]]),
        )
        self.assertEqual(result["modified"], [])
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["unexpected"], [])
        cli = run_cli(
            "verify-policy", self.delivery, self.manifest, self.store, self.policy
        )
        self.assertEqual(cli.returncode, 1)
        report = json.loads(cli.stdout)
        self.assertFalse(report["valid"])
        self.assertEqual(report["reason"], "threshold_not_met")

    def test_invalid_signature_is_classified_invalid(self):
        self.corrupt_signature("b")
        write_policy(self.policy, 3, self.allowed)
        result = self.verify()
        self.assertEqual(result["reason"], "threshold_not_met")
        self.assertEqual(result["keys"][self.ids["b"]], "invalid")
        self.assertEqual(result["matched"], 1)

    def test_revoked_allowed_signer_counts_as_revoked(self):
        write_policy(self.policy, 3, self.allowed)
        result = self.verify()
        self.assertEqual(result["keys"][self.ids["c"]], "revoked")
        self.assertNotIn(self.ids["c"], result["matched_key_ids"])

    def test_revoked_takes_precedence_over_disallowed(self):
        # c is revoked; a policy that does not even list it must still
        # report revoked rather than disallowed.
        write_policy(self.policy, 1, [self.ids["a"]])
        result = self.verify()
        self.assertEqual(result["keys"][self.ids["c"]], "revoked")

    def test_threshold_exactly_met_passes_other_signers_irrelevant(self):
        # Sign with a and b only, both allowed and active.
        self.manifest.unlink()
        self.sign(["a", "b"])
        write_policy(self.policy, 2, self.allowed)
        result = self.verify()
        self.assertTrue(result["valid"])
        self.assertEqual(result["matched"], 2)
        self.assertEqual(
            result["matched_key_ids"],
            sorted([self.ids["a"], self.ids["b"]]),
        )

    def test_file_mismatch_only_after_threshold_met(self):
        write_policy(self.policy, 1, self.allowed)
        (self.delivery / "docs" / "readme.txt").write_bytes(b"changed")
        (self.delivery / "extra.txt").write_bytes(b"extra")
        result = self.verify()
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "file_mismatch")
        self.assertEqual(result["matched"], 2)
        self.assertEqual(result["modified"], ["docs/readme.txt"])
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["unexpected"], ["extra.txt"])
        cli = run_cli(
            "verify-policy", self.delivery, self.manifest, self.store, self.policy
        )
        self.assertEqual(cli.returncode, 1)
        self.assertEqual(json.loads(cli.stdout)["reason"], "file_mismatch")

    def test_threshold_met_with_one_invalid_other_signer(self):
        self.corrupt_signature("b")
        write_policy(self.policy, 1, self.allowed)
        result = self.verify()
        self.assertTrue(result["valid"])
        self.assertEqual(result["matched"], 1)
        self.assertEqual(result["keys"][self.ids["b"]], "invalid")

    def test_policy_file_order_does_not_change_report_order(self):
        write_policy(self.policy, 1, list(reversed(self.allowed)))
        result = self.verify()
        self.assertTrue(result["valid"])
        self.assertEqual(list(result["keys"]), sorted(result["keys"]))

    def test_allowed_keys_absent_from_manifest_do_not_count(self):
        # Re-sign with a alone; b is allowed and active in the store but
        # carries no signature, so threshold 2 is not reached.
        self.manifest.unlink()
        self.sign(["a"])
        write_policy(self.policy, 2, self.allowed)
        result = self.verify()
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "threshold_not_met")
        self.assertEqual(result["matched"], 1)
        self.assertEqual(list(result["keys"]), [self.ids["a"]])


class PolicyValidationTests(MultiTestCase):
    def test_policy_must_be_well_formed(self):
        self.import_keys(["a"])
        self.sign(["a"])
        good = {
            "kind": "release-seal-policy",
            "version": 1,
            "threshold": 1,
            "allowed_key_ids": [self.ids["a"]],
        }
        bad_documents = [
            b"not json",
            json.dumps([]).encode(),
            json.dumps({**good, "extra": 1}).encode(),
            json.dumps({k: v for k, v in good.items() if k != "kind"}).encode(),
            json.dumps({**good, "kind": "something-else"}).encode(),
            json.dumps({**good, "version": 2}).encode(),
            json.dumps({**good, "version": "1"}).encode(),
            json.dumps({**good, "threshold": 0}).encode(),
            json.dumps({**good, "threshold": -1}).encode(),
            json.dumps({**good, "threshold": True}).encode(),
            json.dumps({**good, "threshold": 1.5}).encode(),
            json.dumps({**good, "threshold": "2"}).encode(),
            json.dumps({**good, "allowed_key_ids": []}).encode(),
            json.dumps({**good, "allowed_key_ids": "x"}).encode(),
            json.dumps({**good, "allowed_key_ids": ["deadbeef"]}).encode(),
            json.dumps(
                {**good, "allowed_key_ids": [self.ids["a"], self.ids["a"]]}
            ).encode(),
            json.dumps(
                {**good, "threshold": 2,
                 "allowed_key_ids": [self.ids["a"]]}
            ).encode(),
        ]
        for index, raw in enumerate(bad_documents):
            with self.subTest(index=index):
                self.policy.write_bytes(raw)
                with self.assertRaises(SealError):
                    load_policy(self.policy)
                with self.assertRaises(SealError):
                    verify_policy(
                        self.delivery, self.manifest, self.store, self.policy
                    )
                cli = run_cli(
                    "verify-policy", self.delivery, self.manifest,
                    self.store, self.policy,
                )
                self.assertEqual(cli.returncode, 2, cli.stdout)

    def test_load_policy_accepts_the_documented_shape(self):
        write_policy(self.policy, 1, [self.ids["a"]])
        policy = load_policy(self.policy)
        self.assertEqual(policy["threshold"], 1)

    def test_missing_inputs_are_status_2(self):
        write_policy(self.policy, 1, [self.ids["a"]])
        for manifest, store, policy in [
            (self.work / "missing.json", self.store, self.policy),
            (self.manifest, self.work / "missing-store.json", self.policy),
            (self.manifest, self.store, self.work / "missing-policy.json"),
        ]:
            result = run_cli(
                "verify-policy", self.delivery, manifest, store, policy
            )
            self.assertEqual(result.returncode, 2, result.stdout)

    def test_v1_v2_manifests_are_format_errors_for_verify_policy(self):
        self.import_keys(["a"])
        write_policy(self.policy, 1, [self.ids["a"]])
        # A version 2 manifest from the ordinary sign command.
        sign_directory(self.delivery, self.privates["a"], self.manifest)
        with self.assertRaises(SealError):
            verify_policy(self.delivery, self.manifest, self.store, self.policy)
        self.assertEqual(
            run_cli(
                "verify-policy", self.delivery, self.manifest,
                self.store, self.policy,
            ).returncode,
            2,
        )

    def test_v3_manifest_is_rejected_by_single_signer_commands(self):
        self.sign(["a"])
        result = run_cli(
            "verify", self.delivery, self.manifest, self.publics["a"]
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        self.import_keys(["a"])
        with self.assertRaises(SealError):
            verify_trusted(self.delivery, self.manifest, self.store)
        result = run_cli(
            "verify-trusted", self.delivery, self.manifest, self.store
        )
        self.assertEqual(result.returncode, 2, result.stdout)

    def test_malformed_v3_manifests_are_status_2(self):
        self.import_keys(["a"])
        write_policy(self.policy, 1, [self.ids["a"]])
        good = self.sign(["a"])
        variants = [
            {**good, "version": 4},
            {**good, "extra": 1},
            {k: v for k, v in good.items() if k != "algorithm"},
            {**good, "algorithm": "RSA"},
            {**good, "hash": "SHA-512"},
            {**good, "signatures": {}},
            {**good, "signatures": {"deadbeef": good["signatures"][self.ids["a"]]}},
        ]
        for index, document in enumerate(variants):
            with self.subTest(index=index):
                self.manifest.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(SealError):
                    verify_policy(
                        self.delivery, self.manifest, self.store, self.policy
                    )
        bad_sig = dict(good)
        bad_sig["signatures"] = {self.ids["a"]: "not base64!!"}
        self.manifest.write_text(json.dumps(bad_sig), encoding="utf-8")
        with self.assertRaises(SealError):
            verify_policy(self.delivery, self.manifest, self.store, self.policy)

    def test_refuses_manifest_store_or_policy_inside_delivery(self):
        self.sign(["a"])
        self.import_keys(["a"])
        write_policy(self.policy, 1, [self.ids["a"]])
        with self.assertRaises(SealError):
            verify_policy(
                self.delivery, self.delivery / "m.json", self.store, self.policy
            )
        with self.assertRaises(SealError):
            verify_policy(
                self.delivery, self.manifest, self.delivery / "s.json", self.policy
            )
        with self.assertRaises(SealError):
            verify_policy(
                self.delivery, self.manifest, self.store, self.delivery / "p.json"
            )


class ContentDetectionTests(MultiTestCase):
    def sign_expecting_failure(self):
        with self.assertRaises(SealError):
            sign_multi(
                self.delivery, self.work / "out.json", [self.privates["a"]]
            )
        self.assertFalse((self.work / "out.json").exists())

    def test_plain_pem_named_payload_is_deliverable(self):
        (self.delivery / "notes.pem").write_bytes(
            b"this is not a key, just a file called notes.pem\n"
        )
        document = self.sign(["a"])
        self.assertIn("notes.pem", [r["path"] for r in document["files"]])

    def test_plain_json_config_is_deliverable(self):
        config = self.delivery / "config.json"
        config.write_text(json.dumps({"setting": True, "n": 3}), encoding="utf-8")
        document = self.sign(["a"])
        self.assertIn("config.json", [r["path"] for r in document["files"]])

    def test_real_public_key_with_any_suffix_is_rejected(self):
        (self.delivery / "public.txt").write_bytes(
            self.publics["a"].read_bytes()
        )
        self.sign_expecting_failure()

    def test_real_private_key_with_any_suffix_is_rejected(self):
        (self.delivery / "secret.dat").write_bytes(
            self.privates["a"].read_bytes()
        )
        self.sign_expecting_failure()

    def test_rsa_public_key_pem_is_rejected(self):
        rsa_public = self.work / "rsa-public.pem"
        rsa_public.write_bytes(
            generate_private_key(public_exponent=65537, key_size=2048)
            .public_key()
            .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )
        (self.delivery / "rsa.pem").write_bytes(rsa_public.read_bytes())
        self.sign_expecting_failure()

    def test_pkcs1_private_key_pem_is_rejected(self):
        rsa_private = self.work / "rsa-private.pem"
        rsa_private.write_bytes(
            generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
                Encoding.PEM,
                PrivateFormat.TraditionalOpenSSL,
                NoEncryption(),
            )
        )
        (self.delivery / "legacy.pem").write_bytes(rsa_private.read_bytes())
        self.sign_expecting_failure()

    def test_v3_manifest_json_in_tree_is_rejected(self):
        self.sign(["a"])
        (self.delivery / "copy.json").write_bytes(self.manifest.read_bytes())
        self.sign_expecting_failure()

    def test_trust_store_json_in_tree_is_rejected(self):
        self.import_keys(["a"])
        (self.delivery / "store.json").write_bytes(self.store.read_bytes())
        self.sign_expecting_failure()

    def test_policy_json_in_tree_is_rejected(self):
        write_policy(
            self.delivery / "policy.json", 1, [self.ids["a"]]
        )
        self.sign_expecting_failure()

    def test_structured_manifest_without_json_suffix_is_rejected(self):
        self.sign(["a"])
        (self.delivery / "manifest.backup").write_bytes(self.manifest.read_bytes())
        self.sign_expecting_failure()

    def test_ordinary_single_sign_uses_same_content_rules(self):
        (self.delivery / "notes.pem").write_bytes(b"plain text, allowed\n")
        sign_directory(self.delivery, self.privates["a"], self.work / "v2.json")
        (self.delivery / "real.txt").write_bytes(self.publics["b"].read_bytes())
        with self.assertRaises(SealError):
            sign_directory(self.delivery, self.privates["a"], self.work / "v2b.json")


class DurabilityTests(MultiTestCase):
    def test_sync_failure_after_publish_keeps_complete_new_manifest(self):
        from release_seal import seal as seal_module

        original = seal_module._sync_directory

        def failing_sync(directory):
            raise OSError(28, "synthetic ENOSPC")

        seal_module._sync_directory = failing_sync
        try:
            with self.assertRaises(DurabilityError):
                self.sign(["a", "b"])
        finally:
            seal_module._sync_directory = original
        # New target complete and readable; temp name cleaned up.
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(document["version"], 3)
        self.no_temp_residue()
        # The kept target now blocks republishing (old semantics hold).
        with self.assertRaises(SealError):
            self.sign(["a"])

    def test_sync_failure_after_replace_keeps_complete_store(self):
        from release_seal import seal as seal_module

        original = seal_module._sync_directory

        def failing_sync(directory):
            raise OSError(5, "synthetic EIO")

        seal_module._sync_directory = failing_sync
        try:
            with self.assertRaises(DurabilityError):
                import_key(self.publics["a"], self.store)
        finally:
            seal_module._sync_directory = original
        document = json.loads(self.store.read_text(encoding="utf-8"))
        self.assertIn(self.ids["a"], document["keys"])
        self.no_temp_residue()

    def test_durability_failure_is_status_2_on_the_function_boundary(self):
        self.assertTrue(issubclass(DurabilityError, SealError))


if __name__ == "__main__":
    unittest.main()
