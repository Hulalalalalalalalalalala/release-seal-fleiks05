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
)

from release_seal.batch import verify_batch
from release_seal.seal import (
    SealError,
    key_id_of,
    load_public_key,
    sign_directory,
    sign_multi_directory,
)
from release_seal.trust import import_key


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
    return private, public


def make_delivery(root: Path, name: str = "delivery") -> Path:
    delivery = root / name
    (delivery / "docs").mkdir(parents=True)
    (delivery / "docs" / "readme.txt").write_bytes(b"hello")
    (delivery / "notes.txt").write_bytes(b"notes\n")
    return delivery


class BatchTestCase(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.work = Path(self.workspace.name)
        self.delivery = make_delivery(self.work)
        self.private, self.public = write_keypair(self.work, "a")
        self.manifest = self.work / "manifest.json"
        sign_directory(self.delivery, self.private, self.manifest)
        self.store = self.work / "trust.json"
        import_key(self.public, self.store)
        self.other_private, self.other_public = write_keypair(self.work, "b")
        import_key(self.other_public, self.store)
        self.multi_manifest = self.work / "multi.json"
        sign_multi_directory(
            self.delivery, self.multi_manifest, [self.private, self.other_private]
        )
        self.policy = self.work / "policy.json"
        key_ids = [
            key_id_of(load_public_key(public))
            for public in (self.public, self.other_public)
        ]
        self.policy.write_text(
            json.dumps({
                "version": 1,
                "threshold": 2,
                "allowed_key_ids": key_ids,
            }),
            encoding="utf-8",
        )
        self.batch = self.work / "batch.json"

    def write_batch(self, items) -> Path:
        self.batch.write_text(json.dumps(items), encoding="utf-8")
        return self.batch

    def all_passing_items(self):
        return [
            {
                "id": "plain",
                "command": "verify",
                "args": ["delivery", "manifest.json", "a-public.pem"],
            },
            {
                "id": "trusted",
                "command": "verify-trusted",
                "args": ["delivery", "manifest.json", "trust.json"],
            },
            {
                "id": "policy",
                "command": "verify-policy",
                "args": ["delivery", "multi.json", "trust.json", "policy.json"],
            },
        ]


class BatchStructureTests(BatchTestCase):
    def expect_structure_error(self, batch):
        if not isinstance(batch, bytes):
            batch = json.dumps(batch).encode("utf-8")
        self.batch.write_bytes(batch)
        with self.assertRaises(SealError):
            verify_batch(self.batch)
        result = run_cli("verify-batch", self.batch)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertNotEqual(result.stderr, "")

    def test_batch_must_be_a_json_array(self):
        self.expect_structure_error(b"not json")
        self.expect_structure_error({"command": "verify"})
        self.expect_structure_error([{"id": "x", "command": "verify"}])
        self.expect_structure_error(
            [{"id": "x", "command": "verify", "args": ["a", "b", "c"], "extra": 1}]
        )

    def test_item_ids_must_be_unique_non_empty_strings(self):
        item = {"id": "x", "command": "verify", "args": ["a", "b", "c"]}
        self.expect_structure_error([item, dict(item)])
        self.expect_structure_error([dict(item, id="")])
        self.expect_structure_error([dict(item, id=7)])

    def test_command_and_args_are_checked(self):
        item = {"id": "x", "command": "verify", "args": ["a", "b", "c"]}
        self.expect_structure_error([dict(item, command="sign")])
        self.expect_structure_error([dict(item, args=["a", "b"])])
        self.expect_structure_error([dict(item, args="abc")])
        self.expect_structure_error([dict(item, args=["a", "b", 3])])
        policy_item = {
            "id": "p",
            "command": "verify-policy",
            "args": ["a", "b", "c"],
        }
        self.expect_structure_error([policy_item])

    def test_missing_batch_file_is_a_structure_error(self):
        result = run_cli("verify-batch", self.work / "missing.json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertNotEqual(result.stderr, "")


class BatchRunTests(BatchTestCase):
    def test_all_passing_batch(self):
        self.write_batch(self.all_passing_items())
        report, code = verify_batch(self.batch)
        self.assertEqual(code, 0)
        self.assertEqual(
            report["summary"],
            {"total": 3, "passed": 3, "failed": 0, "errors": 0},
        )
        self.assertTrue(report["valid"])
        self.assertEqual(report["version"], 1)
        self.assertEqual(
            [entry["id"] for entry in report["results"]],
            ["plain", "trusted", "policy"],
        )
        for entry in report["results"]:
            self.assertEqual(entry["code"], 0)
            self.assertTrue(entry["result"]["valid"])
        result = run_cli("verify-batch", self.batch)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), report)

    def test_failed_item_yields_code_1(self):
        (self.delivery / "notes.txt").write_bytes(b"tampered")
        items = self.all_passing_items()
        self.write_batch(items)
        report, code = verify_batch(self.batch)
        self.assertEqual(code, 1)
        self.assertFalse(report["valid"])
        self.assertEqual(
            report["summary"],
            {"total": 3, "passed": 0, "failed": 3, "errors": 0},
        )
        first = report["results"][0]
        self.assertEqual(first["code"], 1)
        self.assertEqual(first["result"]["modified"], ["notes.txt"])

    def test_error_item_yields_code_2_without_stderr(self):
        items = self.all_passing_items()
        items[1] = {
            "id": "broken",
            "command": "verify",
            "args": ["delivery", "missing.json", "a-public.pem"],
        }
        self.write_batch(items)
        report, code = verify_batch(self.batch)
        self.assertEqual(code, 2)
        self.assertFalse(report["valid"])
        self.assertEqual(
            report["summary"],
            {"total": 3, "passed": 2, "failed": 0, "errors": 1},
        )
        broken = report["results"][1]
        self.assertEqual(broken["id"], "broken")
        self.assertEqual(broken["code"], 2)
        self.assertTrue(broken["error"])
        self.assertNotIn("result", broken)
        result = run_cli("verify-batch", self.batch)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout)["summary"]["errors"], 1)

    def test_error_dominates_failure_in_exit_code(self):
        (self.delivery / "notes.txt").write_bytes(b"tampered")
        items = self.all_passing_items()[:1]
        items.append({
            "id": "broken",
            "command": "verify",
            "args": ["delivery", "missing.json", "a-public.pem"],
        })
        self.write_batch(items)
        report, code = verify_batch(self.batch)
        self.assertEqual(code, 2)
        self.assertEqual(report["summary"]["failed"], 1)
        self.assertEqual(report["summary"]["errors"], 1)

    def test_batch_must_stay_outside_the_delivery_tree(self):
        inside = self.delivery / "batch.json"
        inside.write_text(
            json.dumps([{
                "id": "x",
                "command": "verify",
                "args": [".", "../manifest.json", "../a-public.pem"],
            }]),
            encoding="utf-8",
        )
        report, code = verify_batch(inside)
        self.assertEqual(code, 2)
        entry = report["results"][0]
        self.assertEqual(entry["code"], 2)
        self.assertIn("outside", entry["error"])

    def test_relative_paths_resolve_against_the_batch_directory(self):
        nested = self.work / "nested" / "deeper"
        nested.mkdir(parents=True)
        batch = nested / "batch.json"
        batch.write_text(
            json.dumps([{
                "id": "up",
                "command": "verify",
                "args": ["../../delivery", "../../manifest.json", "../../a-public.pem"],
            }]),
            encoding="utf-8",
        )
        report, code = verify_batch(batch)
        self.assertEqual(code, 0)
        self.assertTrue(report["valid"])

    def test_empty_batch_is_valid(self):
        self.write_batch([])
        report, code = verify_batch(self.batch)
        self.assertEqual(code, 0)
        self.assertTrue(report["valid"])
        self.assertEqual(
            report["summary"],
            {"total": 0, "passed": 0, "failed": 0, "errors": 0},
        )
        self.assertEqual(report["results"], [])


if __name__ == "__main__":
    unittest.main()
