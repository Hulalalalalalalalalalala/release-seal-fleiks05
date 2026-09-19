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

from release_seal.batch import load_batch, verify_batch
from release_seal.seal import SealError, sign_directory, sign_multi_directory
from release_seal.trust import import_key


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


def make_delivery(root: Path, name: str = "delivery") -> Path:
    delivery = root / name
    (delivery / "docs").mkdir(parents=True)
    (delivery / "docs" / "readme.txt").write_bytes(b"hello")
    return delivery


class BatchTestCase(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.work = Path(self.workspace.name)

    def prepare_signed(self, name: str, *, tamper: bool = False):
        delivery = make_delivery(self.work, name)
        _, private, public = write_keypair(self.work, name)
        manifest = self.work / f"{name}.json"
        sign_directory(delivery, private, manifest)
        if tamper:
            (delivery / "docs" / "readme.txt").write_bytes(b"changed")
        return delivery, manifest, public

    def write_batch(self, items, *, name: str = "batch.json") -> Path:
        path = self.work / name
        path.write_text(json.dumps(items), encoding="utf-8")
        return path

    def verify_item(self, name, manifest, public):
        return {
            "id": f"{name}-id",
            "command": "verify",
            "args": [name, f"{name}.json", f"{name}-public.pem"],
        }


class LoadBatchTests(BatchTestCase):
    def test_valid_batch_loads_in_order(self):
        path = self.write_batch([
            {"id": "a", "command": "verify", "args": ["d", "m.json", "p.pem"]},
            {"id": "b", "command": "verify-trusted", "args": ["d", "m.json", "s.json"]},
            {"id": "c", "command": "verify-policy",
             "args": ["d", "m.json", "s.json", "p.json"]},
        ])
        items = load_batch(path)
        self.assertEqual([item["id"] for item in items], ["a", "b", "c"])
        self.assertEqual(items[2]["command"], "verify-policy")
        self.assertEqual(len(items[2]["args"]), 4)

    def test_empty_batch_is_structurally_valid(self):
        path = self.write_batch([])
        self.assertEqual(load_batch(path), [])

    def test_structural_errors_are_rejected(self):
        bad = [
            "not an array",
            json.dumps([1, 2, 3]),
            json.dumps([{"id": "a", "command": "verify", "args": []}]),
            json.dumps([{"id": "a", "command": "verify",
                         "args": ["d", "m.json", "p.pem"], "extra": 1}]),
            json.dumps([{"id": "", "command": "verify",
                         "args": ["d", "m.json", "p.pem"]}]),
            json.dumps([{"id": 4, "command": "verify",
                         "args": ["d", "m.json", "p.pem"]}]),
            json.dumps([{"id": "a", "command": "rotate",
                         "args": ["d", "m.json", "p.pem"]}]),
            json.dumps([{"id": "a", "command": "verify",
                         "args": ["d", "m.json", 7]}]),
            json.dumps([{"id": "a", "command": "verify",
                         "args": ["d", "m.json"]}]),
            json.dumps([{"id": "a", "command": "verify-policy",
                         "args": ["d", "m.json", "s.json"]}]),
            json.dumps([{"id": "a", "command": "verify",
                         "args": ["d", "m.json", "p.pem"]},
                        {"id": "a", "command": "verify",
                         "args": ["d", "m.json", "p.pem"]}]),
        ]
        # First case is a raw JSON non-array; the rest are bad documents.
        cases = [json.dumps("not an array"), *bad[1:]]
        for index, text in enumerate(cases):
            with self.subTest(case=index):
                path = self.work / f"bad-{index}.json"
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(SealError):
                    load_batch(path)

    def test_non_utf8_or_unreadable_batch_is_rejected(self):
        path = self.write_batch([])
        path.write_bytes(b"\xff\xfe not json")
        with self.assertRaises(SealError):
            load_batch(path)
        with self.assertRaises(SealError):
            load_batch(self.work / "missing-batch.json")


class VerifyBatchTests(BatchTestCase):
    def test_all_passing(self):
        a, am, ap = self.prepare_signed("a")
        b, bm, bp = self.prepare_signed("b")
        path = self.write_batch([
            self.verify_item("a", am, ap),
            self.verify_item("b", bm, bp),
        ])
        code, report = verify_batch(path)
        self.assertEqual(code, 0)
        self.assertTrue(report["valid"])
        self.assertEqual(report["version"], 1)
        self.assertEqual(report["summary"],
                         {"total": 2, "passed": 2, "failed": 0, "errors": 0})
        self.assertEqual([r["id"] for r in report["results"]], ["a-id", "b-id"])
        for result in report["results"]:
            self.assertEqual(result["code"], 0)
            self.assertEqual(result["result"], {"valid": True})
            self.assertNotIn("error", result)

    def test_mixed_pass_fail_error(self):
        a, am, ap = self.prepare_signed("a")
        b, bm, bp = self.prepare_signed("b", tamper=True)
        path = self.write_batch([
            self.verify_item("a", am, ap),
            self.verify_item("b", bm, bp),
            {"id": "broken", "command": "verify",
             "args": ["a", "missing.json", "a-public.pem"]},
        ])
        code, report = verify_batch(path)
        self.assertEqual(code, 2)
        self.assertFalse(report["valid"])
        self.assertEqual(report["summary"],
                         {"total": 3, "passed": 1, "failed": 1, "errors": 1})
        passed, failed, errored = report["results"]
        self.assertEqual(passed["code"], 0)
        self.assertTrue(passed["result"]["valid"])
        self.assertEqual(failed["code"], 1)
        self.assertFalse(failed["result"]["valid"])
        self.assertEqual(failed["result"]["modified"], ["docs/readme.txt"])
        self.assertEqual(errored["code"], 2)
        self.assertIsInstance(errored["error"], str)
        self.assertNotEqual(errored["error"], "")
        self.assertNotIn("result", errored)

    def test_only_failures_returns_1(self):
        a, am, ap = self.prepare_signed("a", tamper=True)
        path = self.write_batch([self.verify_item("a", am, ap)])
        code, report = verify_batch(path)
        self.assertEqual(code, 1)
        self.assertFalse(report["valid"])
        self.assertEqual(report["summary"],
                         {"total": 1, "passed": 0, "failed": 1, "errors": 0})

    def test_empty_batch_returns_0(self):
        path = self.write_batch([])
        code, report = verify_batch(path)
        self.assertEqual(code, 0)
        self.assertTrue(report["valid"])
        self.assertEqual(report["summary"],
                         {"total": 0, "passed": 0, "failed": 0, "errors": 0})
        self.assertEqual(report["results"], [])

    def test_item_errors_are_caught_and_other_items_still_run(self):
        # A bad public key is a code-2 item error, not a batch abort.
        a, am, ap = self.prepare_signed("a")
        bogus = self.work / "bogus-public.pem"
        bogus.write_bytes(b"not a pem")
        b, bm, bp = self.prepare_signed("b")
        path = self.write_batch([
            {"id": "bad-key", "command": "verify",
             "args": ["a", "a.json", "bogus-public.pem"]},
            self.verify_item("b", bm, bp),
        ])
        code, report = verify_batch(path)
        self.assertEqual(code, 2)
        self.assertEqual(report["results"][0]["code"], 2)
        self.assertTrue(report["results"][0]["error"])
        self.assertEqual(report["results"][1]["code"], 0)

    def test_relative_paths_resolve_from_batch_directory(self):
        a, am, ap = self.prepare_signed("a")
        nested = self.work / "nested"
        nested.mkdir()
        # Batch lives in a subdirectory; relative args climb back out.
        path = self.write_batch([
            {"id": "a", "command": "verify",
             "args": ["../a", "../a.json", "../a-public.pem"]},
        ], name="nested/batch.json")
        code, report = verify_batch(path)
        self.assertEqual(code, 0, report)
        self.assertTrue(report["valid"])

    def test_batch_inside_delivery_tree_is_a_code_2_item_error(self):
        a, am, ap = self.prepare_signed("a")
        path = self.write_batch([
            {"id": "a", "command": "verify",
             "args": [".", "../a.json", "../a-public.pem"]},
        ], name="a/batch.json")
        code, report = verify_batch(path)
        self.assertEqual(code, 2)
        self.assertEqual(report["results"][0]["code"], 2)
        self.assertIn("outside the delivery tree", report["results"][0]["error"])

    def test_verify_trusted_and_verify_policy_items(self):
        from release_seal.seal import key_id_of

        # verify-trusted item
        delivery = make_delivery(self.work, "tr")
        key, private, public = write_keypair(self.work, "tr")
        manifest = self.work / "tr.json"
        sign_directory(delivery, private, manifest)
        store = self.work / "tr-store.json"
        import_key(public, store)
        # verify-policy item with a version 3 manifest
        multi = make_delivery(self.work, "mp")
        multi_manifest = self.work / "mp.json"
        sign_multi_directory(multi, multi_manifest, [private])
        policy = self.work / "mp-policy.json"
        policy.write_text(json.dumps({
            "version": 1,
            "threshold": 1,
            "allowed_key_ids": [key_id_of(key.public_key())],
        }), encoding="utf-8")
        path = self.write_batch([
            {"id": "trusted", "command": "verify-trusted",
             "args": ["tr", "tr.json", "tr-store.json"]},
            {"id": "policy", "command": "verify-policy",
             "args": ["mp", "mp.json", "tr-store.json", "mp-policy.json"]},
        ])
        code, report = verify_batch(path)
        self.assertEqual(code, 0, report)
        self.assertEqual([r["code"] for r in report["results"]], [0, 0])


class VerifyBatchCliTests(BatchTestCase):
    def test_cli_prints_report_and_exit_codes(self):
        a, am, ap = self.prepare_signed("a")
        b, bm, bp = self.prepare_signed("b", tamper=True)
        path = self.write_batch([
            self.verify_item("a", am, ap),
            self.verify_item("b", bm, bp),
        ])
        result = run_cli("verify-batch", path)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        self.assertFalse(report["valid"])
        self.assertEqual(report["summary"],
                         {"total": 2, "passed": 1, "failed": 1, "errors": 0})

    def test_cli_structural_error_writes_stderr_and_no_summary(self):
        path = self.write_batch([{"id": "a", "command": "verify", "args": []}])
        result = run_cli("verify-batch", path)
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
