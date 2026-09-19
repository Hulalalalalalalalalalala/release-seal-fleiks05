import hashlib
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

from release_seal.audit import (
    AUDIT_KIND,
    ERROR_KINDS,
    audit_batch,
    classify_error,
    validate_audit_document,
)
from release_seal.seal import SealError, sign_directory


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


class AuditTestCase(unittest.TestCase):
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

    def verify_item(self, name):
        return {
            "id": f"{name}-id",
            "command": "verify",
            "args": [name, f"{name}.json", f"{name}-public.pem"],
        }


class ClassifyErrorTests(unittest.TestCase):
    def test_outside_tree_is_unsafe(self):
        error = SealError("keys, manifests ... must stay outside the delivery tree: x")
        self.assertEqual(classify_error(error), "unsafe")

    def test_symbolic_link_is_unsafe(self):
        self.assertEqual(
            classify_error(ValueError("symbolic links are not supported: x")),
            "unsafe",
        )

    def test_changed_tree_is_changed(self):
        self.assertEqual(
            classify_error(SealError("directory changed while scanning: x")),
            "changed",
        )

    def test_os_error_is_io(self):
        self.assertEqual(classify_error(OSError("boom")), "io")

    def test_read_failures_are_io(self):
        self.assertEqual(
            classify_error(SealError("cannot read manifest x: gone")), "io"
        )
        self.assertEqual(classify_error(ValueError("cannot stat x: gone")), "io")

    def test_bad_input_is_input(self):
        self.assertEqual(
            classify_error(SealError("expected a PEM Ed25519 public key: x")),
            "input",
        )
        self.assertEqual(classify_error(ValueError("expected a directory: x")), "input")

    def test_unknown_is_internal(self):
        self.assertEqual(classify_error(RuntimeError("surprise")), "internal")

    def test_kinds_cover_all_values(self):
        kinds = {
            classify_error(SealError("must stay outside the delivery tree")),
            classify_error(SealError("changed while scanning")),
            classify_error(OSError("x")),
            classify_error(ValueError("cannot read x")),
            classify_error(ValueError("nope")),
            classify_error(RuntimeError("nope")),
        }
        self.assertEqual(kinds, set(ERROR_KINDS[:4]) | {"internal"})
        self.assertEqual(
            ERROR_KINDS, ("input", "io", "unsafe", "changed", "internal")
        )


class AuditBatchTests(AuditTestCase):
    def test_report_shape_and_hash(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        report_path = self.work / "report.json"
        code, report = audit_batch(batch, report_path)
        self.assertEqual(code, 0)
        self.assertEqual(
            set(report),
            {"kind", "version", "batch_sha256", "valid", "summary", "results"},
        )
        self.assertEqual(report["kind"], AUDIT_KIND)
        self.assertEqual(report["version"], 1)
        self.assertEqual(
            report["batch_sha256"],
            hashlib.sha256(batch.read_bytes()).hexdigest(),
        )
        self.assertTrue(report["valid"])
        self.assertEqual(
            report["summary"],
            {"total": 1, "passed": 1, "failed": 0, "errors": 0},
        )
        (entry,) = report["results"]
        self.assertEqual(entry["id"], "a-id")
        self.assertEqual(entry["command"], "verify")
        self.assertEqual(entry["code"], 0)
        self.assertEqual(entry["outcome"], "passed")
        self.assertEqual(entry["result"], {"valid": True})
        self.assertNotIn("error", entry)
        self.assertNotIn("args", entry)
        # The file on disk holds the same document.
        on_disk = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(on_disk, report)

    def test_mixed_outcomes(self):
        self.prepare_signed("a")
        self.prepare_signed("b", tamper=True)
        batch = self.write_batch([
            self.verify_item("a"),
            self.verify_item("b"),
            {"id": "broken", "command": "verify",
             "args": ["a", "missing.json", "a-public.pem"]},
        ])
        code, report = audit_batch(batch, self.work / "report.json")
        self.assertEqual(code, 2)
        self.assertFalse(report["valid"])
        self.assertEqual(
            report["summary"],
            {"total": 3, "passed": 1, "failed": 1, "errors": 1},
        )
        passed, failed, errored = report["results"]
        self.assertEqual((passed["code"], passed["outcome"]), (0, "passed"))
        self.assertEqual((failed["code"], failed["outcome"]), (1, "failed"))
        self.assertEqual(failed["result"]["modified"], ["docs/readme.txt"])
        self.assertEqual((errored["code"], errored["outcome"]), (2, "error"))
        self.assertTrue(errored["error"])
        self.assertEqual(errored["error_kind"], "io")
        self.assertNotIn("result", errored)
        self.assertNotIn("args", errored)

    def test_error_kinds_for_item_failures(self):
        self.prepare_signed("a")
        bogus = self.work / "bogus-public.pem"
        bogus.write_bytes(b"not a pem")
        batch = self.write_batch([
            {"id": "bad-key", "command": "verify",
             "args": ["a", "a.json", "bogus-public.pem"]},
            {"id": "missing-dir", "command": "verify",
             "args": ["nope", "a.json", "a-public.pem"]},
        ])
        code, report = audit_batch(batch, self.work / "report.json")
        self.assertEqual(code, 2)
        kinds = [entry["error_kind"] for entry in report["results"]]
        self.assertEqual(kinds, ["input", "io"])
        for entry in report["results"]:
            self.assertIn(entry["error_kind"], ERROR_KINDS)

    def test_empty_batch_is_audited(self):
        batch = self.write_batch([])
        code, report = audit_batch(batch, self.work / "report.json")
        self.assertEqual(code, 0)
        self.assertTrue(report["valid"])
        self.assertEqual(report["results"], [])
        self.assertEqual(
            report["summary"],
            {"total": 0, "passed": 0, "failed": 0, "errors": 0},
        )

    def test_report_must_not_exist(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        report_path = self.work / "report.json"
        report_path.write_bytes(b"sentinel")
        with self.assertRaises(SealError):
            audit_batch(batch, report_path)
        self.assertEqual(report_path.read_bytes(), b"sentinel")

    def test_report_outside_delivery_tree(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        inside = self.work / "a" / "report.json"
        with self.assertRaises(SealError) as caught:
            audit_batch(batch, inside)
        self.assertIn("outside the delivery tree", str(caught.exception))
        self.assertFalse(inside.exists())

    def test_structural_error_creates_no_report(self):
        batch = self.write_batch([{"id": "a", "command": "verify", "args": []}])
        report_path = self.work / "report.json"
        with self.assertRaises(SealError):
            audit_batch(batch, report_path)
        self.assertFalse(report_path.exists())
        self.assertEqual(list(self.work.glob("*.tmp")), [])
        self.assertEqual(list(self.work.glob(".*.tmp")), [])

    def test_no_leftover_temp_files(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        audit_batch(batch, self.work / "report.json")
        leftovers = [
            path for path in self.work.iterdir() if path.name.startswith(".")
        ]
        self.assertEqual(leftovers, [])


class AuditDocumentValidationTests(AuditTestCase):
    def make_report(self) -> dict:
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        _, report = audit_batch(batch, self.work / "report.json")
        return report

    def test_genuine_report_validates(self):
        report = self.make_report()
        self.assertIs(validate_audit_document(report), report)

    def test_invalid_similar_documents_are_rejected(self):
        report = self.make_report()
        bad = [
            # Wrong kind, version, hash, field set and outcome.
            {**report, "kind": "something-else"},
            {**report, "version": 2},
            {**report, "batch_sha256": "0" * 63},
            {**report, "extra": 1},
            {**report, "valid": "yes"},
            {**report, "summary": {**report["summary"], "passed": 0}},
            {**report, "results": [{**report["results"][0], "outcome": "error"}]},
            {**report, "results": [{**report["results"][0], "args": []}]},
        ]
        for index, document in enumerate(bad):
            with self.subTest(case=index):
                with self.assertRaises(SealError):
                    validate_audit_document(document)

    def test_in_tree_report_is_rejected_by_content(self):
        # A genuine audit report placed inside a delivery tree makes
        # signing and verifying that tree fail.
        report = self.make_report()
        delivery = make_delivery(self.work, "victim")
        (delivery / "report.json").write_text(json.dumps(report), encoding="utf-8")
        _, private, public = write_keypair(self.work, "victim")
        with self.assertRaises(SealError) as caught:
            sign_directory(delivery, private, self.work / "victim.json")
        self.assertIn("audit reports must stay outside", str(caught.exception))

    def test_invalid_similar_json_in_tree_is_deliverable(self):
        report = self.make_report()
        report["kind"] = "almost-an-audit-report"
        delivery = make_delivery(self.work, "fine")
        (delivery / "report.json").write_text(json.dumps(report), encoding="utf-8")
        _, private, public = write_keypair(self.work, "fine")
        manifest = self.work / "fine.json"
        sign_directory(delivery, private, manifest)
        from release_seal.seal import verify_directory

        self.assertTrue(verify_directory(delivery, manifest, public)["valid"])


class AuditBatchCliTests(AuditTestCase):
    def test_cli_prints_report_and_exit_code(self):
        self.prepare_signed("a")
        self.prepare_signed("b", tamper=True)
        batch = self.write_batch([self.verify_item("a"), self.verify_item("b")])
        report_path = self.work / "report.json"
        result = run_cli("audit-batch", batch, report_path)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        self.assertEqual(report["kind"], AUDIT_KIND)
        self.assertFalse(report["valid"])
        self.assertEqual(json.loads(report_path.read_text(encoding="utf-8")), report)

    def test_cli_structural_error_writes_stderr_and_no_report(self):
        batch = self.write_batch([{"id": "a", "command": "verify", "args": []}])
        report_path = self.work / "report.json"
        result = run_cli("audit-batch", batch, report_path)
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")
        self.assertEqual(result.stdout, "")
        self.assertFalse(report_path.exists())

    def test_cli_existing_report_is_not_overwritten(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        report_path = self.work / "report.json"
        report_path.write_bytes(b"sentinel")
        result = run_cli("audit-batch", batch, report_path)
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")
        self.assertEqual(result.stdout, "")
        self.assertEqual(report_path.read_bytes(), b"sentinel")

    def test_cli_report_inside_tree_fails(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        result = run_cli("audit-batch", batch, self.work / "a" / "report.json")
        self.assertEqual(result.returncode, 2)
        self.assertIn("outside the delivery tree", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
