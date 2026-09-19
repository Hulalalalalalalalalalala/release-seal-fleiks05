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
    AUDIT_REPORT_KIND,
    audit_batch,
    validate_audit_report_document,
)
from release_seal.batch import classify_error
from release_seal.seal import SealError, sign_directory, verify_directory


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
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(items), encoding="utf-8")
        return path

    def verify_item(self, name):
        return {
            "id": f"{name}-id",
            "command": "verify",
            "args": [name, f"{name}.json", f"{name}-public.pem"],
        }


class AuditBatchTests(AuditTestCase):
    def test_all_passing_publishes_report(self):
        self.prepare_signed("a")
        self.prepare_signed("b")
        batch = self.write_batch([self.verify_item("a"), self.verify_item("b")])
        report_path = self.work / "report.json"
        code, report = audit_batch(batch, report_path)
        self.assertEqual(code, 0)
        self.assertTrue(report["valid"])
        # Exactly the six top-level fields.
        self.assertEqual(
            set(report),
            {"kind", "version", "batch_sha256", "valid", "summary", "results"},
        )
        self.assertEqual(report["kind"], AUDIT_REPORT_KIND)
        self.assertEqual(report["kind"], "release-seal-audit-report")
        self.assertEqual(report["version"], 1)
        self.assertEqual(
            report["batch_sha256"],
            hashlib.sha256(batch.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["summary"],
            {"total": 2, "passed": 2, "failed": 0, "errors": 0},
        )
        self.assertEqual([r["id"] for r in report["results"]], ["a-id", "b-id"])
        for entry in report["results"]:
            self.assertEqual(entry["command"], "verify")
            self.assertEqual(entry["code"], 0)
            self.assertEqual(entry["outcome"], "passed")
            self.assertEqual(entry["result"], {"valid": True})
            self.assertNotIn("args", entry)
            self.assertNotIn("error", entry)
        # The published file holds exactly the returned report.
        published = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(published, report)
        # The report itself fully validates.
        self.assertEqual(validate_audit_report_document(published), published)

    def test_mixed_outcomes_and_error_kinds(self):
        self.prepare_signed("a")
        self.prepare_signed("b", tamper=True)
        bogus = self.work / "bogus-public.pem"
        bogus.write_bytes(b"not a pem")
        batch = self.write_batch([
            self.verify_item("a"),
            self.verify_item("b"),
            {"id": "missing", "command": "verify",
             "args": ["a", "missing.json", "a-public.pem"]},
            {"id": "bad-key", "command": "verify",
             "args": ["a", "a.json", "bogus-public.pem"]},
        ])
        code, report = audit_batch(batch, self.work / "report.json")
        self.assertEqual(code, 2)
        self.assertFalse(report["valid"])
        self.assertEqual(
            report["summary"],
            {"total": 4, "passed": 1, "failed": 1, "errors": 2},
        )
        passed, failed, missing, bad_key = report["results"]
        self.assertEqual((passed["code"], passed["outcome"]), (0, "passed"))
        self.assertEqual((failed["code"], failed["outcome"]), (1, "failed"))
        self.assertEqual(failed["result"]["modified"], ["docs/readme.txt"])
        self.assertEqual((missing["code"], missing["outcome"]), (2, "error"))
        self.assertEqual(missing["error_kind"], "io")
        self.assertTrue(missing["error"])
        self.assertNotIn("result", missing)
        self.assertEqual(bad_key["error_kind"], "input")
        self.assertTrue(bad_key["error"])

    def test_unsafe_error_kind_for_batch_inside_tree(self):
        self.prepare_signed("a")
        batch = self.write_batch(
            [{"id": "a", "command": "verify",
              "args": [".", "../a.json", "../a-public.pem"]}],
            name="a/batch.json",
        )
        code, report = audit_batch(batch, self.work / "report.json")
        self.assertEqual(code, 2)
        entry = report["results"][0]
        self.assertEqual(entry["code"], 2)
        self.assertEqual(entry["error_kind"], "unsafe")
        self.assertIn("outside the delivery tree", entry["error"])

    def test_empty_batch_is_audited(self):
        batch = self.write_batch([])
        code, report = audit_batch(batch, self.work / "report.json")
        self.assertEqual(code, 0)
        self.assertTrue(report["valid"])
        self.assertEqual(
            report["summary"],
            {"total": 0, "passed": 0, "failed": 0, "errors": 0},
        )
        self.assertEqual(report["results"], [])

    def test_structural_error_creates_no_report(self):
        batch = self.write_batch([{"id": "a", "command": "verify", "args": []}])
        report_path = self.work / "report.json"
        with self.assertRaises(SealError):
            audit_batch(batch, report_path)
        self.assertFalse(report_path.exists())

    def test_report_must_not_exist_and_is_not_overwritten(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        report_path = self.work / "report.json"
        report_path.write_bytes(b"previous")
        with self.assertRaises(SealError) as caught:
            audit_batch(batch, report_path)
        self.assertIn("already exists", str(caught.exception))
        self.assertEqual(report_path.read_bytes(), b"previous")

    def test_report_inside_delivery_tree_is_rejected(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        report_path = self.work / "a" / "report.json"
        with self.assertRaises(SealError) as caught:
            audit_batch(batch, report_path)
        self.assertIn("outside the delivery tree", str(caught.exception))
        self.assertFalse(report_path.exists())

    def test_relative_paths_resolve_from_batch_directory(self):
        self.prepare_signed("a")
        batch = self.write_batch(
            [{"id": "a", "command": "verify",
              "args": ["../a", "../a.json", "../a-public.pem"]}],
            name="nested/batch.json",
        )
        code, report = audit_batch(batch, self.work / "report.json")
        self.assertEqual(code, 0, report)
        self.assertTrue(report["valid"])

    def test_report_contains_no_args_keys_or_signatures(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        _, report = audit_batch(batch, self.work / "report.json")
        text = json.dumps(report)
        self.assertNotIn('"args"', text)
        self.assertNotIn("PRIVATE KEY", text)
        self.assertNotIn("signature", text)
        for entry in report["results"]:
            self.assertNotIn("args", entry)


class ClassifyErrorTests(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(classify_error(SealError("directory changed while scanning: d")), "changed")
        self.assertEqual(
            classify_error(SealError("keys must stay outside the delivery tree: x")),
            "unsafe",
        )
        self.assertEqual(classify_error(SealError("symbolic links are not supported: x")), "unsafe")
        self.assertEqual(classify_error(OSError("boom")), "io")
        self.assertEqual(
            classify_error(SealError("cannot read manifest m")),
            "input",
        )
        self.assertEqual(
            classify_error(SealError("cannot read manifest m: nope")),
            "input",
        )
        wrapped = SealError("cannot read manifest m")
        wrapped.__cause__ = OSError("nope")
        self.assertEqual(classify_error(wrapped), "io")
        self.assertEqual(classify_error(ValueError("bad input")), "input")
        self.assertEqual(classify_error(RuntimeError("bug")), "internal")


class ValidateAuditReportTests(AuditTestCase):
    def valid_report(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        _, report = audit_batch(batch, self.work / "report.json")
        return report

    def test_generated_report_validates(self):
        report = self.valid_report()
        self.assertEqual(validate_audit_report_document(report), report)

    def test_similar_but_invalid_documents_are_rejected(self):
        report = self.valid_report()
        bad = []
        wrong_kind = dict(report, kind="release-seal-audit-repor")
        bad.append(wrong_kind)
        bad.append(dict(report, version=2))
        bad.append(dict(report, batch_sha256="0" * 63))
        bad.append(dict(report, batch_sha256="0" * 64 + " "))
        bad.append(dict(report, valid="yes"))
        bad.append(dict(report, extra=1))
        missing = dict(report)
        del missing["summary"]
        bad.append(missing)
        bad.append(dict(report, summary={"total": 1, "passed": 1,
                                         "failed": 0, "errors": 1}))
        flipped = json.loads(json.dumps(report))
        flipped["results"][0]["outcome"] = "failed"
        bad.append(flipped)
        no_result = json.loads(json.dumps(report))
        del no_result["results"][0]["result"]
        bad.append(no_result)
        with_args = json.loads(json.dumps(report))
        with_args["results"][0]["args"] = ["a"]
        bad.append(with_args)
        for index, document in enumerate(bad):
            with self.subTest(case=index):
                with self.assertRaises(SealError):
                    validate_audit_report_document(document)


class AuditReportInTreeTests(AuditTestCase):
    def test_valid_audit_report_in_tree_is_rejected_by_content(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        _, report = audit_batch(batch, self.work / "report.json")
        # Drop a fully valid audit report into the delivery tree.
        delivery, manifest, public = self.work / "a", self.work / "a.json", self.work / "a-public.pem"
        (delivery / "innocent.txt").write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaises(SealError) as caught:
            verify_directory(delivery, manifest, public)
        self.assertIn("audit reports must stay outside the delivery tree",
                      str(caught.exception))

    def test_invalid_similar_json_in_tree_is_deliverable(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        _, report = audit_batch(batch, self.work / "report.json")
        similar = dict(report, kind="release-seal-audit-report-v2")
        delivery = self.work / "a"
        (delivery / "notes.json").write_text(json.dumps(similar), encoding="utf-8")
        # Re-sign so the extra file is part of the manifest, then verify.
        _, private, public = write_keypair(self.work, "b")
        manifest = self.work / "b.json"
        sign_directory(delivery, private, manifest)
        result = verify_directory(delivery, manifest, public)
        self.assertTrue(result["valid"])


class AuditBatchCliTests(AuditTestCase):
    def test_cli_prints_report_and_follows_batch_exit_code(self):
        self.prepare_signed("a")
        self.prepare_signed("b", tamper=True)
        batch = self.write_batch([self.verify_item("a"), self.verify_item("b")])
        report_path = self.work / "report.json"
        result = run_cli("audit-batch", batch, report_path)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        printed = json.loads(result.stdout)
        self.assertEqual(printed["kind"], "release-seal-audit-report")
        self.assertFalse(printed["valid"])
        self.assertEqual(
            printed["summary"],
            {"total": 2, "passed": 1, "failed": 1, "errors": 0},
        )
        self.assertEqual(printed, json.loads(report_path.read_text(encoding="utf-8")))

    def test_cli_item_errors_still_publish_report(self):
        self.prepare_signed("a")
        batch = self.write_batch([
            {"id": "broken", "command": "verify",
             "args": ["a", "missing.json", "a-public.pem"]},
        ])
        report_path = self.work / "report.json"
        result = run_cli("audit-batch", batch, report_path)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, "")
        printed = json.loads(result.stdout)
        self.assertEqual(printed["results"][0]["error_kind"], "io")
        self.assertTrue(report_path.exists())

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
        report_path.write_bytes(b"previous")
        result = run_cli("audit-batch", batch, report_path)
        self.assertEqual(result.returncode, 2)
        self.assertIn("already exists", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(report_path.read_bytes(), b"previous")


if __name__ == "__main__":
    unittest.main()
