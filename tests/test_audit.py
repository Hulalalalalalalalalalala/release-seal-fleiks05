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
    AUDIT_CHAIN_KIND,
    AUDIT_REPORT_KIND,
    audit_batch,
    audit_chain,
    audit_chain_verify,
    validate_audit_report_document,
    validate_chain_report_document,
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


class AuditChainTests(AuditTestCase):
    CHAIN_FIELDS = {
        "kind",
        "version",
        "sequence",
        "previous_sha256",
        "batch_sha256",
        "valid",
        "summary",
        "results",
    }

    def append_chain(self, items, previous, name, *, batch_name=None):
        batch = self.write_batch(
            items, name=batch_name or f"{name}-batch.json"
        )
        report_path = self.work / f"{name}.json"
        code, report = audit_chain(batch, previous, report_path)
        return batch, report_path, code, report

    def make_chain(self, count):
        self.prepare_signed("a")
        reports = []
        previous = "-"
        for number in range(1, count + 1):
            batch, path, code, report = self.append_chain(
                [self.verify_item("a")], previous, f"chain{number}"
            )
            self.assertEqual(code, 0)
            reports.append((batch, path, report))
            previous = path
        return reports

    def test_genesis_report_starts_the_chain(self):
        self.prepare_signed("a")
        batch, path, code, report = self.append_chain(
            [self.verify_item("a")], "-", "chain1"
        )
        self.assertEqual(code, 0)
        self.assertEqual(set(report), self.CHAIN_FIELDS)
        self.assertEqual(report["kind"], AUDIT_CHAIN_KIND)
        self.assertEqual(report["kind"], "release-seal-audit-chain")
        self.assertEqual(report["version"], 2)
        self.assertEqual(report["sequence"], 1)
        self.assertIsNone(report["previous_sha256"])
        self.assertEqual(
            report["batch_sha256"],
            hashlib.sha256(batch.read_bytes()).hexdigest(),
        )
        self.assertTrue(report["valid"])
        entry = report["results"][0]
        self.assertEqual(entry["outcome"], "passed")
        self.assertEqual(entry["result"], {"valid": True})
        self.assertNotIn("args", entry)
        # The published bytes fully validate as a chain report.
        published = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(published, report)
        self.assertEqual(
            validate_chain_report_document(published), published
        )

    def test_successor_links_sequence_and_raw_byte_digest(self):
        reports = self.make_chain(2)
        _, r1_path, r1 = reports[0]
        _, r2_path, r2 = reports[1]
        self.assertEqual(r2["sequence"], 2)
        self.assertEqual(
            r2["previous_sha256"],
            hashlib.sha256(r1_path.read_bytes()).hexdigest(),
        )
        _, r3_path, _, r3 = self.append_chain([], r2_path, "chain3")
        self.assertEqual(r3["sequence"], 3)
        self.assertEqual(
            r3["previous_sha256"],
            hashlib.sha256(r2_path.read_bytes()).hexdigest(),
        )
        self.assertTrue(r3["valid"])
        self.assertEqual(r3["summary"]["total"], 0)
        self.assertEqual(r3["results"], [])

    def test_empty_batch_genesis_is_valid(self):
        batch = self.write_batch([], name="empty.json")
        code, report = audit_chain(batch, "-", self.work / "chain1.json")
        self.assertEqual(code, 0)
        self.assertTrue(report["valid"])
        self.assertEqual(report["sequence"], 1)
        self.assertIsNone(report["previous_sha256"])
        self.assertEqual(report["results"], [])

    def test_exit_code_follows_batch_result(self):
        self.prepare_signed("a")
        self.prepare_signed("b", tamper=True)
        batch = self.write_batch(
            [self.verify_item("a"), self.verify_item("b")]
        )
        code, report = audit_chain(batch, "-", self.work / "chain1.json")
        self.assertEqual(code, 1)
        self.assertFalse(report["valid"])
        self.assertEqual(report["summary"]["failed"], 1)

    def test_item_errors_still_publish_chain_report(self):
        self.prepare_signed("a")
        batch = self.write_batch([
            {"id": "broken", "command": "verify",
             "args": ["a", "missing.json", "a-public.pem"]},
        ])
        code, report = audit_chain(batch, "-", self.work / "chain1.json")
        self.assertEqual(code, 2)
        self.assertEqual(report["results"][0]["error_kind"], "io")

    def test_structural_batch_error_creates_no_report(self):
        bad = self.write_batch(
            [{"id": "a", "command": "verify", "args": []}],
            name="bad.json",
        )
        genesis = self.work / "g.json"
        with self.assertRaises(SealError):
            audit_chain(bad, "-", genesis)
        self.assertFalse(genesis.exists())
        # The same holds for a successor run with a valid predecessor.
        _, prev_path, _ = self.make_chain(1)[0]
        successor = self.work / "s.json"
        with self.assertRaises(SealError):
            audit_chain(bad, prev_path, successor)
        self.assertFalse(successor.exists())

    def test_missing_predecessor_creates_no_report(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        report_path = self.work / "chain1.json"
        with self.assertRaises(SealError) as caught:
            audit_chain(batch, self.work / "missing.json", report_path)
        self.assertIn("cannot read previous chain report", str(caught.exception))
        self.assertFalse(report_path.exists())

    def test_v1_audit_report_is_not_a_predecessor(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        v1 = self.work / "v1.json"
        audit_batch(batch, v1)
        report_path = self.work / "chain1.json"
        with self.assertRaises(SealError):
            audit_chain(batch, v1, report_path)
        self.assertFalse(report_path.exists())

    def test_malformed_or_similar_predecessor_is_rejected(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        not_json = self.work / "notjson.json"
        not_json.write_bytes(b"{nope")
        similar = self.work / "similar.json"
        good_path = self.work / "good.json"
        _, good = audit_chain(batch, "-", good_path)
        # A structurally valid chain report with a wrong version is only
        # a lookalike and must not extend the chain.
        similar.write_text(
            json.dumps(dict(good, version=1)), encoding="utf-8"
        )
        for predecessor in (not_json, similar):
            report_path = self.work / f"after-{predecessor.stem}.json"
            with self.subTest(predecessor=predecessor.name):
                with self.assertRaises(SealError):
                    audit_chain(batch, predecessor, report_path)
                self.assertFalse(report_path.exists())

    def test_report_is_not_overwritten(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        report_path = self.work / "chain1.json"
        report_path.write_bytes(b"previous")
        with self.assertRaises(SealError) as caught:
            audit_chain(batch, "-", report_path)
        self.assertIn("already exists", str(caught.exception))
        self.assertEqual(report_path.read_bytes(), b"previous")

    def test_report_inside_delivery_tree_is_rejected(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        report_path = self.work / "a" / "chain1.json"
        with self.assertRaises(SealError) as caught:
            audit_chain(batch, "-", report_path)
        self.assertIn("outside the delivery tree", str(caught.exception))
        self.assertFalse(report_path.exists())

    def test_report_contains_no_args_keys_or_signatures(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        _, report = audit_chain(batch, "-", self.work / "chain1.json")
        text = json.dumps(report)
        self.assertNotIn('"args"', text)
        self.assertNotIn("PRIVATE KEY", text)
        self.assertNotIn("signature", text)

    def test_similar_chain_documents_are_rejected(self):
        _, _, report = self.make_chain(1)[0]
        digest = "0" * 64
        bad = [
            dict(report, kind="release-seal-audit-chai"),
            dict(report, version=1),
            dict(report, sequence=0),
            dict(report, sequence="1"),
            dict(report, previous_sha256=digest),
            dict(report, sequence=2),
            dict(report, batch_sha256="0" * 63),
            dict(report, valid="yes"),
            dict(report, extra=1),
        ]
        missing = dict(report)
        del missing["sequence"]
        bad.append(missing)
        # A non-genesis report with a null link is internally inconsistent.
        successor_like = json.loads(json.dumps(report))
        successor_like["sequence"] = 2
        successor_like["previous_sha256"] = None
        bad.append(successor_like)
        for index, document in enumerate(bad):
            with self.subTest(case=index):
                with self.assertRaises(SealError):
                    validate_chain_report_document(document)


class AuditChainVerifyTests(AuditTestCase):
    def raw_digest(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def make_chain(self, count):
        self.prepare_signed("a")
        paths = []
        previous = "-"
        for number in range(1, count + 1):
            batch = self.write_batch(
                [self.verify_item("a")], name=f"b{number}.json"
            )
            path = self.work / f"c{number}.json"
            code, _ = audit_chain(batch, previous, path)
            self.assertEqual(code, 0)
            paths.append(path)
            previous = path
        return paths

    def test_valid_chain(self):
        paths = self.make_chain(3)
        head = self.raw_digest(paths[-1])
        code, result = audit_chain_verify(head, paths)
        self.assertEqual(code, 0)
        self.assertEqual(
            result,
            {"valid": True, "count": 3, "head_sha256": head},
        )

    def test_single_genesis_report(self):
        paths = self.make_chain(1)
        head = self.raw_digest(paths[0])
        code, result = audit_chain_verify(head, paths)
        self.assertEqual(code, 0)
        self.assertEqual(result["count"], 1)

    def test_wrong_head_digest_points_at_last_index(self):
        paths = self.make_chain(2)
        code, result = audit_chain_verify("0" * 64, paths)
        self.assertEqual(code, 1)
        self.assertEqual(
            result,
            {"valid": False, "reason": "broken_chain", "index": 1},
        )

    def test_tampered_predecessor_breaks_link(self):
        paths = self.make_chain(2)
        # Extra trailing whitespace keeps the document parseable and
        # valid, but changes the raw bytes the successor linked to.
        paths[0].write_bytes(paths[0].read_bytes() + b"\n")
        head = self.raw_digest(paths[-1])
        code, result = audit_chain_verify(head, paths)
        self.assertEqual(code, 1)
        self.assertEqual(result["index"], 1)
        self.assertEqual(result["reason"], "broken_chain")

    def test_starting_mid_chain_points_at_index_zero(self):
        paths = self.make_chain(2)
        head = self.raw_digest(paths[-1])
        code, result = audit_chain_verify(head, paths[1:])
        self.assertEqual(code, 1)
        self.assertEqual(result["index"], 0)

    def test_reversed_order_points_at_index_zero(self):
        paths = self.make_chain(2)
        code, result = audit_chain_verify(
            self.raw_digest(paths[0]), list(reversed(paths))
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["index"], 0)

    def test_sequence_gap_points_at_gap_index(self):
        paths = self.make_chain(2)
        batch = self.write_batch(
            [self.verify_item("a")], name="b3.json"
        )
        third = self.work / "c3.json"
        self.assertEqual(audit_chain(batch, paths[1], third)[0], 0)
        head = self.raw_digest(third)
        code, result = audit_chain_verify(head, [paths[0], third])
        self.assertEqual(code, 1)
        self.assertEqual(result["index"], 1)

    def test_bad_expected_head_is_a_parameter_error(self):
        paths = self.make_chain(1)
        for bad in ("", "zzz", "0" * 63, "0" * 65, "A" * 64):
            with self.subTest(bad=bad):
                with self.assertRaises(SealError):
                    audit_chain_verify(bad, paths)

    def test_no_reports_is_a_parameter_error(self):
        with self.assertRaises(SealError):
            audit_chain_verify("0" * 64, [])

    def test_unreadable_or_invalid_report_is_a_format_error(self):
        paths = self.make_chain(2)
        missing = self.work / "missing.json"
        with self.assertRaises(SealError):
            audit_chain_verify("0" * 64, [paths[0], missing])
        malformed = self.work / "malformed.json"
        malformed.write_bytes(b"{not json")
        with self.assertRaises(SealError):
            audit_chain_verify("0" * 64, [malformed])
        similar = self.work / "similar.json"
        good = json.loads(paths[0].read_text(encoding="utf-8"))
        similar.write_text(json.dumps(dict(good, kind="nope")), encoding="utf-8")
        with self.assertRaises(SealError):
            audit_chain_verify("0" * 64, [similar])


class AuditChainInTreeTests(AuditTestCase):
    def test_valid_chain_report_in_tree_is_rejected_by_content(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        _, report = audit_chain(batch, "-", self.work / "chain1.json")
        delivery = self.work / "a"
        (delivery / "innocent.txt").write_text(
            json.dumps(report), encoding="utf-8"
        )
        manifest = self.work / "a.json"
        public = self.work / "a-public.pem"
        with self.assertRaises(SealError) as caught:
            verify_directory(delivery, manifest, public)
        self.assertIn(
            "audit chain reports must stay outside the delivery tree",
            str(caught.exception),
        )

    def test_similar_chain_json_in_tree_is_deliverable(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        _, report = audit_chain(batch, "-", self.work / "chain1.json")
        similar = dict(report, kind="release-seal-audit-chain-v2")
        delivery = self.work / "a"
        (delivery / "notes.json").write_text(
            json.dumps(similar), encoding="utf-8"
        )
        _, private, public = write_keypair(self.work, "b")
        manifest = self.work / "b.json"
        sign_directory(delivery, private, manifest)
        result = verify_directory(delivery, manifest, public)
        self.assertTrue(result["valid"])


class AuditChainCliTests(AuditTestCase):
    def test_cli_genesis_and_successor(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        r1 = self.work / "c1.json"
        result = run_cli("audit-chain", batch, "-", r1)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        printed = json.loads(result.stdout)
        self.assertEqual(printed["kind"], "release-seal-audit-chain")
        self.assertEqual(printed["sequence"], 1)
        self.assertIsNone(printed["previous_sha256"])
        self.assertEqual(printed, json.loads(r1.read_text(encoding="utf-8")))
        empty = self.write_batch([], name="empty.json")
        r2 = self.work / "c2.json"
        result = run_cli("audit-chain", empty, r1, r2)
        self.assertEqual(result.returncode, 0)
        printed = json.loads(result.stdout)
        self.assertEqual(printed["sequence"], 2)
        self.assertEqual(
            printed["previous_sha256"],
            hashlib.sha256(r1.read_bytes()).hexdigest(),
        )

    def test_cli_bad_predecessor_writes_stderr_and_no_report(self):
        batch = self.write_batch([])
        report_path = self.work / "c1.json"
        result = run_cli(
            "audit-chain", batch, self.work / "missing.json", report_path
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")
        self.assertEqual(result.stdout, "")
        self.assertFalse(report_path.exists())

    def test_cli_verify_success(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        r1 = self.work / "c1.json"
        run_cli("audit-chain", batch, "-", r1)
        head = hashlib.sha256(r1.read_bytes()).hexdigest()
        result = run_cli("audit-chain-verify", head, r1)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(
            json.loads(result.stdout),
            {"valid": True, "count": 1, "head_sha256": head},
        )

    def test_cli_verify_broken_chain_returns_one(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        r1 = self.work / "c1.json"
        r2 = self.work / "c2.json"
        run_cli("audit-chain", batch, "-", r1)
        run_cli("audit-chain", batch, r1, r2)
        result = run_cli("audit-chain-verify", "0" * 64, r1, r2)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertEqual(
            json.loads(result.stdout),
            {"valid": False, "reason": "broken_chain", "index": 1},
        )

    def test_cli_verify_bad_head_returns_two(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        r1 = self.work / "c1.json"
        run_cli("audit-chain", batch, "-", r1)
        result = run_cli("audit-chain-verify", "not-hex", r1)
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")
        self.assertEqual(result.stdout, "")

    def test_cli_verify_without_reports_is_usage_error(self):
        result = run_cli("audit-chain-verify", "0" * 64)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
