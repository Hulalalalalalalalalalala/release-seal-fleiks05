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

from release_seal.chain import (
    CHAIN_REPORT_KIND,
    audit_chain,
    validate_chain_report_document,
    verify_chain,
    verify_chain_set,
)
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


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ChainTestCase(unittest.TestCase):
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

    def make_chain(self, length: int = 2) -> list[Path]:
        """Build a chain of ``length`` reports; return their paths."""
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        paths = []
        previous = "-"
        for index in range(length):
            report_path = self.work / f"chain-{index}.json"
            code, _ = audit_chain(batch, previous, report_path)
            self.assertEqual(code, 0)
            paths.append(report_path)
            previous = report_path
        return paths


class AuditChainTests(ChainTestCase):
    def test_genesis_report(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        report_path = self.work / "report.json"
        code, report = audit_chain(batch, "-", report_path)
        self.assertEqual(code, 0)
        self.assertTrue(report["valid"])
        # Exactly the eight top-level fields.
        self.assertEqual(
            set(report),
            {
                "kind", "version", "sequence", "previous_sha256",
                "batch_sha256", "valid", "summary", "results",
            },
        )
        self.assertEqual(report["kind"], CHAIN_REPORT_KIND)
        self.assertEqual(report["kind"], "release-seal-audit-chain")
        self.assertEqual(report["version"], 2)
        self.assertEqual(report["sequence"], 1)
        self.assertIsNone(report["previous_sha256"])
        self.assertEqual(report["batch_sha256"], sha256_of(batch))
        self.assertEqual(
            report["summary"],
            {"total": 1, "passed": 1, "failed": 0, "errors": 0},
        )
        (entry,) = report["results"]
        self.assertEqual(entry["id"], "a-id")
        self.assertEqual(entry["command"], "verify")
        self.assertEqual((entry["code"], entry["outcome"]), (0, "passed"))
        self.assertEqual(entry["result"], {"valid": True})
        self.assertNotIn("args", entry)
        # The published file holds exactly the returned report.
        published = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(published, report)
        self.assertEqual(validate_chain_report_document(published), published)

    def test_successor_links_to_previous_raw_bytes(self):
        first, second = self.make_chain(2)
        first_document = json.loads(first.read_text(encoding="utf-8"))
        second_document = json.loads(second.read_text(encoding="utf-8"))
        self.assertEqual(first_document["sequence"], 1)
        self.assertIsNone(first_document["previous_sha256"])
        self.assertEqual(second_document["sequence"], 2)
        self.assertEqual(second_document["previous_sha256"], sha256_of(first))
        self.assertEqual(
            second_document["batch_sha256"], first_document["batch_sha256"]
        )

    def test_empty_batch_is_legal(self):
        batch = self.write_batch([])
        report_path = self.work / "report.json"
        code, report = audit_chain(batch, "-", report_path)
        self.assertEqual(code, 0)
        self.assertTrue(report["valid"])
        self.assertEqual(report["sequence"], 1)
        self.assertEqual(report["results"], [])
        self.assertEqual(
            report["summary"],
            {"total": 0, "passed": 0, "failed": 0, "errors": 0},
        )

    def test_mixed_outcomes_follow_v1_audit_semantics(self):
        self.prepare_signed("a")
        self.prepare_signed("b", tamper=True)
        batch = self.write_batch([
            self.verify_item("a"),
            self.verify_item("b"),
            {"id": "missing", "command": "verify",
             "args": ["a", "missing.json", "a-public.pem"]},
        ])
        code, report = audit_chain(batch, "-", self.work / "report.json")
        self.assertEqual(code, 2)
        self.assertFalse(report["valid"])
        self.assertEqual(
            report["summary"],
            {"total": 3, "passed": 1, "failed": 1, "errors": 1},
        )
        passed, failed, missing = report["results"]
        self.assertEqual((passed["code"], passed["outcome"]), (0, "passed"))
        self.assertEqual((failed["code"], failed["outcome"]), (1, "failed"))
        self.assertEqual(failed["result"]["modified"], ["docs/readme.txt"])
        self.assertEqual((missing["code"], missing["outcome"]), (2, "error"))
        self.assertEqual(missing["error_kind"], "io")
        self.assertTrue(missing["error"])
        self.assertNotIn("result", missing)

    def test_structural_batch_error_creates_no_report(self):
        batch = self.write_batch([{"id": "a", "command": "verify", "args": []}])
        report_path = self.work / "report.json"
        with self.assertRaises(SealError):
            audit_chain(batch, "-", report_path)
        self.assertFalse(report_path.exists())

    def test_missing_previous_creates_no_report(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        report_path = self.work / "report.json"
        with self.assertRaises(SealError) as caught:
            audit_chain(batch, self.work / "absent.json", report_path)
        self.assertIn("cannot read", str(caught.exception))
        self.assertFalse(report_path.exists())

    def test_invalid_previous_creates_no_report(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        previous = self.work / "previous.json"
        previous.write_text(json.dumps({"kind": CHAIN_REPORT_KIND}))
        report_path = self.work / "report.json"
        with self.assertRaises(SealError):
            audit_chain(batch, previous, report_path)
        self.assertFalse(report_path.exists())

    def test_v1_audit_report_is_not_a_valid_previous(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        from release_seal.audit import audit_batch

        previous = self.work / "previous.json"
        audit_batch(batch, previous)
        report_path = self.work / "report.json"
        with self.assertRaises(SealError):
            audit_chain(batch, previous, report_path)
        self.assertFalse(report_path.exists())

    def test_report_must_not_exist_and_is_not_overwritten(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        report_path = self.work / "report.json"
        report_path.write_bytes(b"previous")
        with self.assertRaises(SealError) as caught:
            audit_chain(batch, "-", report_path)
        self.assertIn("already exists", str(caught.exception))
        self.assertEqual(report_path.read_bytes(), b"previous")

    def test_report_inside_delivery_tree_is_rejected(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        report_path = self.work / "a" / "report.json"
        with self.assertRaises(SealError) as caught:
            audit_chain(batch, "-", report_path)
        self.assertIn("outside the delivery tree", str(caught.exception))
        self.assertFalse(report_path.exists())

    def test_previous_inside_delivery_tree_is_rejected(self):
        first = self.make_chain(1)[0]
        moved = self.work / "a" / "previous.json"
        moved.write_bytes(first.read_bytes())
        batch = self.work / "batch.json"
        report_path = self.work / "report.json"
        with self.assertRaises(SealError) as caught:
            audit_chain(batch, moved, report_path)
        self.assertIn("outside the delivery tree", str(caught.exception))
        self.assertFalse(report_path.exists())

    def test_report_contains_no_args_keys_or_signatures(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        _, report = audit_chain(batch, "-", self.work / "report.json")
        text = json.dumps(report)
        self.assertNotIn('"args"', text)
        self.assertNotIn("PRIVATE KEY", text)
        self.assertNotIn("signature", text)
        self.assertNotIn("Traceback", text)


class ValidateChainReportTests(ChainTestCase):
    def valid_report(self):
        return json.loads(self.make_chain(1)[0].read_text(encoding="utf-8"))

    def test_generated_reports_validate(self):
        for path in self.make_chain(3):
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(validate_chain_report_document(document), document)

    def test_similar_but_invalid_documents_are_rejected(self):
        report = self.valid_report()
        bad = []
        bad.append(dict(report, kind="release-seal-audit-chain-v3"))
        bad.append(dict(report, version=1))
        bad.append(dict(report, sequence=0))
        bad.append(dict(report, sequence=True))
        bad.append(dict(report, sequence=1.5))
        bad.append(dict(report, previous_sha256="0" * 64))  # genesis must be null
        successor = dict(report, sequence=2)
        bad.append(successor)  # successor needs a digest, not null
        bad.append(dict(report, batch_sha256="0" * 63))
        bad.append(dict(report, valid="yes"))
        bad.append(dict(report, extra=1))
        missing = dict(report)
        del missing["previous_sha256"]
        bad.append(missing)
        bad.append(dict(report, summary={"total": 1, "passed": 1,
                                         "failed": 0, "errors": 1}))
        flipped = json.loads(json.dumps(report))
        flipped["results"][0]["outcome"] = "failed"
        bad.append(flipped)
        for index, document in enumerate(bad):
            with self.subTest(case=index):
                with self.assertRaises(SealError):
                    validate_chain_report_document(document)


class VerifyChainTests(ChainTestCase):
    def test_valid_chain(self):
        paths = self.make_chain(3)
        code, result = verify_chain(sha256_of(paths[-1]), paths)
        self.assertEqual(code, 0)
        self.assertEqual(
            result,
            {
                "valid": True,
                "count": 3,
                "head_sha256": sha256_of(paths[-1]),
            },
        )

    def test_single_report_chain(self):
        paths = self.make_chain(1)
        code, result = verify_chain(sha256_of(paths[0]), paths)
        self.assertEqual(code, 0)
        self.assertEqual(result["count"], 1)

    def test_wrong_head_is_broken_at_last_index(self):
        paths = self.make_chain(2)
        code, result = verify_chain("0" * 64, paths)
        self.assertEqual(code, 1)
        self.assertEqual(
            result,
            {"valid": False, "reason": "broken_chain", "index": 1},
        )

    def test_non_genesis_start_is_broken_at_zero(self):
        paths = self.make_chain(2)
        code, result = verify_chain(
            sha256_of(paths[1]), [paths[1]],
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["index"], 0)
        self.assertEqual(result["reason"], "broken_chain")

    def test_reversed_order_breaks_the_link(self):
        paths = self.make_chain(2)
        code, result = verify_chain(
            sha256_of(paths[0]), [paths[1], paths[0]],
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["index"], 0)

    def test_tampered_middle_link_is_broken(self):
        paths = self.make_chain(3)
        middle = json.loads(paths[1].read_text(encoding="utf-8"))
        middle["sequence"] = 7
        paths[1].write_text(json.dumps(middle), encoding="utf-8")
        code, result = verify_chain(sha256_of(paths[2]), paths)
        self.assertEqual(code, 1)
        self.assertEqual(result["index"], 1)

    def test_missing_report_is_an_error(self):
        with self.assertRaises(SealError):
            verify_chain("0" * 64, [self.work / "absent.json"])

    def test_malformed_report_is_an_error(self):
        bad = self.work / "bad.json"
        bad.write_bytes(b"not json")
        with self.assertRaises(SealError):
            verify_chain("0" * 64, [bad])

    def test_bad_expected_head_is_an_error(self):
        paths = self.make_chain(1)
        for head in ("", "0" * 63, "0" * 65, "g" * 64, "A" * 64):
            with self.subTest(head=head):
                with self.assertRaises(SealError):
                    verify_chain(head, paths)

    def test_empty_report_list_is_an_error(self):
        with self.assertRaises(SealError):
            verify_chain("0" * 64, [])


class VerifyChainSetTests(ChainTestCase):
    def write_report(self, sequence, previous_sha256, name, *, batch="0" * 64):
        report = {
            "kind": CHAIN_REPORT_KIND,
            "version": 2,
            "sequence": sequence,
            "previous_sha256": previous_sha256,
            "batch_sha256": batch,
            "valid": True,
            "summary": {"total": 0, "passed": 0, "failed": 0, "errors": 0},
            "results": [],
        }
        path = self.work / name
        path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def test_valid_set_in_input_order(self):
        paths = self.make_chain(3)
        code, result = verify_chain_set(sha256_of(paths[-1]), paths)
        self.assertEqual(code, 0)
        self.assertEqual(
            result,
            {
                "valid": True,
                "count": 3,
                "head_sha256": sha256_of(paths[-1]),
            },
        )

    def test_valid_set_in_unknown_order(self):
        paths = self.make_chain(3)
        for ordering in (
            list(reversed(paths)),
            [paths[1], paths[2], paths[0]],
            [paths[2], paths[0], paths[1]],
        ):
            with self.subTest(ordering=[p.name for p in ordering]):
                code, result = verify_chain_set(
                    sha256_of(paths[-1]), ordering
                )
                self.assertEqual(code, 0)
                self.assertTrue(result["valid"])
                self.assertEqual(result["count"], 3)

    def test_single_genesis_report(self):
        paths = self.make_chain(1)
        code, result = verify_chain_set(sha256_of(paths[0]), [paths[0]])
        self.assertEqual(code, 0)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["head_sha256"], sha256_of(paths[0]))

    def test_head_not_found(self):
        paths = self.make_chain(3)
        code, result = verify_chain_set("0" * 64, paths)
        self.assertEqual(code, 1)
        self.assertEqual(
            result,
            {"valid": False, "reason": "broken_chain",
             "problem": "head_not_found"},
        )
        self.assertNotIn("head_sha256", result)

    def test_duplicate_report_same_path_twice(self):
        paths = self.make_chain(2)
        code, result = verify_chain_set(
            sha256_of(paths[-1]), [paths[0], paths[1], paths[1]],
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["problem"], "duplicate_report")

    def test_duplicate_report_bytes_copied_to_another_file(self):
        paths = self.make_chain(2)
        duplicate = self.work / "copy.json"
        duplicate.write_bytes(paths[0].read_bytes())
        code, result = verify_chain_set(
            sha256_of(paths[-1]), [paths[0], paths[1], duplicate],
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["problem"], "duplicate_report")

    def test_missing_previous_when_intermediate_report_absent(self):
        paths = self.make_chain(3)
        code, result = verify_chain_set(
            sha256_of(paths[2]), [paths[0], paths[2]],
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["problem"], "missing_previous")

    def test_missing_previous_when_only_head_given(self):
        paths = self.make_chain(2)
        code, result = verify_chain_set(
            sha256_of(paths[1]), [paths[1]],
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["problem"], "missing_previous")

    def test_invalid_link_when_sequence_does_not_decrement_by_one(self):
        first = self.write_report(1, None, "a.json")
        # Sequence 3 claims a report whose sequence is 1 as its predecessor:
        # the digest exists in the set but the sequence is not 2.
        third = self.write_report(3, sha256_of(first), "c.json")
        code, result = verify_chain_set(
            sha256_of(third), [first, third],
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["problem"], "invalid_link")

    def test_unused_orphan_report_is_not_ignored(self):
        paths = self.make_chain(2)
        orphan = self.write_report(1, None, "orphan.json")
        code, result = verify_chain_set(
            sha256_of(paths[-1]), [*paths, orphan],
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["problem"], "unused_report")

    def test_unused_fork_report_is_not_ignored(self):
        first = self.write_report(1, None, "a.json")
        second = self.write_report(2, sha256_of(first), "b.json")
        fork = self.write_report(
            2, sha256_of(first), "fork.json", batch="1" * 64,
        )
        code, result = verify_chain_set(
            sha256_of(second), [first, second, fork],
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["problem"], "unused_report")

    def test_extra_prefix_reports_are_unused(self):
        paths = self.make_chain(3)
        # Head anchored at report 2 leaves the real report 3 as an orphan.
        code, result = verify_chain_set(
            sha256_of(paths[1]), paths,
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["problem"], "unused_report")

    def test_missing_report_file_is_an_error(self):
        with self.assertRaises(SealError):
            verify_chain_set("0" * 64, [self.work / "absent.json"])

    def test_malformed_report_is_an_error(self):
        bad = self.work / "bad.json"
        bad.write_bytes(b"not json")
        with self.assertRaises(SealError):
            verify_chain_set("0" * 64, [bad])

    def test_structurally_invalid_report_is_an_error(self):
        bad = self.work / "bad.json"
        bad.write_text(json.dumps({"kind": CHAIN_REPORT_KIND}), encoding="utf-8")
        with self.assertRaises(SealError):
            verify_chain_set("0" * 64, [bad])

    def test_bad_expected_head_is_an_error(self):
        paths = self.make_chain(1)
        for head in ("", "0" * 63, "0" * 65, "g" * 64, "A" * 64):
            with self.subTest(head=head):
                with self.assertRaises(SealError):
                    verify_chain_set(head, paths)

    def test_empty_report_list_is_an_error(self):
        with self.assertRaises(SealError):
            verify_chain_set("0" * 64, [])

    def test_reports_are_not_modified(self):
        paths = self.make_chain(2)
        before = [path.read_bytes() for path in paths]
        verify_chain_set(sha256_of(paths[-1]), list(reversed(paths)))
        self.assertEqual([path.read_bytes() for path in paths], before)


class ChainReportInTreeTests(ChainTestCase):
    def test_valid_chain_report_in_tree_is_rejected_by_content(self):
        paths = self.make_chain(1)
        delivery, manifest, public = (
            self.work / "a", self.work / "a.json", self.work / "a-public.pem",
        )
        (delivery / "innocent.txt").write_bytes(paths[0].read_bytes())
        with self.assertRaises(SealError) as caught:
            verify_directory(delivery, manifest, public)
        self.assertIn("audit chain reports must stay outside the delivery tree",
                      str(caught.exception))

    def test_invalid_similar_json_in_tree_is_deliverable(self):
        paths = self.make_chain(1)
        document = json.loads(paths[0].read_text(encoding="utf-8"))
        similar = dict(document, kind="release-seal-audit-chain-v3")
        delivery = self.work / "a"
        (delivery / "notes.json").write_text(json.dumps(similar), encoding="utf-8")
        # Re-sign so the extra file is part of the manifest, then verify.
        _, private, public = write_keypair(self.work, "b")
        manifest = self.work / "b.json"
        sign_directory(delivery, private, manifest)
        result = verify_directory(delivery, manifest, public)
        self.assertTrue(result["valid"])


class AuditChainCliTests(ChainTestCase):
    def test_cli_genesis_and_successor(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        first = self.work / "first.json"
        result = run_cli("audit-chain", batch, "-", first)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        printed = json.loads(result.stdout)
        self.assertEqual(printed["kind"], "release-seal-audit-chain")
        self.assertEqual(printed["sequence"], 1)
        self.assertIsNone(printed["previous_sha256"])
        self.assertEqual(printed, json.loads(first.read_text(encoding="utf-8")))
        second = self.work / "second.json"
        result = run_cli("audit-chain", batch, first, second)
        self.assertEqual(result.returncode, 0, result.stderr)
        printed = json.loads(result.stdout)
        self.assertEqual(printed["sequence"], 2)
        self.assertEqual(printed["previous_sha256"], sha256_of(first))

    def test_cli_batch_exit_code_is_kept(self):
        self.prepare_signed("a", tamper=True)
        batch = self.write_batch([self.verify_item("a")])
        report_path = self.work / "report.json"
        result = run_cli("audit-chain", batch, "-", report_path)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)["valid"])
        self.assertTrue(report_path.exists())

    def test_cli_structural_error_writes_stderr_and_no_report(self):
        batch = self.write_batch([{"id": "a", "command": "verify", "args": []}])
        report_path = self.work / "report.json"
        result = run_cli("audit-chain", batch, "-", report_path)
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")
        self.assertEqual(result.stdout, "")
        self.assertFalse(report_path.exists())

    def test_cli_invalid_previous_writes_stderr_and_no_report(self):
        self.prepare_signed("a")
        batch = self.write_batch([self.verify_item("a")])
        previous = self.work / "previous.json"
        previous.write_bytes(b"{}")
        report_path = self.work / "report.json"
        result = run_cli("audit-chain", batch, previous, report_path)
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")
        self.assertEqual(result.stdout, "")
        self.assertFalse(report_path.exists())

    def test_cli_verify_valid_chain(self):
        paths = self.make_chain(2)
        result = run_cli(
            "audit-chain-verify", sha256_of(paths[-1]), *paths,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        printed = json.loads(result.stdout)
        self.assertEqual(
            printed,
            {"valid": True, "count": 2, "head_sha256": sha256_of(paths[-1])},
        )

    def test_cli_verify_broken_chain(self):
        paths = self.make_chain(2)
        result = run_cli("audit-chain-verify", "0" * 64, *paths)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        printed = json.loads(result.stdout)
        self.assertEqual(
            printed,
            {"valid": False, "reason": "broken_chain", "index": 1},
        )

    def test_cli_verify_format_error_writes_stderr(self):
        bad = self.work / "bad.json"
        bad.write_bytes(b"{}")
        result = run_cli("audit-chain-verify", "0" * 64, bad)
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")
        self.assertEqual(result.stdout, "")

    def test_cli_verify_requires_a_report(self):
        result = run_cli("audit-chain-verify", "0" * 64)
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")

    def test_cli_verify_set_valid_in_any_order(self):
        paths = self.make_chain(3)
        result = run_cli(
            "audit-chain-verify-set",
            sha256_of(paths[-1]),
            *reversed(paths),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        printed = json.loads(result.stdout)
        self.assertEqual(
            printed,
            {"valid": True, "count": 3, "head_sha256": sha256_of(paths[-1])},
        )

    def test_cli_verify_set_broken_chain(self):
        paths = self.make_chain(2)
        result = run_cli(
            "audit-chain-verify-set", "0" * 64, *paths,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertEqual(
            json.loads(result.stdout),
            {"valid": False, "reason": "broken_chain",
             "problem": "head_not_found"},
        )

    def test_cli_verify_set_format_error_writes_stderr(self):
        bad = self.work / "bad.json"
        bad.write_bytes(b"{}")
        result = run_cli("audit-chain-verify-set", "0" * 64, bad)
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")
        self.assertEqual(result.stdout, "")

    def test_cli_verify_set_requires_a_report(self):
        result = run_cli("audit-chain-verify-set", "0" * 64)
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
