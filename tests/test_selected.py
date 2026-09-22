import base64
import json
import os
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
    load_pem_private_key,
)

from release_seal.batch import verify_batch
from release_seal.audit import audit_batch, validate_audit_report_document
from release_seal.inventory import inventory
from release_seal.seal import SealError, sign_directory
from release_seal.selected import verify_selected


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


def make_delivery(root: Path) -> Path:
    delivery = root / "delivery"
    (delivery / "docs").mkdir(parents=True)
    (delivery / "docs" / "readme.txt").write_bytes(b"hello")
    (delivery / "docs" / "guide.txt").write_bytes(b"guide")
    (delivery / "notes.txt").write_bytes(b"notes")
    return delivery


class SelectedTestCase(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.work = Path(self.workspace.name)
        self.delivery = make_delivery(self.work)
        _, self.private, self.public = write_keypair(self.work)
        self.manifest = self.work / "manifest.json"
        sign_directory(self.delivery, self.private, self.manifest)
        self.selection = self.work / "selection.json"

    def write_selection(self, items, *, raw=None) -> Path:
        if raw is not None:
            self.selection.write_bytes(raw)
        else:
            self.selection.write_text(json.dumps(items), encoding="utf-8")
        return self.selection

    def verify(self, selection=None, public=None):
        return verify_selected(
            self.delivery,
            self.manifest,
            public or self.public,
            selection or self.write_selection(["docs/readme.txt"]),
        )


class VerifySelectedTests(SelectedTestCase):
    def test_valid_selection(self):
        result = self.verify(self.write_selection(["notes.txt", "docs/readme.txt"]))
        self.assertEqual(result, {"valid": True, "checked": 2})
        result = run_cli(
            "verify-selected",
            self.delivery, self.manifest, self.public, self.selection,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout), {"valid": True, "checked": 2}
        )

    def test_full_selection_matches_every_file(self):
        paths = [record["path"] for record in inventory(self.delivery)]
        result = self.verify(self.write_selection(paths))
        self.assertEqual(result, {"valid": True, "checked": len(paths)})

    def test_unselected_files_are_not_read(self):
        # Tampering an unselected file must not affect the result; a
        # symlink elsewhere in the tree is never even statted.
        (self.delivery / "notes.txt").write_bytes(b"tampered")
        (self.delivery / "loop").symlink_to(self.work)
        result = self.verify(self.write_selection(["docs/readme.txt"]))
        self.assertEqual(result, {"valid": True, "checked": 1})

    def test_modified_selected_file(self):
        (self.delivery / "docs" / "readme.txt").write_bytes(b"changed")
        (self.delivery / "notes.txt").write_bytes(b"changed too")
        result = self.verify(
            self.write_selection(["docs/readme.txt", "notes.txt"])
        )
        self.assertEqual(result, {
            "valid": False,
            "reason": "file_mismatch",
            "checked": 2,
            "modified": ["docs/readme.txt", "notes.txt"],
            "missing": [],
        })
        result = run_cli(
            "verify-selected",
            self.delivery, self.manifest, self.public, self.selection,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["reason"], "file_mismatch")

    def test_missing_selected_file(self):
        (self.delivery / "docs" / "readme.txt").unlink()
        (self.delivery / "notes.txt").unlink()
        result = self.verify(
            self.write_selection(["docs/readme.txt", "notes.txt"])
        )
        self.assertEqual(result, {
            "valid": False,
            "reason": "file_mismatch",
            "checked": 2,
            "modified": [],
            "missing": ["docs/readme.txt", "notes.txt"],
        })

    def test_missing_parent_directory_counts_as_missing(self):
        (self.delivery / "docs" / "readme.txt").unlink()
        (self.delivery / "docs" / "guide.txt").unlink()
        (self.delivery / "docs").rmdir()
        result = self.verify(self.write_selection(["docs/readme.txt"]))
        self.assertEqual(result["missing"], ["docs/readme.txt"])

    def test_regular_file_where_directory_is_needed_counts_as_missing(self):
        (self.delivery / "docs" / "readme.txt").unlink()
        (self.delivery / "docs" / "guide.txt").unlink()
        (self.delivery / "docs").rmdir()
        (self.delivery / "docs").write_bytes(b"not a directory")
        result = self.verify(self.write_selection(["docs/readme.txt"]))
        self.assertEqual(result["valid"], False)
        self.assertEqual(result["missing"], ["docs/readme.txt"])

    def test_untrusted_manifest_wrong_key(self):
        other = self.work / "other"
        other.mkdir()
        _, _, other_public = write_keypair(other, "other")
        result = self.verify(public=other_public)
        self.assertEqual(result, {
            "valid": False,
            "reason": "untrusted_manifest",
            "checked": 0,
            "modified": [],
            "missing": [],
        })
        result = run_cli(
            "verify-selected",
            self.delivery, self.manifest, other_public, self.selection,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["reason"], "untrusted_manifest")

    def test_untrusted_manifest_tampered_signature(self):
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        document["files"][0]["size"] += 1
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        result = self.verify()
        self.assertEqual(result["reason"], "untrusted_manifest")
        self.assertEqual(result["checked"], 0)

    def test_version_1_manifest_is_accepted(self):
        files = inventory(self.delivery)
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
        result = self.verify(self.write_selection(["notes.txt"]))
        self.assertEqual(result, {"valid": True, "checked": 1})

    def test_malformed_manifest_is_a_format_error(self):
        self.manifest.write_bytes(b"not json")
        with self.assertRaises(SealError):
            self.verify()
        result = run_cli(
            "verify-selected",
            self.delivery, self.manifest, self.public, self.selection,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")

    def test_support_files_must_stay_outside_the_tree(self):
        inside = self.delivery / "selection.json"
        with self.assertRaises(SealError):
            verify_selected(self.delivery, self.manifest, self.public, inside)
        with self.assertRaises(SealError):
            verify_selected(
                self.delivery, self.delivery / "manifest.json",
                self.public, self.selection,
            )
        with self.assertRaises(SealError):
            verify_selected(
                self.delivery, self.manifest,
                self.delivery / "public.pem", self.selection,
            )


class SelectionValidationTests(SelectedTestCase):
    def assertRejected(self, items=None, *, raw=None):
        selection = self.write_selection(items, raw=raw)
        with self.assertRaises(SealError):
            verify_selected(self.delivery, self.manifest, self.public, selection)
        result = run_cli(
            "verify-selected",
            self.delivery, self.manifest, self.public, selection,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")
        self.assertEqual(result.stdout, "")

    def test_not_json(self):
        self.assertRejected(raw=b"not json")

    def test_not_utf8(self):
        self.assertRejected(raw=b"\xff\xfe")

    def test_not_an_array(self):
        self.assertRejected(raw=b'{"path": "notes.txt"}')

    def test_empty_array(self):
        self.assertRejected([])

    def test_non_string_entries(self):
        self.assertRejected(["notes.txt", 7])

    def test_duplicate_entries(self):
        self.assertRejected(["notes.txt", "notes.txt"])

    def test_absolute_path(self):
        self.assertRejected(["/notes.txt"])

    def test_empty_segments(self):
        self.assertRejected(["docs//readme.txt"])
        self.assertRejected(["docs/"])
        self.assertRejected([""])

    def test_dot_segments(self):
        self.assertRejected(["./notes.txt"])
        self.assertRejected(["docs/./readme.txt"])
        self.assertRejected(["."])

    def test_dotdot_segments(self):
        self.assertRejected(["../manifest.json"])
        self.assertRejected(["docs/../notes.txt"])
        self.assertRejected([".."])

    def test_backslash(self):
        self.assertRejected(["docs\\readme.txt"])

    def test_path_not_in_manifest(self):
        self.assertRejected(["no-such-file.txt"])

    def test_invalid_selection_reads_no_delivery_files(self):
        # A symlink inside the tree would fail any scan; an invalid
        # selection must be rejected before anything is read.
        (self.delivery / "loop").symlink_to(self.work)
        self.assertRejected(["docs/../notes.txt"])


class SelectedSafetyTests(SelectedTestCase):
    def test_symlink_as_selected_file_is_rejected(self):
        target = self.delivery / "docs" / "readme.txt"
        target.unlink()
        target.symlink_to(self.delivery / "notes.txt")
        with self.assertRaises(SealError) as caught:
            self.verify()
        self.assertIn("symbolic links are not supported", str(caught.exception))

    def test_symlink_as_parent_directory_is_rejected(self):
        (self.delivery / "docs" / "readme.txt").unlink()
        (self.delivery / "docs" / "guide.txt").unlink()
        (self.delivery / "docs").rmdir()
        (self.delivery / "docs").symlink_to(self.work)
        with self.assertRaises(SealError) as caught:
            self.verify()
        self.assertIn("symbolic links are not supported", str(caught.exception))

    def test_special_file_as_selected_file_is_rejected(self):
        target = self.delivery / "docs" / "readme.txt"
        target.unlink()
        os.mkfifo(target)
        with self.assertRaises(SealError) as caught:
            self.verify()
        self.assertIn("expected an ordinary file", str(caught.exception))

    def test_special_file_as_parent_directory_is_rejected(self):
        (self.delivery / "docs" / "readme.txt").unlink()
        (self.delivery / "docs" / "guide.txt").unlink()
        (self.delivery / "docs").rmdir()
        os.mkfifo(self.delivery / "docs")
        with self.assertRaises(SealError) as caught:
            self.verify()
        self.assertIn("expected a directory", str(caught.exception))

    def test_file_replaced_between_stat_and_open_is_an_error(self):
        from release_seal import selected as selected_module

        replacement = self.work / "replacement"
        replacement.write_bytes(b"replacement content")
        target = self.delivery / "docs" / "readme.txt"
        original = selected_module._hash_selected_file

        def racing(path, before):
            os.replace(replacement, path)
            return original(path, before)

        selected_module._hash_selected_file = racing
        try:
            with self.assertRaises(SealError) as caught:
                self.verify()
        finally:
            selected_module._hash_selected_file = original
        self.assertIn("changed while reading", str(caught.exception))

    def test_file_replaced_during_read_is_an_error(self):
        from release_seal import selected as selected_module

        replacement = self.work / "replacement"
        replacement.write_bytes(b"replacement content")
        target = self.delivery / "docs" / "readme.txt"
        real_fdopen = os.fdopen

        def racing(fd, mode, *args, **kwargs):
            source = real_fdopen(fd, mode, *args, **kwargs)
            os.replace(replacement, target)
            return source

        selected_module.os.fdopen = racing
        try:
            with self.assertRaises(SealError) as caught:
                self.verify()
        finally:
            selected_module.os.fdopen = real_fdopen
        self.assertIn("changed while reading", str(caught.exception))


class SelectedBatchTests(SelectedTestCase):
    def write_batch(self, items, *, name: str = "batch.json") -> Path:
        path = self.work / name
        path.write_text(json.dumps(items), encoding="utf-8")
        return path

    def selected_item(self, selection_name="selection.json"):
        return {
            "id": "selected-id",
            "command": "verify-selected",
            "args": ["delivery", "manifest.json", "key-public.pem", selection_name],
        }

    def test_batch_runs_verify_selected_items(self):
        self.write_selection(["docs/readme.txt", "notes.txt"])
        batch = self.write_batch([self.selected_item()])
        code, report = verify_batch(batch)
        self.assertEqual(code, 0, report)
        self.assertEqual(report["results"][0]["code"], 0)
        self.assertEqual(
            report["results"][0]["result"], {"valid": True, "checked": 2}
        )

    def test_batch_verify_selected_mismatch_and_error(self):
        (self.delivery / "notes.txt").write_bytes(b"tampered")
        self.write_selection(["notes.txt"])
        bad = self.work / "bad-selection.json"
        bad.write_text(json.dumps(["notes.txt", "notes.txt"]), encoding="utf-8")
        batch = self.write_batch([
            self.selected_item(),
            {
                "id": "bad-selection",
                "command": "verify-selected",
                "args": ["delivery", "manifest.json", "key-public.pem",
                         "bad-selection.json"],
            },
        ])
        code, report = verify_batch(batch)
        self.assertEqual(code, 2)
        failed, errored = report["results"]
        self.assertEqual(failed["code"], 1)
        self.assertEqual(failed["result"]["reason"], "file_mismatch")
        self.assertEqual(failed["result"]["modified"], ["notes.txt"])
        self.assertEqual(errored["code"], 2)
        self.assertNotEqual(errored["error"], "")

    def test_batch_rejects_wrong_arity(self):
        batch = self.write_batch([
            {"id": "x", "command": "verify-selected",
             "args": ["delivery", "manifest.json", "key-public.pem"]},
        ])
        with self.assertRaises(SealError):
            verify_batch(batch)

    def test_audit_batch_covers_verify_selected(self):
        self.write_selection(["docs/readme.txt"])
        batch = self.write_batch([self.selected_item()])
        report_path = self.work / "report.json"
        code, report = audit_batch(batch, report_path)
        self.assertEqual(code, 0)
        entry = report["results"][0]
        self.assertEqual(entry["command"], "verify-selected")
        self.assertEqual(entry["outcome"], "passed")
        self.assertEqual(entry["result"], {"valid": True, "checked": 1})
        published = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(validate_audit_report_document(published), published)

    def test_audit_chain_covers_verify_selected(self):
        from release_seal.chain import audit_chain, validate_chain_report_document

        self.write_selection(["docs/readme.txt"])
        batch = self.write_batch([self.selected_item()])
        report_path = self.work / "chain.json"
        code, report = audit_chain(batch, "-", report_path)
        self.assertEqual(code, 0)
        self.assertEqual(report["results"][0]["command"], "verify-selected")
        published = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(validate_chain_report_document(published), published)


if __name__ == "__main__":
    unittest.main()
