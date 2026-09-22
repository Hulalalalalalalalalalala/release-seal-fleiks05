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
    load_pem_public_key,
)

from release_seal.seal import SealError, sign_directory
from release_seal.selected import (
    validate_selection,
    validate_selection_path,
    verify_selected,
)


def run_cli(*args) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "release_seal", *map(str, args)],
        capture_output=True, text=True,
    )


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
    (delivery / "café.txt").write_text("café\n", encoding="utf-8")
    (delivery / "top.txt").write_bytes(b"top level")
    return delivery


class SelectedTestCase(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.work = Path(self.workspace.name)
        self.delivery = make_delivery(self.work)
        self.private, self.public = write_keypair(self.work)
        self.manifest = self.work / "manifest.json"
        sign_directory(self.delivery, self.private, self.manifest)
        self.manifest_paths = ["café.txt", "docs/readme.txt", "top.txt"]

    def write_selection(self, entries, *, name: str = "selection.json") -> Path:
        path = self.work / name
        path.write_text(json.dumps(entries), encoding="utf-8")
        return path

    def verify(self, entries):
        selection = self.write_selection(entries)
        return verify_selected(
            self.delivery, self.manifest, self.public, selection
        )


class ValidSelectionTests(SelectedTestCase):
    def test_select_all_files(self):
        result = self.verify(self.manifest_paths)
        self.assertEqual(result, {"valid": True, "checked": 3})

    def test_select_single_file(self):
        result = self.verify(["docs/readme.txt"])
        self.assertEqual(result, {"valid": True, "checked": 1})

    def test_cli_success(self):
        selection = self.write_selection(["top.txt"])
        result = run_cli(
            "verify-selected", self.delivery, self.manifest, self.public, selection
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"valid": True, "checked": 1})

    def test_unselected_extra_file_is_never_checked(self):
        # An unlisted file would fail a full `verify`, but selected
        # verification must neither read nor report it.
        (self.delivery / "extra.txt").write_bytes(b"extra")
        result = self.verify(["top.txt"])
        self.assertEqual(result, {"valid": True, "checked": 1})

    def test_unselected_tampered_file_is_ignored(self):
        (self.delivery / "café.txt").write_bytes(b"tampered")
        result = self.verify(["top.txt", "docs/readme.txt"])
        self.assertTrue(result["valid"])
        self.assertEqual(result["checked"], 2)

    def test_files_are_read_in_manifest_order_not_selection_order(self):
        from release_seal import selected

        order = []
        original = selected._read_selected_file

        def recorder(directory, rel, record):
            order.append(rel)
            return original(directory, rel, record)

        selection = self.write_selection(
            ["top.txt", "café.txt", "docs/readme.txt"]
        )
        selected._read_selected_file = recorder
        try:
            result = verify_selected(
                self.delivery, self.manifest, self.public, selection
            )
        finally:
            selected._read_selected_file = original
        self.assertTrue(result["valid"])
        self.assertEqual(order, ["café.txt", "docs/readme.txt", "top.txt"])


class MismatchTests(SelectedTestCase):
    def test_tampered_selected_file(self):
        (self.delivery / "docs" / "readme.txt").write_bytes(b"changed")
        result = self.verify(self.manifest_paths)
        self.assertEqual(result, {
            "valid": False,
            "reason": "file_mismatch",
            "checked": 3,
            "modified": ["docs/readme.txt"],
            "missing": [],
        })

    def test_missing_selected_file(self):
        (self.delivery / "café.txt").unlink()
        result = self.verify(self.manifest_paths)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "file_mismatch")
        self.assertEqual(result["missing"], ["café.txt"])
        self.assertEqual(result["modified"], [])
        self.assertEqual(result["checked"], 2)

    def test_missing_parent_directory(self):
        import shutil

        shutil.rmtree(self.delivery / "docs")
        result = self.verify(["docs/readme.txt", "top.txt"])
        self.assertEqual(result["reason"], "file_mismatch")
        self.assertEqual(result["missing"], ["docs/readme.txt"])
        self.assertEqual(result["checked"], 1)

    def test_modified_and_missing_are_sorted_regardless_of_selection_order(self):
        (self.delivery / "café.txt").write_bytes(b"changed")
        (self.delivery / "docs" / "readme.txt").unlink()
        result = self.verify(["top.txt", "docs/readme.txt", "café.txt"])
        self.assertEqual(result["reason"], "file_mismatch")
        self.assertEqual(result["modified"], ["café.txt"])
        self.assertEqual(result["missing"], ["docs/readme.txt"])
        self.assertEqual(result["checked"], 2)

    def test_cli_mismatch_returns_1(self):
        (self.delivery / "top.txt").write_bytes(b"changed")
        selection = self.write_selection(["top.txt"])
        result = run_cli(
            "verify-selected", self.delivery, self.manifest, self.public, selection
        )
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertFalse(report["valid"])
        self.assertEqual(report["reason"], "file_mismatch")
        self.assertEqual(report["modified"], ["top.txt"])


class UntrustedManifestTests(SelectedTestCase):
    def test_wrong_public_key(self):
        other_dir = self.work / "other"
        other_dir.mkdir()
        _, other_public = write_keypair(other_dir)
        selection = self.write_selection(["top.txt"])
        result = verify_selected(
            self.delivery, self.manifest, other_public, selection
        )
        self.assertEqual(result, {
            "valid": False,
            "reason": "untrusted_manifest",
            "checked": 0,
            "modified": [],
            "missing": [],
        })

    def test_bad_signature(self):
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        signature = bytearray(base64.b64decode(document["signature"]))
        signature[0] ^= 0xFF
        document["signature"] = base64.b64encode(bytes(signature)).decode("ascii")
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        result = self.verify(["top.txt"])
        self.assertEqual(result["reason"], "untrusted_manifest")
        self.assertEqual(result["checked"], 0)

    def test_key_id_signed_by_other_key(self):
        other_dir = self.work / "other"
        other_dir.mkdir()
        other_private, other_public = write_keypair(other_dir)
        other_key = load_pem_private_key(
            other_private.read_bytes(), password=None
        )
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        other_id = __import__("hashlib").sha256(
            load_pem_public_key(other_public.read_bytes()).public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
        ).hexdigest()
        document["key_id"] = other_id
        payload = json.dumps({
            "version": 2,
            "algorithm": "Ed25519",
            "hash": "SHA-256",
            "key_id": other_id,
            "files": document["files"],
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        document["signature"] = base64.b64encode(
            other_key.sign(payload)
        ).decode("ascii")
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        # Manifest is genuinely signed by the other key: verifying with
        # the original key must report it as untrusted.
        result = self.verify(["top.txt"])
        self.assertEqual(result["reason"], "untrusted_manifest")
        self.assertEqual(result["checked"], 0)

    def test_untrusted_manifest_reads_no_delivery_files(self):
        # Even with a symlink where a regular file should be (which would
        # be a status-2 safety error after trust) and a missing selected
        # file, an untrusted manifest stays a plain code-1 result.
        other_dir = self.work / "other"
        other_dir.mkdir()
        _, other_public = write_keypair(other_dir)
        target = self.work / "outside.txt"
        target.write_bytes(b"top level")
        link = self.delivery / "top.txt"
        link.unlink()
        link.symlink_to(target)
        (self.delivery / "café.txt").unlink()
        selection = self.write_selection(["top.txt", "café.txt"])
        result = verify_selected(
            self.delivery, self.manifest, other_public, selection
        )
        self.assertEqual(result["reason"], "untrusted_manifest")
        self.assertEqual(result["checked"], 0)
        link.unlink()

    def test_cli_untrusted_returns_1(self):
        other_dir = self.work / "other"
        other_dir.mkdir()
        _, other_public = write_keypair(other_dir)
        selection = self.write_selection(["top.txt"])
        result = run_cli(
            "verify-selected", self.delivery, self.manifest, other_public, selection
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            json.loads(result.stdout)["reason"], "untrusted_manifest"
        )


class Version1ManifestTests(SelectedTestCase):
    def test_version_1_manifest_is_accepted(self):
        from release_seal.inventory import inventory

        files = inventory(self.delivery)
        private_key = load_pem_private_key(
            self.private.read_bytes(), password=None
        )
        payload = json.dumps({
            "version": 1,
            "algorithm": "Ed25519",
            "hash": "SHA-256",
            "files": files,
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        document = {
            "version": 1,
            "algorithm": "Ed25519",
            "hash": "SHA-256",
            "files": files,
            "signature": base64.b64encode(private_key.sign(payload)).decode("ascii"),
        }
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        result = self.verify(["top.txt"])
        self.assertEqual(result, {"valid": True, "checked": 1})

    def test_version_3_manifest_is_a_format_error(self):
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        document["version"] = 3
        document["signatures"] = {document.pop("key_id"): document.pop("signature")}
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SealError):
            self.verify(["top.txt"])


class SelectionValidationTests(SelectedTestCase):
    def test_path_shape_rules(self):
        for bad in (
            "/etc/passwd",
            "a\\b",
            ".",
            "..",
            "docs/../readme.txt",
            "docs/./readme.txt",
            "docs//readme.txt",
            "readme.txt/",
            "/readme.txt",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(SealError):
                    validate_selection_path(bad)

    def test_document_rules(self):
        for bad in (
            [],
            ["a", "a"],
            [""],
            [1],
            [None],
            {},
            "top.txt",
            ["a", 1],
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(SealError):
                    validate_selection(bad)

    def test_valid_paths_pass(self):
        self.assertEqual(
            validate_selection(["a", "b/c.txt", "café.txt"]),
            ["a", "b/c.txt", "café.txt"],
        )

    def test_path_not_in_manifest_is_status_2(self):
        # The selection is well-formed and trusted, but the manifest
        # never lists the path.
        with self.assertRaises(SealError) as caught:
            self.verify(["top.txt", "not-in-manifest.txt"])
        self.assertIn("not listed in the manifest", str(caught.exception))

    def test_malformed_selection_file_is_status_2(self):
        selection = self.write_selection(["top.txt"])
        selection.write_bytes(b"not json")
        result = run_cli(
            "verify-selected", self.delivery, self.manifest, self.public, selection
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")

    def test_non_utf8_selection_file_is_status_2(self):
        selection = self.write_selection(["top.txt"])
        selection.write_bytes(b"\xff\xfe" + json.dumps(["top.txt"]).encode())
        result = run_cli(
            "verify-selected", self.delivery, self.manifest, self.public, selection
        )
        self.assertEqual(result.returncode, 2)

    def test_missing_selection_file_is_status_2(self):
        result = run_cli(
            "verify-selected",
            self.delivery, self.manifest, self.public, self.work / "absent.json",
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotEqual(result.stderr, "")

    def test_bad_shape_via_cli_is_status_2(self):
        cases = [["top.txt", "top.txt"], [], ["/top.txt"], ["a\\b.txt"],
                 ["docs/../top.txt"], ["x"]]
        for entries in cases[:-1]:
            selection = self.write_selection(entries)
            result = run_cli(
                "verify-selected",
                self.delivery, self.manifest, self.public, selection,
            )
            self.assertEqual(result.returncode, 2, entries)
        # The last case is a manifest-membership failure, also exit 2.
        selection = self.write_selection(["x"])
        result = run_cli(
            "verify-selected", self.delivery, self.manifest, self.public, selection
        )
        self.assertEqual(result.returncode, 2)


class TreeSafetyTests(SelectedTestCase):
    def test_selection_inside_delivery_is_rejected(self):
        selection = self.delivery / "selection.json"
        selection.write_text(json.dumps(["top.txt"]), encoding="utf-8")
        with self.assertRaises(SealError) as caught:
            verify_selected(
                self.delivery, self.manifest, self.public, selection
            )
        self.assertIn("outside the delivery tree", str(caught.exception))

    def test_manifest_and_key_inside_delivery_are_rejected(self):
        selection = self.write_selection(["top.txt"])
        with self.assertRaises(SealError):
            verify_selected(
                self.delivery, self.delivery / "manifest.json",
                self.public, selection,
            )
        with self.assertRaises(SealError):
            verify_selected(
                self.delivery, self.manifest,
                self.delivery / "public.pem", selection,
            )

    def test_symlinked_selected_file_is_rejected(self):
        outside = self.work / "outside.txt"
        outside.write_bytes(b"top level")
        link = self.delivery / "top.txt"
        link.unlink()
        link.symlink_to(outside)
        try:
            with self.assertRaises(SealError):
                self.verify(["top.txt"])
        finally:
            link.unlink()

    def test_symlinked_parent_directory_is_rejected(self):
        outside_dir = self.work / "outside-dir"
        outside_dir.mkdir()
        (outside_dir / "readme.txt").write_bytes(b"hello")
        docs = self.delivery / "docs"
        import shutil

        shutil.rmtree(docs)
        docs.symlink_to(outside_dir, target_is_directory=True)
        try:
            with self.assertRaises(SealError):
                self.verify(["docs/readme.txt"])
        finally:
            docs.unlink()

    def test_special_file_is_rejected(self):
        target = self.delivery / "top.txt"
        target.unlink()
        os.mkfifo(target)
        try:
            with self.assertRaises(SealError) as caught:
                self.verify(["top.txt"])
            self.assertIn("ordinary file", str(caught.exception))
        finally:
            target.unlink()

    def test_regular_directory_at_file_path_is_rejected(self):
        # Manifest expects docs/readme.txt as a file; make it a directory.
        target = self.delivery / "top.txt"
        target.unlink()
        target.mkdir()
        try:
            with self.assertRaises(SealError):
                self.verify(["top.txt"])
        finally:
            target.rmdir()

    def test_change_detected_via_open_handle_returns_2(self):
        from release_seal import selected

        original = selected._fd_identity
        calls = {"n": 0}

        def flaky(fd, path):
            result = original(fd, path)
            calls["n"] += 1
            if calls["n"] == 2:
                # Post-read fstat reports a newer mtime: a write raced the
                # verification, which must be a status-2 failure.
                return (result[0], result[1], result[2], result[3] + 1)
            return result

        selection = self.write_selection(["top.txt"])
        selected._fd_identity = flaky
        try:
            with self.assertRaises(SealError) as caught:
                verify_selected(
                    self.delivery, self.manifest, self.public, selection
                )
        finally:
            selected._fd_identity = original
        self.assertIn("changed while reading", str(caught.exception))


class SelectedBatchTests(SelectedTestCase):
    def write_batch(self, items, *, name: str = "batch.json") -> Path:
        path = self.work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(items), encoding="utf-8")
        return path

    def selected_item(self, item_id="sel", selection="selection.json"):
        self.write_selection(["top.txt"], name=selection)
        return {
            "id": item_id,
            "command": "verify-selected",
            "args": ["delivery", "manifest.json", "public.pem", selection],
        }

    def test_batch_item_passes(self):
        from release_seal.batch import verify_batch

        batch = self.write_batch([self.selected_item()])
        code, report = verify_batch(batch)
        self.assertEqual(code, 0)
        self.assertEqual(report["summary"],
                         {"total": 1, "passed": 1, "failed": 0, "errors": 0})
        self.assertEqual(
            report["results"][0]["result"], {"valid": True, "checked": 1}
        )

    def test_batch_item_reports_mismatch(self):
        from release_seal.batch import verify_batch

        (self.delivery / "top.txt").write_bytes(b"changed")
        batch = self.write_batch([self.selected_item()])
        code, report = verify_batch(batch)
        self.assertEqual(code, 1)
        result = report["results"][0]["result"]
        self.assertEqual(result["reason"], "file_mismatch")
        self.assertEqual(result["modified"], ["top.txt"])

    def test_batch_item_reports_untrusted(self):
        from release_seal.batch import verify_batch

        other_dir = self.work / "otherkey"
        other_dir.mkdir()
        write_keypair(other_dir)
        self.write_selection(["top.txt"])
        batch = self.write_batch([{
            "id": "sel",
            "command": "verify-selected",
            "args": ["delivery", "manifest.json", "otherkey/public.pem",
                     "selection.json"],
        }])
        code, report = verify_batch(batch)
        self.assertEqual(code, 1)
        self.assertEqual(
            report["results"][0]["result"]["reason"], "untrusted_manifest"
        )

    def test_batch_wrong_arity_is_a_structure_error(self):
        from release_seal.batch import verify_batch

        batch = self.write_batch([{
            "id": "sel",
            "command": "verify-selected",
            "args": ["delivery", "manifest.json", "public.pem"],
        }])
        with self.assertRaises(SealError):
            verify_batch(batch)

    def test_batch_selection_inside_tree_is_code_2_item_error(self):
        from release_seal.batch import verify_batch

        (self.delivery / "selection.json").write_text(
            json.dumps(["top.txt"]), encoding="utf-8"
        )
        batch = self.write_batch([{
            "id": "sel",
            "command": "verify-selected",
            "args": ["delivery", "manifest.json", "public.pem",
                     "delivery/selection.json"],
        }])
        code, report = verify_batch(batch)
        self.assertEqual(code, 2)
        self.assertEqual(report["results"][0]["code"], 2)
        self.assertIn("outside the delivery tree",
                      report["results"][0]["error"])

    def test_audit_batch_and_chain_support_selected_items(self):
        from release_seal.audit import audit_batch
        from release_seal.chain import audit_chain

        batch = self.write_batch([self.selected_item()])
        report = self.work / "audit.json"
        code, published = audit_batch(batch, report)
        self.assertEqual(code, 0)
        entry = published["results"][0]
        self.assertEqual(entry["command"], "verify-selected")
        self.assertEqual(entry["outcome"], "passed")
        self.assertEqual(entry["result"], {"valid": True, "checked": 1})

        chain = self.work / "chain.json"
        code, chained = audit_chain(batch, "-", chain)
        self.assertEqual(code, 0)
        self.assertEqual(
            chained["results"][0]["command"], "verify-selected"
        )

    def test_mid_read_change_item_gets_changed_error_kind(self):
        from release_seal import selected
        from release_seal.audit import audit_batch

        original = selected._fd_identity
        calls = {"n": 0}

        def flaky(fd, path):
            result = original(fd, path)
            calls["n"] += 1
            if calls["n"] == 2:
                # Second identity probe is the post-read fstat: a raced
                # write must classify as the stable "changed" error kind.
                return (result[0], result[1], result[2], result[3] + 1)
            return result

        batch = self.write_batch([self.selected_item()])
        selected._fd_identity = flaky
        try:
            code, report = audit_batch(batch, self.work / "audit.json")
        finally:
            selected._fd_identity = original
        self.assertEqual(code, 2)
        self.assertEqual(
            report["results"][0]["error_kind"], "changed"
        )


if __name__ == "__main__":
    unittest.main()
