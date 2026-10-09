"""Trusted tests use only inert locally generated artifacts."""

import base64
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "inspect_artifact.py"
SPEC = importlib.util.spec_from_file_location("trusted_inspector", SCRIPT)
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class InspectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def inspect(self, **limits):
        instance = helper.Inspector(str(self.root), limits)
        self.addCleanup(instance.close)
        return instance

    def write(self, path, data):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        return destination

    def cli(self, *arguments):
        output = io.StringIO()
        with redirect_stdout(output):
            code = helper.main(["--root", str(self.root), *arguments])
        return code, json.loads(output.getvalue())

    def test_inventory_digest_and_unchanged_content(self):
        self.write("space name.txt", b"safe inert content")
        self.write("nested/-file", b"\xff")
        before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        instance = self.inspect()
        instance.inventory()
        items = {item["path"]: item for item in instance.items}
        self.assertEqual(items["space name.txt"]["sha256"],
                         hashlib.sha256(b"safe inert content").hexdigest())
        self.assertEqual(items["nested/-file"]["content_kind"], "binary-or-non-utf8")
        self.assertFalse(instance.partial)
        self.assertEqual(before, {p.relative_to(self.root): p.read_bytes()
                                 for p in self.root.rglob("*") if p.is_file()})

    def test_file_limit_exact_and_one_over(self):
        self.write("a", b"1234")
        self.write("b", b"12345")
        instance = self.inspect(file_bytes=4)
        instance.inventory()
        self.assertEqual(instance.items[0]["status"], "inspected")
        self.assertEqual(instance.items[1]["status"], "skipped")
        self.assertNotIn("sha256", instance.items[1])
        self.assertTrue(instance.partial)

    def test_actual_default_file_threshold(self):
        self.assertEqual(helper.DEFAULTS, {"entries": 10000, "file_bytes": 5242880,
                                         "total_bytes": 104857600, "layers": 3,
                                         "decoded_bytes": 5242880, "seconds": 60})
        self.write("exact", b"x" * helper.DEFAULTS["file_bytes"])
        self.write("over", b"x" * (helper.DEFAULTS["file_bytes"] + 1))
        instance = self.inspect()
        instance.inventory()
        self.assertEqual(instance.items[0]["status"], "inspected")
        self.assertEqual(instance.items[1]["status"], "skipped")

    def test_total_limit(self):
        self.write("a", b"12")
        self.write("b", b"34")
        self.write("c", b"5")
        instance = self.inspect(total_bytes=4)
        instance.inventory()
        self.assertEqual(instance.bytes_read, 4)
        self.assertEqual(instance.items[-1]["status"], "skipped")

    def test_entry_limit_exact_and_over(self):
        self.write("a", b"")
        instance = self.inspect(entries=1)
        instance.inventory()
        self.assertFalse(instance.partial)
        self.write("b", b"")
        instance = self.inspect(entries=1)
        instance.inventory()
        self.assertTrue(instance.partial)
        self.assertIn("entry limit", instance.diagnostics[0])

    def test_symlinks_hardlinks_fifo(self):
        self.write("original", b"data")
        os.symlink(self.root / "original", self.root / "symlink")
        os.link(self.root / "original", self.root / "hardlink")
        os.mkfifo(self.root / "fifo")
        instance = self.inspect()
        instance.inventory()
        self.assertEqual(len(instance.items), 4)
        self.assertTrue(all(item["status"] == "skipped" for item in instance.items))
        with self.assertRaises(helper.EvidenceError):
            instance.read_relative("symlink")

    def test_root_link_and_parent_traversal_refused(self):
        os.symlink(self.root, self.root / "link")
        with self.assertRaises(OSError):
            helper.Inspector(str(self.root / "link"))
        with self.assertRaises(helper.EvidenceError):
            helper.Inspector(str(self.root) + "/../elsewhere")
        instance = self.inspect()
        for path in ("../escape", "/etc/passwd", "a//b", ".", "a/../b", "a\\b"):
            with self.subTest(path=path), self.assertRaises(helper.EvidenceError):
                instance.read_relative(path)

    def test_parent_link_refused(self):
        os.symlink(self.root, self.root / "linked")
        instance = self.inspect()
        with self.assertRaises(OSError):
            instance.read_relative("linked/file")

    def test_disappearing_file_and_permission_failure(self):
        self.write("a", b"data")
        instance = self.inspect()
        with patch.object(helper.os, "open", side_effect=PermissionError("denied")):
            instance.inventory()
        self.assertTrue(instance.partial)
        self.assertIn("PermissionError", instance.items[0]["reason"])
        instance = self.inspect()
        with patch.object(helper.os, "stat", side_effect=FileNotFoundError("gone")):
            instance.inventory()
        self.assertIn("FileNotFoundError", instance.items[0]["reason"])

    def test_change_during_read_gets_no_digest(self):
        path = self.write("a", b"data")
        instance = self.inspect()
        real_read = helper.os.read

        def mutate(fd, count):
            result = real_read(fd, count)
            path.write_bytes(b"changed")
            return result

        with patch.object(helper.os, "read", side_effect=mutate):
            instance.inventory()
        self.assertEqual(instance.items[0]["status"], "skipped")
        self.assertNotIn("sha256", instance.items[0])

    def test_cross_device_file_refused(self):
        self.write("a", b"data")
        instance = self.inspect()
        instance.device += 1
        instance.inventory()
        self.assertIn("cross-device", instance.items[0]["reason"])

    def test_cross_device_directory_refused(self):
        (self.root / "directory").mkdir()
        instance = self.inspect()
        instance.device += 1
        instance.inventory()
        self.assertEqual(instance.items[0]["status"], "skipped")
        self.assertIn("cross-device directory", instance.items[0]["reason"])

    def test_swap_to_symlink_before_open(self):
        path = self.write("a", b"data")
        destination = self.write("outside-simulation", b"must not read")
        instance = self.inspect()
        original_open = helper.os.open

        def swap(name, flags, **kwargs):
            if name == "a":
                path.unlink()
                path.symlink_to(destination)
            return original_open(name, flags, **kwargs)

        with patch.object(helper.os, "open", side_effect=swap):
            with self.assertRaises(OSError):
                instance.read_relative("a")
        self.assertEqual(instance.bytes_read, 0)

    def test_directory_depth_limit(self):
        path = self.root
        for _ in range(130):
            path = path / "d"
            path.mkdir()
        instance = self.inspect()
        instance.inventory()
        self.assertTrue(instance.partial)
        self.assertIn("depth limit", instance.items[0]["reason"])

    def test_deadline(self):
        self.write("a", b"data")
        instance = self.inspect(seconds=1)
        with patch.object(helper.time, "monotonic", return_value=instance.started + 1):
            instance.inventory()
        self.assertTrue(instance.partial)
        self.assertIn("deadline", instance.diagnostics[0])

    def test_unicode_offsets_counts_and_no_source_preview(self):
        self.write("u", "é\nx\u202ey\u200b".encode())
        instance = self.inspect()
        instance.unicode("u")
        item = instance.items[0]
        self.assertEqual(item["control_count"], 2)
        self.assertEqual(item["occurrences"][0]["byte_offset"], 4)
        self.assertEqual(item["occurrences"][0]["line"], 2)
        self.assertNotIn("preview", item)

    def test_unicode_details_limit_and_nonutf8(self):
        self.write("u", ("\u200b" * 257).encode())
        instance = self.inspect()
        instance.unicode("u")
        self.assertTrue(instance.partial)
        self.assertEqual(len(instance.items[0]["occurrences"]), 256)
        self.write("bad", b"\xff")
        instance = self.inspect()
        instance.unicode("bad")
        self.assertEqual(instance.items[0]["status"], "skipped")

    def test_all_transforms_and_provenance(self):
        fixtures = (("base64", b"b2s="), ("hex", b"6f6b"), ("percent", b"%6F%6B"))
        for encoding, data in fixtures:
            with self.subTest(encoding=encoding):
                self.write("encoded", data)
                instance = self.inspect()
                instance.decode("encoded", [encoding])
                item = instance.items[0]
                self.assertEqual(item["transforms"][0]["output_sha256"],
                                 hashlib.sha256(b"ok").hexdigest())
                self.assertNotIn("preview", item)

    def test_decode_cumulative_exact_and_one_over(self):
        self.write("encoded", base64.b64encode(b"6f6b"))
        instance = self.inspect(decoded_bytes=6)
        instance.decode("encoded", ["base64", "hex"])
        self.assertEqual(instance.items[0]["cumulative_decoded_bytes"], 6)
        instance = self.inspect(decoded_bytes=5)
        with self.assertRaises(helper.LimitReached):
            instance.decode("encoded", ["base64", "hex"])
        self.assertEqual(instance.items[0]["status"], "partial")
        self.assertEqual(len(instance.items[0]["transforms"]), 1)
        self.assertEqual(instance.items[0]["cumulative_decoded_bytes"], 4)

    def test_failed_later_transform_retains_provenance(self):
        self.write("encoded", base64.b64encode(b"invalid hex"))
        code, report = self.cli("decode", "encoded", "--encoding", "base64", "--encoding", "hex")
        self.assertEqual(code, 2)
        self.assertEqual(report["items"][0]["status"], "partial")
        self.assertEqual(len(report["items"][0]["transforms"]), 1)

    def test_decode_layer_limit_exact_and_over(self):
        self.write("encoded", b"253336253631")
        instance = self.inspect(layers=3)
        instance.decode("encoded", ["hex", "percent", "hex"])
        self.assertEqual(len(instance.items[0]["transforms"]), 3)
        with self.assertRaises(helper.EvidenceError):
            instance.decode("encoded", ["hex"] * 4)

    def test_each_transform_output_limit_exact_and_over(self):
        for encoding, encoded in (("base64", b"b2s="), ("hex", b"6f6b"), ("percent", b"%6f%6b")):
            with self.subTest(encoding=encoding):
                self.write("encoded", encoded)
                self.inspect(decoded_bytes=2).decode("encoded", [encoding])
                with self.assertRaises(helper.LimitReached):
                    self.inspect(decoded_bytes=1).decode("encoded", [encoding])

    def test_preview_size_limit(self):
        self.write("encoded", base64.b64encode(b"a" * 257))
        instance = self.inspect()
        instance.decode("encoded", ["base64"], preview=True)
        self.assertEqual(len(instance.items[0]["preview"]), 256)
        self.assertTrue(instance.items[0]["preview_truncated"])

    def test_malformed_and_unknown_decoding(self):
        for encoding, data in (("base64", b"%%%"), ("hex", b"0"), ("hex", b"gg"),
                               ("percent", b"%ZZ"), ("percent", b"\xff"), ("other", b"a")):
            with self.subTest(encoding=encoding, data=data):
                self.write("bad", data)
                with self.assertRaises(helper.EvidenceError):
                    self.inspect().decode("bad", [encoding])

    def test_preview_and_json_control_escaping(self):
        self.write("escape\u202e", base64.b64encode(b"\x1b[31m inert"))
        code, report = self.cli("decode", "escape\u202e", "--encoding", "base64", "--preview")
        self.assertEqual(code, 0)
        rendered = json.dumps(report, ensure_ascii=True)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertIn("\\u001b", rendered)

    def test_cli_leading_dash_and_error_codes(self):
        self.write("-input", b"b2s=")
        code, _ = self.cli("decode", "--encoding", "base64", "--", "-input")
        self.assertEqual(code, 0)
        code, report = self.cli("unicode", "missing")
        self.assertEqual(code, 2)
        self.assertEqual(report["coverage"], "failed")
        code, report = self.cli("--file-bytes", "1", "inventory")
        self.assertEqual(code, 1)
        self.assertEqual(report["coverage"], "partial")

    def test_invalid_limits_are_explicit(self):
        for value in ("0", "-1", "61"):
            code, report = self.cli("--seconds", value, "inventory")
            self.assertEqual(code, 2)
            self.assertIn("limits", report["error"])

    def test_helpers_do_not_execute_fixture(self):
        sentinel = self.root / "must-not-exist"
        self.write("untrusted.py", f"open({str(sentinel)!r}, 'w').write('ran')".encode())
        instance = self.inspect()
        instance.inventory()
        self.assertFalse(sentinel.exists())
        self.write("payload", base64.b64encode(b"print('never execute')"))
        self.inspect().decode("payload", ["base64"])
        self.assertFalse(sentinel.exists())

    def test_unsupported_safe_access_fails(self):
        with patch.object(helper.os, "supports_dir_fd", set()):
            with self.assertRaisesRegex(helper.EvidenceError, "no-follow"):
                helper.Inspector(str(self.root))


if __name__ == "__main__":
    unittest.main()
