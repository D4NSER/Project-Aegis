"""Protocol checks with inert texts; these are not evidence of a Windows run."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import guest_control
from control_workspace import CONTROLS


class GuestControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve() / ("guest-control-" + "a" * 32)
        self.root.mkdir()
        self.request = {"schema": 1, "run_id": self.root.name,
                        "nonce": "b" * 64, "selected": ["marker", "unicode"]}
        self.write_request()
        for key in self.request["selected"]:
            (self.root / (key + ".txt")).write_bytes(CONTROLS[key][1])

    def tearDown(self):
        self.temp.cleanup()

    def write_request(self):
        (self.root / "request.json").write_text(json.dumps(self.request), encoding="utf-8")

    def test_selected_transfer_hashes_and_marker_remain_without_restore_claim(self):
        report = guest_control.run_control(self.root)
        self.assertEqual(["marker", "unicode"], [row["id"] for row in report["files"]])
        self.assertEqual([True, False], [row["literal_marker_found"] for row in report["files"]])
        self.assertEqual(self.request["nonce"], report["nonce"])
        self.assertTrue((self.root / "mutation.json").exists())
        self.assertTrue((self.root / "unicode.txt").exists())
        saved = json.loads((self.root / "guest-report.json").read_text())
        self.assertEqual(report, saved)
        self.assertFalse(saved["experiment_results"])
        self.assertFalse(saved["vm_restore_verified"])
        self.assertFalse(saved["work_cleanup_performed"])
        self.assertEqual("NOT_RUN", saved["files"][0]["av_status"])
        with self.assertRaises(ValueError):
            guest_control.run_control(self.root)

    def test_tampered_transfer_and_unselected_extra_are_rejected(self):
        text = self.root / "marker.txt"
        text.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "mismatch"):
            guest_control.run_control(self.root)
        text.write_bytes(CONTROLS["marker"][1])
        (self.root / "plain.txt").write_bytes(CONTROLS["plain"][1])
        with self.assertRaisesRegex(ValueError, "Unexpected files"):
            guest_control.run_control(self.root)
        self.assertFalse((self.root / "mutation.json").exists())

    def test_request_identity_and_selection_cannot_redirect_work(self):
        for field, value in (("run_id", "../other"), ("nonce", "bad"),
                             ("schema", True), ("selected", ["../outside"]),
                             ("selected", ["plain", "plain"]), ("selected", [None])):
            original = self.request[field]
            self.request[field] = value
            self.write_request()
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                guest_control.run_control(self.root)
            self.request[field] = original
        self.assertFalse((self.root / "mutation.json").exists())

    def test_symlink_input_is_rejected(self):
        target = self.root.parent / "keep.txt"
        target.write_bytes(CONTROLS["marker"][1])
        path = self.root / "marker.txt"
        path.unlink()
        path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "links"):
            guest_control.run_control(self.root)
        self.assertEqual(CONTROLS["marker"][1], target.read_bytes())

    def test_failed_report_keeps_marker_and_rejects_retry(self):
        original = guest_control.write_json
        def fail_report(path, value):
            if path.name == "guest-report.json":
                raise OSError("synthetic result failure")
            original(path, value)
        with patch.object(guest_control, "write_json", side_effect=fail_report):
            with self.assertRaises(OSError):
                guest_control.run_control(self.root)
        self.assertTrue((self.root / "mutation.json").exists())
        with self.assertRaises(ValueError):
            guest_control.run_control(self.root)


if __name__ == "__main__":
    unittest.main()
