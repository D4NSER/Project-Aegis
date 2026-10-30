"""Check selected-control staging, real marker checks and constrained cleanup."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from control_workspace import ControlWorkspace


class ControlCycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "workspace"
        self.workspace = ControlWorkspace(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_only_selected_controls_are_checked_and_results_survive_cleanup(self):
        folder, report = self.workspace.run(["marker"])
        self.assertEqual(["marker"], [r["id"] for r in report["files"]])
        self.assertTrue(report["files"][0]["literal_marker_found"])
        self.assertFalse(report["vm_restore_verified"])
        self.assertFalse(report["experiment_results"])
        self.assertFalse((folder / "work").exists())
        self.assertTrue(json.loads((folder / "completion.json").read_text())["work_cleanup_verified"])
        self.assertTrue((folder / "report.json").is_file())
        self.assertEqual(3, len(list((self.root / "controls").glob("*.txt"))))

    def test_repeated_cycles_keep_distinct_results(self):
        first, report = self.workspace.run(["plain", "unicode"])
        second, _ = self.workspace.run(["plain"])
        self.assertNotEqual(first, second)
        self.assertTrue(all(not r["literal_marker_found"] for r in report["files"]))
        self.assertEqual(2, len(self.workspace.recent_runs()))

    def test_changed_or_symlink_source_is_rejected(self):
        path = self.root / "controls/plain.txt"
        path.write_text("modified")
        with self.assertRaisesRegex(ValueError, "source changed"):
            self.workspace.run(["plain"])
        path.unlink()
        path.symlink_to(self.root / "controls/marker.txt")
        with self.assertRaises(ValueError):
            self.workspace.run(["plain"])
        self.assertEqual([], self.workspace.recent_runs())

    def test_invalid_selection_rejected(self):
        for selection in ([], ["plain", "plain"], ["../other"], ["unknown"]):
            with self.subTest(selection=selection), self.assertRaises(ValueError):
                self.workspace.run(selection)

    def test_failed_result_save_preserves_work_and_blocks_next_cycle(self):
        import control_workspace
        original = control_workspace.write_json
        def fail_report(path, value):
            if path.name == "report.json":
                raise OSError("synthetic storage failure")
            return original(path, value)
        with patch.object(control_workspace, "write_json", side_effect=fail_report):
            with self.assertRaises(OSError):
                self.workspace.run(["plain"])
        self.assertEqual(1, len(list((self.root / "runs").glob("*/work/plain.txt"))))
        with self.assertRaisesRegex(ValueError, "recovery"):
            self.workspace.run(["plain"])

    def test_cleanup_failure_keeps_report_and_blocks_next_cycle(self):
        with patch.object(self.workspace, "clean_work", side_effect=OSError("synthetic cleanup failure")):
            with self.assertRaises(OSError):
                self.workspace.run(["plain"])
        self.assertEqual(1, len(self.workspace.recent_runs()))
        self.assertTrue((self.root / "recovery-required.json").exists())

    def test_cleanup_refuses_unowned_directory(self):
        other = self.root / "keep"
        other.mkdir()
        file = other / "plain.txt"
        file.write_text("keep")
        with self.assertRaises(ValueError):
            self.workspace.clean_work(other, ["plain"])
        self.assertEqual("keep", file.read_text())


if __name__ == "__main__":
    unittest.main()
