"""Behavioural checks with generated inert text and synthetic classifications."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
import aegis
from run_control_demo import create_demo


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp.name) / "control"
        self.report = create_demo(self.workspace)
        self.rows = aegis.read_csv(self.workspace / "manifest.csv", aegis.SAMPLE_FIELDS)
        self.config = json.loads((self.workspace / "run.json").read_text())
        self.samples = aegis.validate_samples(self.rows, self.workspace)

    def tearDown(self):
        self.temp.cleanup()

    def test_complete_control_path_and_missing_result(self):
        self.assertFalse(self.report["experiment_results"])
        self.assertEqual(3, self.report["registered_evaluation_records"])
        self.assertEqual(2, self.report["paired_records"])
        self.assertEqual(["control-04"], self.report["missing_comparison_ids"])
        self.assertEqual(aegis.fraction(1, 2), self.report["benign"]["combined_positive"])
        self.assertEqual(1, self.report["benign"]["additional_positive"])
        self.assertIsNone(self.report["detection_loss"]["rate"])

    def test_changed_file_rejected(self):
        (self.workspace / self.rows[0]["path"]).write_text("changed content")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            aegis.validate_samples(self.rows, self.workspace)

    def test_duplicate_id_or_hash_rejected(self):
        for field in ("sample_id", "sha256"):
            rows = copy.deepcopy(self.rows)
            rows[1][field] = rows[0][field]
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "duplicate"):
                aegis.validate_samples(rows, self.workspace)

    def test_related_project_cannot_cross_split(self):
        self.rows[1]["project_id"] = self.rows[0]["project_id"]
        with self.assertRaisesRegex(ValueError, "Project crosses"):
            aegis.validate_samples(self.rows, self.workspace)

    def test_escaping_and_symlink_paths_rejected(self):
        for path in ("../outside.txt", "/outside.txt", "controls/../controls/control-01.txt"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                aegis.local_file(self.workspace, path)
        (self.workspace / "link.txt").symlink_to(self.workspace / self.rows[0]["path"])
        with self.assertRaisesRegex(ValueError, "Symlink"):
            aegis.local_file(self.workspace, "link.txt")

    def test_parent_must_be_original_and_in_same_split(self):
        self.rows[0].update(kind="original", family_id="synthetic-family", functionality="PASS")
        self.rows[1].update(kind="variant", family_id="synthetic-family", functionality="PASS",
                            parent_id=self.rows[0]["sample_id"])
        with self.assertRaisesRegex(ValueError, "cross-split parent"):
            aegis.validate_samples(self.rows, self.workspace)

    def test_same_family_can_have_distinct_originals_in_each_split(self):
        for row in self.rows[:2]:
            row.update(kind="original", family_id="synthetic-family", functionality="PASS")
        self.assertEqual(4, len(aegis.validate_samples(self.rows, self.workspace)))

    def test_stale_foreign_duplicate_and_invalid_observations_rejected(self):
        base = aegis.read_csv(self.workspace / "observations.csv", aegis.OBSERVATION_FIELDS)
        for field, value in (("sha256", "a" * 64), ("run_id", "different"),
                             ("state_id", "different"), ("status", "CLEAN"),
                             ("tool", "other"), ("observed_at", "2026-01-01T00:00:00"),
                             ("evidence", "missing.txt")):
            rows = copy.deepcopy(base)
            rows[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                aegis.validate_observations(rows, self.samples, self.config, self.workspace)
        with self.assertRaisesRegex(ValueError, "Duplicate observation"):
            aegis.validate_observations(base + base[:1], self.samples, self.config, self.workspace)

    def test_incomplete_statuses_are_not_negative(self):
        for status in ("ERROR", "INCONCLUSIVE", "NOT_RUN"):
            self.assertIsNone(aegis.decision(status))
        self.assertIsNone(aegis.combined(False, None))
        self.assertTrue(aegis.combined(True, None))
        self.assertTrue(aegis.combined(None, True))
        self.assertFalse(aegis.combined(False, False))

    def test_known_or_result_can_be_paired_with_known_av(self):
        observations = {(row["sample_id"], "av"): "DETECTED" for row in self.rows}
        report = aegis.summarize(self.samples, observations)
        self.assertEqual(3, report["paired_records"])
        self.assertEqual(3, report["status_counts"]["yara:NOT_RUN"])
        self.assertEqual(aegis.fraction(3, 3), report["benign"]["combined_positive"])

    def test_functionality_and_detected_parent_control_loss_denominator(self):
        # These labels exercise arithmetic only; the files remain inert text.
        rows = copy.deepcopy(self.rows)
        for row in rows:
            row.update(split="evaluation", kind="variant", project_id="synthetic-project",
                       family_id="synthetic-family", functionality="PASS", parent_id=rows[0]["sample_id"])
        rows[0].update(kind="original", parent_id="")
        rows[3]["functionality"] = "FAIL"
        samples = aegis.validate_samples(rows, self.workspace)
        obs = {(rows[0]["sample_id"], "av"): "DETECTED",
               (rows[1]["sample_id"], "av"): "NOT_DETECTED",
               (rows[2]["sample_id"], "av"): "DETECTED",
               (rows[3]["sample_id"], "av"): "NOT_DETECTED"}
        report = aegis.summarize(samples, obs)
        self.assertEqual(aegis.fraction(1, 2), report["detection_loss"])
        self.assertEqual([rows[3]["sample_id"]], report["excluded_functionality_ids"])
        obs[(rows[0]["sample_id"], "av")] = "NOT_DETECTED"
        self.assertEqual(aegis.fraction(0, 0), aegis.summarize(samples, obs)["detection_loss"])
        samples[rows[0]["sample_id"]]["functionality"] = "INCONCLUSIVE"
        self.assertEqual(0, aegis.summarize(samples, obs)["eligible_evaluation_records"])

    def test_calibration_responses_never_change_evaluation(self):
        obs = aegis.validate_observations(
            aegis.read_csv(self.workspace / "observations.csv", aegis.OBSERVATION_FIELDS),
            self.samples, self.config, self.workspace)
        before = aegis.summarize(self.samples, obs)
        obs[(self.rows[0]["sample_id"], "av")] = "DETECTED"
        obs[(self.rows[0]["sample_id"], "yara")] = "DETECTED"
        self.assertEqual(before, aegis.summarize(self.samples, obs))

    def test_public_repository_and_existing_directory_are_protected(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            create_demo(ROOT / "tests/fixtures/generated")
        before = (self.workspace / "manifest.csv").read_bytes()
        with self.assertRaises(FileExistsError):
            create_demo(self.workspace)
        self.assertEqual(before, (self.workspace / "manifest.csv").read_bytes())

    def test_research_mode_cannot_be_misrepresented_as_supported(self):
        self.config["mode"] = "research"
        (self.workspace / "run.json").write_text(json.dumps(self.config))
        with self.assertRaisesRegex(ValueError, "control runs only"):
            aegis.run(self.workspace / "run.json", self.workspace / "manifest.csv", self.workspace / "observations.csv")

    def test_cli_does_not_overwrite_report(self):
        output = self.workspace / "report.json"
        before = output.read_bytes()
        result = subprocess.run([sys.executable, str(ROOT / "src/aegis.py"),
                                 "--config", str(self.workspace / "run.json"),
                                 "--manifest", str(self.workspace / "manifest.csv"),
                                 "--observations", str(self.workspace / "observations.csv"),
                                 "--output", str(output)], capture_output=True, text=True)
        self.assertEqual(1, result.returncode)
        self.assertEqual(before, output.read_bytes())


if __name__ == "__main__":
    unittest.main()
