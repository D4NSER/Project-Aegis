"""Behavioural checks with generated inert text and synthetic classifications.

Labels such as "original" or "variant" below exercise accounting arithmetic
only. Every file is a short inert UTF-8 text written by the test itself.
Expected values are counted by hand in the comments next to each scenario.
"""
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

CARD = "c" * 64
OTHER_CARD = "d" * 64


class Workspace:
    """Builds inert manifest rows, files and functionality records."""

    def __init__(self, root):
        self.root = root
        root.mkdir()
        (root / "files").mkdir()
        (root / "records").mkdir()
        self.rows = []

    def add(self, sample_id, kind, split, project, *, family="family-x", parent="", order="", holdout="",
            functionality=None, card=CARD, content=None, synthetic=True):
        if functionality is None:
            functionality = {"benign": "NOT_APPLICABLE", "control_copy": "NOT_APPLICABLE"}.get(kind, "PASS")
        if kind == "benign":
            family = ""
        relative = "files/" + sample_id + ".txt"
        data = content if content is not None else ("Inert accounting fixture " + sample_id + "\n").encode()
        (self.root / relative).write_bytes(data)
        sha = aegis.digest(self.root / relative)
        tested = functionality in aegis.TESTED_FUNCTIONALITY
        evidence = ""
        if tested:
            evidence = "records/" + sample_id + ".json"
            (self.root / evidence).write_text(json.dumps({
                "schema": 1, "kind": "functionality_record", "record_id": "card-check-" + sample_id,
                "sample_sha256": sha, "card_sha256": card, "status": functionality, "synthetic": synthetic}))
        row = dict(zip(aegis.SAMPLE_FIELDS, [
            sample_id, project, family, split, kind, parent, str(order) if order else "", holdout,
            sha, relative, functionality, card if tested else "", evidence,
            "generated inert text", "fixture-v1", "Known inert UTF-8 content", "text", "none"]))
        self.rows.append(row)
        return row

    def samples(self):
        return aegis.validate_samples(copy.deepcopy(self.rows), self.root)


def scenario(root):
    """Two splits with every inclusion path the protocol names."""
    ws = Workspace(root)
    # Evaluation: original E1 with an identical control copy and three variants.
    e1 = ws.add("E1", "original", "evaluation", "proj-E1")
    ws.add("E1-copy", "control_copy", "evaluation", "proj-E1", parent="E1",
           content=(root / e1["path"]).read_bytes())
    ws.add("E1-v1", "variant", "evaluation", "proj-E1", parent="E1", order=1)
    ws.add("E1-v2", "variant", "evaluation", "proj-E1", parent="E1", order=2)
    ws.add("E1-v3", "variant", "evaluation", "proj-E1", parent="E1", order=3, functionality="FAIL")
    for index in range(1, 5):
        ws.add("B%d" % index, "benign", "evaluation", "benign-%d" % index)
    # Calibration: C1 has a different control copy and a holdout (v2; v3 failed).
    ws.add("C1", "original", "calibration", "proj-C1")
    ws.add("C1-copy", "control_copy", "calibration", "proj-C1", parent="C1")
    ws.add("C1-v1", "variant", "calibration", "proj-C1", parent="C1", order=1, holdout="false")
    ws.add("C1-v2", "variant", "calibration", "proj-C1", parent="C1", order=2, holdout="true")
    ws.add("C1-v3", "variant", "calibration", "proj-C1", parent="C1", order=3, functionality="FAIL")
    # C2: control copy not detected. C3: original not detected.
    ws.add("C2", "original", "calibration", "proj-C2")
    ws.add("C2-copy", "control_copy", "calibration", "proj-C2", parent="C2")
    ws.add("C2-v1", "variant", "calibration", "proj-C2", parent="C2", order=1)
    ws.add("C3", "original", "calibration", "proj-C3")
    ws.add("C3-copy", "control_copy", "calibration", "proj-C3", parent="C3")
    ws.add("C3-v1", "variant", "calibration", "proj-C3", parent="C3", order=1)
    ws.add("CB1", "benign", "calibration", "benign-c1")
    observations = {
        ("E1", "av"): "DETECTED", ("E1", "yara"): "NOT_DETECTED",
        ("E1-v1", "av"): "NOT_DETECTED", ("E1-v1", "yara"): "DETECTED",
        ("E1-v2", "av"): "NOT_DETECTED", ("E1-v2", "yara"): "NOT_DETECTED",
        ("E1-v3", "av"): "NOT_DETECTED", ("E1-v3", "yara"): "DETECTED",
        ("B1", "av"): "NOT_DETECTED", ("B1", "yara"): "NOT_DETECTED",
        ("B2", "av"): "NOT_DETECTED", ("B2", "yara"): "DETECTED",
        ("B3", "av"): "DETECTED", ("B3", "yara"): "NOT_DETECTED",
        ("B4", "av"): "NOT_DETECTED", ("B4", "yara"): "ERROR",
        ("C1", "av"): "DETECTED", ("C1-copy", "av"): "DETECTED",
        ("C1-v1", "av"): "DETECTED", ("C1-v2", "av"): "NOT_DETECTED", ("C1-v2", "yara"): "DETECTED",
        ("C2", "av"): "DETECTED", ("C2-copy", "av"): "NOT_DETECTED", ("C2-v1", "av"): "NOT_DETECTED",
        ("C3", "av"): "NOT_DETECTED", ("C3-copy", "av"): "NOT_DETECTED", ("C3-v1", "av"): "NOT_DETECTED",
    }
    return ws, observations


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.workspace = self.base / "control"
        self.report = create_demo(self.workspace)
        self.rows = aegis.read_csv(self.workspace / "manifest.csv", aegis.SAMPLE_FIELDS)
        self.config = json.loads((self.workspace / "run.json").read_text())
        self.samples = aegis.validate_samples(self.rows, self.workspace)

    def tearDown(self):
        self.temp.cleanup()

    def frac(self, value):
        return (value["numerator"], value["denominator"])

    # Demonstration and file identity -------------------------------------------------

    def test_complete_control_path_and_missing_result(self):
        # Evaluation: benign 02 (A0,Y0), 03 (A0,Y1), 04 (A0, YARA not run);
        # synthetic original 06 (A0,Y1). Calibration: benign 01, original 05.
        self.assertFalse(self.report["experiment_results"])
        self.assertEqual(4, self.report["eligible_evaluation_records"])
        self.assertEqual(2, self.report["synthetic_functionality_records"])
        supplement = self.report["supplementation"]
        self.assertEqual("EVALUATED", supplement["status"])
        self.assertEqual(3, supplement["paired_records"])
        self.assertEqual(["control-04"], supplement["incomplete_ids"])
        self.assertEqual((1, 2), self.frac(supplement["tools"]["combined"]["fpr"]))
        self.assertEqual((1, 1), self.frac(supplement["tools"]["combined"]["recall"]))
        self.assertEqual((0, 1), self.frac(supplement["tools"]["av"]["recall"]))
        self.assertEqual((0, 2), self.frac(supplement["tools"]["av"]["fpr"]))
        self.assertEqual(1, supplement["additional_detections"]["all"])
        self.assertEqual(1, supplement["additional_false_positives"])
        bounds = supplement["bounds"]["combined"]
        self.assertEqual((1, 3), self.frac(bounds["missing_as_not_detected"]["fpr"]))
        self.assertEqual((2, 3), self.frac(bounds["missing_as_detected"]["fpr"]))
        loss = self.report["detection_loss"]
        self.assertEqual("CONTROL_COPY_MISSING", loss["by_original"]["control-05"]["status"])
        self.assertEqual("ORIGINAL_NOT_DETECTED", loss["by_original"]["control-06"]["status"])
        self.assertIsNone(loss["pooled"]["rate"])

    def test_recalculation_is_identical(self):
        again = aegis.run(self.workspace / "run.json", self.workspace / "manifest.csv",
                          self.workspace / "observations.csv")
        self.assertEqual(json.loads((self.workspace / "report.json").read_text()), again)

    def test_changed_file_rejected(self):
        (self.workspace / self.rows[0]["path"]).write_text("changed content")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            aegis.validate_samples(self.rows, self.workspace)

    def test_duplicate_id_rejected(self):
        rows = copy.deepcopy(self.rows)
        rows[1]["sample_id"] = rows[0]["sample_id"]
        with self.assertRaisesRegex(ValueError, "duplicate sample ID"):
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

    def test_collection_paths_need_a_collection_root(self):
        collection = self.base / "collection"
        (collection / "objects").mkdir(parents=True)
        (collection / "objects/inert.txt").write_text("Inert collection text\n")
        rows = copy.deepcopy(self.rows)
        rows[0]["path"] = "collection:objects/inert.txt"
        rows[0]["sha256"] = aegis.digest(collection / "objects/inert.txt")
        with self.assertRaisesRegex(ValueError, "collection root"):
            aegis.validate_samples(rows, self.workspace)
        self.assertEqual(6, len(aegis.validate_samples(rows, self.workspace, collection)))
        rows[0]["path"] = "collection:../outside.txt"
        with self.assertRaises(ValueError):
            aegis.validate_samples(rows, self.workspace, collection)

    # Lineage, control copies, holdout --------------------------------------------------

    def test_parent_must_be_original_and_in_same_split(self):
        ws = Workspace(self.base / "lineage")
        ws.add("O", "original", "calibration", "proj")
        ws.add("V", "variant", "evaluation", "proj-other", parent="O", order=1)
        with self.assertRaisesRegex(ValueError, "cross-split parent"):
            ws.samples()

    def test_same_family_can_have_distinct_originals_in_each_split(self):
        ws = Workspace(self.base / "family")
        ws.add("O1", "original", "calibration", "proj-1")
        ws.add("O2", "original", "evaluation", "proj-2")
        self.assertEqual(2, len(ws.samples()))

    def test_identical_control_copy_is_the_only_allowed_duplicate_hash(self):
        ws = Workspace(self.base / "dupes")
        original = ws.add("O", "original", "evaluation", "proj")
        same = (ws.root / original["path"]).read_bytes()
        ws.add("O-copy", "control_copy", "evaluation", "proj", parent="O", content=same)
        self.assertEqual(2, len(ws.samples()))
        for kind, extra in (("variant", {"order": 1}), ("original", {})):
            with self.subTest(kind=kind):
                trial = copy.deepcopy(ws)
                trial.add("X", kind, "evaluation", "proj", parent="O" if kind == "variant" else "",
                          content=same, **extra)
                with self.assertRaisesRegex(ValueError, "Duplicate SHA-256"):
                    trial.samples()
        ws.add("O-copy2", "control_copy", "evaluation", "proj", parent="O")
        with self.assertRaisesRegex(ValueError, "more than one control copy"):
            ws.samples()

    def test_control_copy_fields_are_constrained(self):
        ws = Workspace(self.base / "copyfields")
        ws.add("O", "original", "evaluation", "proj")
        ws.add("O-copy", "control_copy", "evaluation", "proj")
        with self.assertRaisesRegex(ValueError, "needs its original"):
            ws.samples()
        ws.rows[-1].update(parent_id="O", functionality="PASS")
        with self.assertRaisesRegex(ValueError, "no separate functionality"):
            ws.samples()

    def test_holdout_is_the_last_eligible_calibration_variant(self):
        def build(name, flags, functionality=("PASS", "PASS", "PASS"), split="calibration"):
            ws = Workspace(self.base / name)
            ws.add("O", "original", split, "proj")
            for index, (flag, status) in enumerate(zip(flags, functionality), start=1):
                ws.add("V%d" % index, "variant", split, "proj", parent="O", order=index,
                       holdout=flag, functionality=status)
            return ws
        self.assertTrue(build("ok", ["", "", "true"]).samples()["V3"]["holdout"])
        # V3 failed functionality, so V2 is the last eligible one.
        self.assertTrue(build("failed-last", ["", "true", ""], ("PASS", "PASS", "FAIL")).samples()["V2"]["holdout"])
        for name, flags, functionality, split in (
                ("missing", ["", "", ""], ("PASS",) * 3, "calibration"),
                ("wrong", ["true", "", ""], ("PASS",) * 3, "calibration"),
                ("single", ["true", "", ""], ("PASS", "FAIL", "FAIL"), "calibration"),
                ("evaluation", ["", "", "true"], ("PASS",) * 3, "evaluation")):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Holdout flags"):
                build(name, flags, functionality, split).samples()

    def test_generation_order_is_required_and_unique_per_project(self):
        ws = Workspace(self.base / "order")
        ws.add("O", "original", "evaluation", "proj")
        ws.add("V1", "variant", "evaluation", "proj", parent="O", order=1)
        ws.add("V2", "variant", "evaluation", "proj", parent="O", order=1)
        with self.assertRaisesRegex(ValueError, "not unique"):
            ws.samples()
        ws.rows[-1]["generation_order"] = ""
        with self.assertRaisesRegex(ValueError, "positive generation order"):
            ws.samples()
        ws.rows[-1]["generation_order"] = "2"
        ws.rows[0]["generation_order"] = "5"
        with self.assertRaisesRegex(ValueError, "Only a variant"):
            ws.samples()

    # Functionality records -----------------------------------------------------------

    def test_functionality_needs_a_matching_record_and_card(self):
        ws = Workspace(self.base / "functionality")
        ws.add("O", "original", "evaluation", "proj")
        self.assertEqual(1, ws.samples()["O"]["functionality_synthetic"] is True)
        for field, value, message in (("functionality_evidence", "", "card hash and evaluator record"),
                                      ("card_sha256", OTHER_CARD, "does not match"),
                                      ("functionality", "FAIL", "does not match")):
            with self.subTest(field=field):
                trial = copy.deepcopy(ws)
                trial.rows[0][field] = value
                with self.assertRaisesRegex(ValueError, message):
                    trial.samples()

    def test_variant_uses_the_original_card(self):
        ws = Workspace(self.base / "cards")
        ws.add("O", "original", "evaluation", "proj")
        ws.add("V", "variant", "evaluation", "proj", parent="O", order=1, card=OTHER_CARD)
        with self.assertRaisesRegex(ValueError, "original's functionality card"):
            ws.samples()

    def test_untested_original_needs_no_record(self):
        ws = Workspace(self.base / "untested")
        ws.add("O", "original", "evaluation", "proj", functionality="NOT_RUN")
        self.assertIsNone(ws.samples()["O"]["functionality_synthetic"])

    # Observations --------------------------------------------------------------------

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

    def test_empty_rule_set_has_no_yara_observations(self):
        base = aegis.read_csv(self.workspace / "observations.csv", aegis.OBSERVATION_FIELDS)
        self.config["yara"]["ruleset_status"] = "EMPTY"
        with self.assertRaisesRegex(ValueError, "empty rule set"):
            aegis.validate_observations(base, self.samples, self.config, self.workspace)
        av_only = [row for row in base if row["tool"] == "av"]
        self.assertEqual(6, len(aegis.validate_observations(av_only, self.samples, self.config, self.workspace)))

    def test_incomplete_statuses_are_not_negative(self):
        for status in ("ERROR", "INCONCLUSIVE", "NOT_RUN"):
            self.assertIsNone(aegis.decision(status))
        self.assertIsNone(aegis.combined(False, None))
        self.assertTrue(aegis.combined(True, None))
        self.assertTrue(aegis.combined(None, True))
        self.assertFalse(aegis.combined(False, False))

    # Supplementation (evaluation split) ----------------------------------------------

    def test_comparison_requires_both_valid_responses(self):
        # The protocol compares AV and C(x) only where A(x) and Y(x) are both valid,
        # even when AV alone would already make C(x)=1.
        observations = {(row["sample_id"], "av"): "DETECTED" for row in self.rows}
        report = aegis.summarize(self.samples, observations)
        supplement = report["supplementation"]
        self.assertEqual(0, supplement["paired_records"])
        # Regression: zero pairs was reported as EVALUATED.
        self.assertEqual(("NOT_EVALUATED", "NO_PAIRED_RECORDS"), (supplement["status"], supplement["reason"]))
        self.assertEqual(["control-02", "control-03", "control-04", "control-06"], supplement["incomplete_ids"])
        # Status counts cover both splits; the comparison itself uses evaluation only.
        self.assertEqual(6, report["status_counts"]["yara:NOT_RUN"])
        comparison = {row["sample_id"]: row["comparison"] for row in report["rows"]}
        self.assertEqual("YARA_INCOMPLETE", comparison["control-02"])
        self.assertEqual("CALIBRATION_SPLIT", comparison["control-01"])
        self.assertNotIn("supplementation.csv", aegis.tables(report))
        self.assertEqual("NO_PAIRED_RECORDS", aegis.summarize(self.samples, {})["supplementation"]["reason"])

    def test_supplementation_metrics_by_hand(self):
        ws, observations = scenario(self.base / "scenario")
        report = aegis.summarize(ws.samples(), observations)
        supplement = report["supplementation"]
        # Paired evaluation files: E1, E1-v1, E1-v2 (malicious); B1-B3 (benign).
        # E1-v3 failed functionality; B4 has a YARA error.
        self.assertEqual({"malicious": 3, "benign": 3}, supplement["class_sizes"])
        self.assertEqual(["B4"], supplement["incomplete_ids"])
        expected = {
            # tool: (TP, FN, FP, TN), recall, FPR, precision, F1 numerator/denominator
            "av": ((1, 2, 1, 2), (1, 3), (1, 3), (1, 2), (2, 5)),
            "yara": ((1, 2, 1, 2), (1, 3), (1, 3), (1, 2), (2, 5)),
            "combined": ((2, 1, 2, 1), (2, 3), (2, 3), (2, 4), (4, 7)),
        }
        for tool, (counts, recall, fpr, precision, f1) in expected.items():
            value = supplement["tools"][tool]
            with self.subTest(tool=tool):
                self.assertEqual(counts, (value["tp"], value["fn"], value["fp"], value["tn"]))
                self.assertEqual(recall, self.frac(value["recall"]))
                self.assertEqual(fpr, self.frac(value["fpr"]))
                self.assertEqual(precision, self.frac(value["precision"]))
                self.assertEqual(f1, self.frac(value["f1"]))
        combined = supplement["tools"]["combined"]["recall_by_kind"]
        self.assertEqual((1, 1), self.frac(combined["original"]))
        self.assertEqual((1, 2), self.frac(combined["variant"]))
        self.assertEqual({"all": 1, "original": 0, "variant": 1}, supplement["additional_detections"])
        self.assertEqual(1, supplement["additional_false_positives"])
        # Bounds use all eligible evaluation files: B4's missing Y read as 0, then 1.
        bounds = supplement["bounds"]
        self.assertEqual((2, 4), self.frac(bounds["combined"]["missing_as_not_detected"]["fpr"]))
        self.assertEqual((3, 4), self.frac(bounds["combined"]["missing_as_detected"]["fpr"]))
        self.assertEqual((1, 4), self.frac(bounds["yara"]["missing_as_not_detected"]["fpr"]))
        self.assertEqual((2, 4), self.frac(bounds["yara"]["missing_as_detected"]["fpr"]))
        self.assertEqual((2, 3), self.frac(bounds["combined"]["missing_as_detected"]["recall"]))
        self.assertNotIn("precision", bounds["combined"]["missing_as_detected"])

    def test_undefined_precision_and_zero_f1_without_positive_decisions(self):
        value = aegis.confusion([False, False], [False])
        self.assertIsNone(value["precision"]["rate"])
        self.assertEqual(0, value["f1"]["rate"])
        self.assertIsNone(aegis.confusion([], [])["f1"]["rate"])

    def test_calibration_responses_never_change_supplementation(self):
        ws, observations = scenario(self.base / "scenario")
        samples = ws.samples()
        before = aegis.summarize(samples, observations)["supplementation"]
        for key in ("C1", "C1-v1", "CB1"):
            observations[(key, "av")] = "NOT_DETECTED"
            observations[(key, "yara")] = "DETECTED"
        self.assertEqual(before, aegis.summarize(samples, observations)["supplementation"])

    # Detection loss (both splits) ----------------------------------------------------

    def test_detection_loss_by_hand(self):
        ws, observations = scenario(self.base / "scenario")
        report = aegis.summarize(ws.samples(), observations)
        loss = report["detection_loss"]
        by_original = loss["by_original"]
        # E1: identical copy, v1 and v2 lost, v3 not functional -> 2/2.
        self.assertEqual(("ELIGIBLE", "IDENTICAL", (2, 2)),
                         (by_original["E1"]["status"], by_original["E1"]["control_copy"],
                          self.frac(by_original["E1"]["loss"])))
        # C1: different copy detected; v1 kept, v2 (holdout) lost, v3 not functional -> 1/2.
        self.assertEqual(("ELIGIBLE", "DIFFERENT", (1, 2)),
                         (by_original["C1"]["status"], by_original["C1"]["control_copy"],
                          self.frac(by_original["C1"]["loss"])))
        self.assertEqual("CONTROL_COPY_NOT_DETECTED", by_original["C2"]["status"])
        self.assertEqual("ORIGINAL_NOT_DETECTED", by_original["C3"]["status"])
        self.assertEqual((3, 4), self.frac(loss["pooled"]))
        self.assertEqual({"CONTROL_COPY_NOT_DETECTED": 1, "ORIGINAL_NOT_DETECTED": 1,
                          "VARIANT_NOT_FUNCTIONAL": 2}, loss["excluded_variants"])
        rows = {row["sample_id"]: row for row in report["rows"]}
        self.assertEqual("INCLUDED", rows["C1-v2"]["detection_loss"])
        self.assertTrue(rows["C1-v2"]["holdout"])
        self.assertEqual("ORIGINAL_NOT_DETECTED", rows["C3-v1"]["detection_loss"])
        self.assertEqual("CONTROL_COPY", rows["E1-copy"]["comparison"])

    def test_control_copy_outcomes(self):
        ws, observations = scenario(self.base / "scenario")
        samples = ws.samples()
        cases = (
            # identical copy with a contrary valid response
            ({("E1-copy", "av"): "NOT_DETECTED"}, "E1", "CONTROL_COPY_CONFLICT"),
            # identical copy whose own check failed: the original's response stands
            ({("E1-copy", "av"): "ERROR"}, "E1", "ELIGIBLE"),
            # different copy with an incomplete response
            ({("C1-copy", "av"): "ERROR"}, "C1", "CONTROL_COPY_INCOMPLETE"),
            ({("C1-copy", "av"): "NOT_RUN"}, "C1", "CONTROL_COPY_INCOMPLETE"),
            # original incomplete
            ({("C1", "av"): "INCONCLUSIVE"}, "C1", "ORIGINAL_INCOMPLETE"),
        )
        for change, original, status in cases:
            with self.subTest(change=change):
                trial = {**observations, **change}
                self.assertEqual(status, aegis.summarize(samples, trial)["detection_loss"]["by_original"][original]["status"])
        del samples["C1-copy"]
        self.assertEqual("CONTROL_COPY_MISSING",
                         aegis.summarize(samples, observations)["detection_loss"]["by_original"]["C1"]["status"])

    def test_incomplete_variant_response_is_excluded_from_loss(self):
        ws, observations = scenario(self.base / "scenario")
        observations[("E1-v1", "av")] = "ERROR"
        loss = aegis.summarize(ws.samples(), observations)["detection_loss"]
        self.assertEqual((1, 1), self.frac(loss["by_original"]["E1"]["loss"]))
        self.assertEqual(1, loss["excluded_variants"]["VARIANT_INCOMPLETE"])

    # Rule-set states and holdout ------------------------------------------------------

    def test_holdout_rules_reported_separately(self):
        ws, observations = scenario(self.base / "scenario")
        report = aegis.summarize(ws.samples(), observations)
        self.assertEqual(["C1-v2"], report["holdout_rules"]["ids"])
        self.assertEqual((1, 1), self.frac(report["holdout_rules"]["detected"]))
        self.assertNotIn("C1-v2", report["supplementation"]["incomplete_ids"])

    def test_empty_rule_set_means_y_is_zero(self):
        ws, observations = scenario(self.base / "scenario")
        observations = {key: value for key, value in observations.items() if key[1] == "av"}
        report = aegis.summarize(ws.samples(), observations, "EMPTY")
        tools = report["supplementation"]["tools"]
        self.assertEqual(tools["av"]["recall"], tools["combined"]["recall"])
        self.assertEqual(tools["av"]["fpr"], tools["combined"]["fpr"])
        self.assertEqual(0, report["supplementation"]["additional_detections"]["all"])
        self.assertEqual((0, 1), self.frac(report["holdout_rules"]["detected"]))
        self.assertEqual("EMPTY_RULESET", {r["sample_id"]: r for r in report["rows"]}["B1"]["yara_status"])

    def test_supplementation_needs_independent_groups_in_both_splits(self):
        # One original group in calibration and a benign file in evaluation:
        # final rule evaluation is not performed (no evaluation original group).
        ws = Workspace(self.base / "single-group")
        ws.add("O", "original", "calibration", "proj")
        ws.add("B", "benign", "evaluation", "benign-proj")
        observations = {("O", "av"): "DETECTED", ("B", "av"): "NOT_DETECTED", ("B", "yara"): "NOT_DETECTED"}
        report = aegis.summarize(ws.samples(), observations)
        self.assertEqual("NOT_EVALUATED", report["supplementation"]["status"])
        self.assertEqual("INDEPENDENT_GROUPS_MISSING", report["supplementation"]["reason"])
        self.assertEqual({"calibration": 1, "evaluation": 0}, report["supplementation"]["original_groups"])
        self.assertEqual("INDEPENDENT_GROUPS_MISSING", {r["sample_id"]: r for r in report["rows"]}["B"]["comparison"])
        self.assertNotIn("supplementation.csv", aegis.tables(report))
        # A failed evaluation original does not form a group either.
        ws.add("E", "original", "evaluation", "proj-e", functionality="FAIL")
        self.assertEqual("NOT_EVALUATED", aegis.summarize(ws.samples(), observations)["supplementation"]["status"])

    def test_failed_rule_set_leaves_supplementation_unevaluated(self):
        ws, observations = scenario(self.base / "scenario")
        report = aegis.summarize(ws.samples(), observations, "FAILED")
        self.assertEqual("NOT_EVALUATED", report["supplementation"]["status"])
        self.assertEqual("NOT_EVALUATED", report["holdout_rules"]["status"])
        self.assertEqual((3, 4), self.frac(report["detection_loss"]["pooled"]))
        self.assertEqual("RULESET_FAILED", {r["sample_id"]: r for r in report["rows"]}["B1"]["comparison"])

    # Tables and command line ----------------------------------------------------------

    def test_tables_keep_numerators_and_denominators(self):
        ws, observations = scenario(self.base / "scenario")
        output = aegis.tables(aegis.summarize(ws.samples(), observations))
        self.assertIn("combined,recall,2,3,", output["supplementation.csv"])
        self.assertIn("ALL,,,,3,4,0.75", output["detection_loss.csv"])
        self.assertIn("Derinys & 2/3 (66,7\\,\\%)", output["supplementation.tex"])
        self.assertIn("malicious 3, benign 3", output["supplementation.tex"])
        self.assertIn("E1-v3,variant,evaluation,False,FAIL", output["rows.csv"])
        # Benign pairs only: recall has an empty denominator and is printed as undefined.
        benign_only = {(key, tool): "NOT_DETECTED" for key in ("control-02", "control-03") for tool in ("av", "yara")}
        undefined = aegis.tables(aegis.summarize(self.samples, benign_only))
        self.assertIn("0/0 (neapibrėžta)", undefined["supplementation.tex"])

    def test_public_repository_and_existing_directory_are_protected(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            create_demo(ROOT / "tests/fixtures/generated")
        before = (self.workspace / "manifest.csv").read_bytes()
        with self.assertRaises(FileExistsError):
            create_demo(self.workspace)
        self.assertEqual(before, (self.workspace / "manifest.csv").read_bytes())

    def test_research_mode_refuses_simulated_inputs(self):
        self.config.update(mode="research")
        (self.workspace / "run.json").write_text(json.dumps(self.config))
        with self.assertRaisesRegex(ValueError, "synthetic functionality"):
            aegis.run(self.workspace / "run.json", self.workspace / "manifest.csv", self.workspace / "observations.csv")
        self.config.update(mode="experiment")
        (self.workspace / "run.json").write_text(json.dumps(self.config))
        with self.assertRaisesRegex(ValueError, "control or research runs only"):
            aegis.run(self.workspace / "run.json", self.workspace / "manifest.csv", self.workspace / "observations.csv")

    def test_rule_set_status_is_required(self):
        del self.config["yara"]["ruleset_status"]
        (self.workspace / "run.json").write_text(json.dumps(self.config))
        with self.assertRaisesRegex(ValueError, "rule-set status"):
            aegis.run(self.workspace / "run.json", self.workspace / "manifest.csv", self.workspace / "observations.csv")

    def test_cli_does_not_overwrite_report_or_tables(self):
        output = self.workspace / "report.json"
        before = output.read_bytes()
        arguments = [sys.executable, str(ROOT / "src/aegis.py"),
                     "--config", str(self.workspace / "run.json"),
                     "--manifest", str(self.workspace / "manifest.csv"),
                     "--observations", str(self.workspace / "observations.csv")]
        result = subprocess.run(arguments + ["--output", str(output)], capture_output=True, text=True)
        self.assertEqual(1, result.returncode)
        self.assertEqual(before, output.read_bytes())
        tables = self.base / "tables"
        result = subprocess.run(arguments + ["--output", str(self.base / "new.json"), "--tables", str(tables)],
                                capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue((tables / "supplementation.tex").is_file())
        result = subprocess.run(arguments + ["--output", str(self.base / "again.json"), "--tables", str(tables)],
                                capture_output=True, text=True)
        self.assertEqual(1, result.returncode)


if __name__ == "__main__":
    unittest.main()
