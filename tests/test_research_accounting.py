"""Research-mode accounting, the execution guard and configuration segments.

All files are inert text and all detector reports are synthetic records in
the shape the guest checks write; no Defender, YARA or sample runs.
"""
import copy
import csv
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
import aegis
import run_guard
import scan_bridge
from test_accounting import Workspace

STATE_A = {"AMEngineVersion": "1.1.1", "AMProductVersion": "4.18.1", "AntivirusEnabled": True,
           "RealTimeProtectionEnabled": True, "IsTamperProtected": True, "AntivirusSignatureVersion": "1.463.13.0"}
STATE_F = dict(STATE_A, RealTimeProtectionEnabled=False)
RULES = 'rule Aegis_Frozen { strings: $a = "Marker" condition: $a }\n'
FROZEN_AT = "2026-11-27T12:30:00+00:00"


def lookup(detected, source):
    events = [{"id": 1116, "time": "2026-11-27T13:00:30Z", "path": "file:_C:\\x", "source": source}]
    return {"known": True, "detected": detected, "threats": [], "events": events if detected else []}


def freeze_record(status="FROZEN", text=RULES, run_id="run-1"):
    return {"schema": 1, "kind": "ruleset_freeze", "run_id": run_id, "status": status, "reason": None if status == "FROZEN" else "X",
            "frozen_at_utc": FROZEN_AT, "yara_version": "4.6.0",
            "ruleset_sha256": hashlib.sha256(text.encode()).hexdigest() if status == "FROZEN" else None,
            "targets": [], "unknown_av_targets": [], "undecided_targets": [], "incomplete_rules": [], "rules": []}


class ResearchFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ws = Workspace(Path(self.temp.name) / "research")
        for args in (("C1", "original", "calibration", "proj-C"), ("CB1", "benign", "calibration", "benign-c"),
                     ("E1", "original", "evaluation", "proj-E"), ("EB1", "benign", "evaluation", "benign-e")):
            self.ws.add(*args, synthetic=False)
        self.ws.add("E1-v1", "variant", "evaluation", "proj-E", parent="E1", order=1, synthetic=False)
        self.samples = self.ws.samples()
        (self.ws.root / "reports").mkdir()
        run_guard.write_freeze(self.ws.root, "rules", RULES, freeze_record())

    def tearDown(self):
        self.temp.cleanup()

    def av(self, sample_id, status="NOT_DETECTED", detected_by="", started="2026-11-27T13:00:00+00:00", state=None,
           run_id="run-1"):
        state = state or STATE_A
        return {"schema": 1, "kind": "av_check", "run_id": run_id, "scan_id": "av-" + sample_id,
                "sample_id": sample_id, "sha256": self.samples[sample_id]["sha256"], "expected_state": "A",
                "wait_seconds": 7, "started_at_utc": started, "finished_at_utc": started.replace(":00+", ":40+"),
                "defender_before": state, "defender_after": state,
                "realtime": lookup(detected_by == "REALTIME", "Real-Time Protection"),
                "custom_scan": None if detected_by == "REALTIME" else {
                    "timed_out": False, "exit_code": 0, "lookup": lookup(detected_by == "CUSTOM_SCAN", "User")},
                "file_unchanged": True if status == "NOT_DETECTED" else None,
                "status": status, "detected_by": detected_by, "reasons": [],
                "platform": "Windows", "architecture": "ARM64", "code_sha256": "e" * 64}

    def yara(self, statuses, ruleset=None, started="2026-11-27T14:00:00+00:00"):
        return {"schema": 1, "kind": "yara_check", "run_id": "run-1", "scan_id": "yara-batch",
                "expected_state": "F", "defender_state": STATE_F, "yara_version": "4.6.0", "yara_sha256": "f" * 64,
                "ruleset_sha256": ruleset or hashlib.sha256(RULES.encode()).hexdigest(),
                "started_at_utc": started, "finished_at_utc": started.replace(":00:00+", ":01:00+"),
                "files": [{"sample_id": key, "sha256": self.samples[key]["sha256"], "status": status,
                           "rules": ["Aegis_Frozen"] if status == "MATCHED" else [],
                           "reason": None if status in {"MATCHED", "NOT_MATCHED"} else "TIMEOUT"}
                          for key, status in statuses.items()],
                "platform": "Windows", "architecture": "ARM64", "code_sha256": "e" * 64}

    def store(self, name, value):
        (self.ws.root / "reports" / name).write_text(json.dumps(value))
        return "reports/" + name

    def reports(self):
        return [self.store("c1.json", self.av("C1", "DETECTED", "REALTIME", started="2026-11-27T11:00:00+00:00")),
                self.store("cb1.json", self.av("CB1", started="2026-11-27T11:10:00+00:00")),
                # The evaluation original's baseline check may precede the freeze.
                self.store("e1.json", self.av("E1", started="2026-11-27T11:20:00+00:00")),
                self.store("e1v1.json", self.av("E1-v1", "DETECTED", "CUSTOM_SCAN")),
                self.store("eb1.json", self.av("EB1")),
                self.store("yara.json", self.yara({"E1": "MATCHED", "E1-v1": "NOT_MATCHED", "EB1": "NOT_MATCHED"}))]

    def prepare(self, paths=None, change=None, series=None):
        paths = paths or self.reports()
        rows, states = scan_bridge.observations(paths, self.samples, "run-1", self.ws.root)
        series = paths if series is None else series
        (self.ws.root / "series.json").write_text(json.dumps(
            {"schema": 1, "kind": "detector_series", "run_id": "run-1", "reports": series}))
        split = scan_bridge.segments(series, self.ws.root, "run-1")
        if change:
            change(rows)
        for name, fields, values in (("manifest.csv", aegis.SAMPLE_FIELDS, self.ws.rows),
                                     ("observations.csv", aegis.OBSERVATION_FIELDS, rows)):
            with (self.ws.root / name).open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields)
                writer.writeheader()
                writer.writerows(values)
        config = {"run_id": "run-1", "mode": "research", "workspace": ".", "protocol_version": "protocol-test",
                  "series": "series.json",
                  "av": {"state_id": states["av"], "segment_id": split["av"][0]["segment_id"] if split["av"] else None},
                  "yara": {"state_id": states["yara"], "ruleset_status": "FROZEN",
                           "segment_id": split["yara"][0]["segment_id"] if split["yara"] else None,
                           "ruleset_sha256": hashlib.sha256(RULES.encode()).hexdigest(),
                           "freeze_record": "rules/freeze.json"}}
        return config

    def run_with(self, config):
        (self.ws.root / "run.json").write_text(json.dumps(config))
        return aegis.run(self.ws.root / "run.json", self.ws.root / "manifest.csv", self.ws.root / "observations.csv")


class ResearchModeTests(ResearchFixture):
    def test_research_run_from_validated_reports(self):
        report = self.run_with(self.prepare())
        self.assertEqual(("research", True), (report["mode"], report["experiment_results"]))
        self.assertEqual({"AMProductVersion": "4.18.1", "AMEngineVersion": "1.1.1",
                          "AntivirusSignatureVersion": "1.463.13.0"}, report["tool_states"]["av"])
        self.assertEqual("4.6.0", report["tool_states"]["yara"]["version"])
        supplement = report["supplementation"]
        self.assertEqual("EVALUATED", supplement["status"])
        # E1 (A0,Y1), E1-v1 (A1,Y0), EB1 (A0,Y0): combined recall 2/2, one additional detection.
        self.assertEqual((2, 2), (supplement["tools"]["combined"]["recall"]["numerator"],
                                  supplement["tools"]["combined"]["recall"]["denominator"]))
        self.assertEqual(1, supplement["additional_detections"]["all"])
        rows = {r["sample_id"]: r for r in report["rows"]}
        self.assertEqual("CUSTOM_SCAN", rows["E1-v1"]["av_detected_by"])

    def test_synthetic_functionality_records_refused(self):
        config = self.prepare()
        self.ws.rows[0]["functionality_evidence"] = ""
        trial = Workspace(Path(self.temp.name) / "synthetic")
        trial.add("O", "original", "evaluation", "proj")
        with self.assertRaisesRegex(ValueError, "synthetic functionality"):
            aegis.research_evidence(config, trial.samples(), [], trial.root)

    def test_rows_must_equal_their_evidence(self):
        def tamper(rows):
            next(r for r in rows if r["sample_id"] == "EB1" and r["tool"] == "av")["status"] = "DETECTED"
            next(r for r in rows if r["sample_id"] == "EB1" and r["tool"] == "av")["detected_by"] = "REALTIME"
        with self.assertRaisesRegex(ValueError, "differ from their evidence"):
            self.run_with(self.prepare(change=tamper))
        def drop(rows):
            rows.remove(next(r for r in rows if r["sample_id"] == "EB1" and r["tool"] == "yara"))
        with self.assertRaisesRegex(ValueError, "differ from their evidence"):
            self.run_with(self.prepare(change=drop))
        (self.ws.root / "reports/note.txt").write_text("not a report")
        def foreign(rows):
            rows[0]["evidence"] = "reports/note.txt"
        with self.assertRaises(ValueError):
            self.run_with(self.prepare(change=foreign))

    def test_freeze_record_and_configuration_must_agree(self):
        config = self.prepare()
        for change in ({"ruleset_sha256": "0" * 64}, {"ruleset_status": "EMPTY"}, {"freeze_record": None}):
            trial = copy.deepcopy(config)
            trial["yara"].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.run_with(trial)
        (self.ws.root / "rules/frozen.yar").write_text(RULES + "// edited\n")
        with self.assertRaisesRegex(ValueError, "changed after freezing"):
            self.run_with(config)

    def test_yara_evidence_must_use_the_frozen_rule_set(self):
        paths = self.reports()[:-1] + [self.store("other.json", self.yara({"E1": "MATCHED"}, ruleset="b" * 64))]
        with self.assertRaisesRegex(ValueError, "other than the frozen one"):
            self.run_with(self.prepare(paths))

    def test_evaluation_av_checks_must_follow_the_freeze(self):
        paths = self.reports()
        paths[4] = self.store("eb1-early.json", self.av("EB1", started="2026-11-27T12:00:00+00:00"))
        with self.assertRaisesRegex(ValueError, "began before the rule set was final"):
            self.run_with(self.prepare(paths))


class ResearchRegressionTests(ResearchFixture):
    def test_segments_cannot_be_combined_across_a_change(self):
        # Regression: A -> B -> A was accepted by joining the first and third segments.
        newer = dict(STATE_A, AntivirusSignatureVersion="1.463.14.0")
        paths = self.reports()
        middle = self.store("middle.json", self.av("CB1", started="2026-11-27T12:50:00+00:00", state=newer))
        # Series: C1, (CB1 old), E1 ... in state A; then CB1 again in state B; then E1-v1, EB1 in state A.
        series = paths[:3] + [middle] + paths[3:]
        config = self.prepare(paths=[p for p in paths], series=series)
        segments = scan_bridge.segments(series, self.ws.root, "run-1")["av"]
        self.assertEqual(3, len(segments))
        with self.assertRaisesRegex(ValueError, "exactly the reports of the named av segment"):
            self.run_with(config)
        config["av"]["segment_id"] = segments[2]["segment_id"]
        with self.assertRaisesRegex(ValueError, "exactly the reports"):
            self.run_with(config)

    def test_segments_and_series_belong_to_one_run(self):
        # Regression: --segments joined run-1 and run-2 reports in one segment.
        other = self.store("other-run.json", self.av("C1", run_id="run-2"))
        with self.assertRaisesRegex(ValueError, "different run"):
            scan_bridge.segments(self.reports()[:2] + [other], self.ws.root, "run-1")
        config = self.prepare()
        (self.ws.root / "series.json").write_text(json.dumps(
            {"schema": 1, "kind": "detector_series", "run_id": "run-2", "reports": []}))
        with self.assertRaisesRegex(ValueError, "series belongs to a different run"):
            self.run_with(config)
        config = self.prepare()
        del config["series"]
        with self.assertRaisesRegex(ValueError, "detector series record"):
            self.run_with(config)

    def test_frozen_rule_yara_evidence_must_follow_the_freeze(self):
        # Regression: a YARA report with the frozen hash but an earlier start counted as an additional detection.
        paths = self.reports()[:-1] + [self.store("early-yara.json", self.yara(
            {"E1": "MATCHED", "E1-v1": "NOT_MATCHED", "EB1": "NOT_MATCHED"}, started="2026-11-27T12:00:00+00:00"))]
        with self.assertRaisesRegex(ValueError, "began before freezing"):
            self.run_with(self.prepare(paths))

    def test_freeze_record_belongs_to_one_run(self):
        # Regression: one freeze record authorised a request of another run.
        with self.assertRaisesRegex(ValueError, "different run"):
            run_guard.prepare_av_request(self.samples, "EB1", run_id="run-2", wait_seconds=7,
                                         workspace=self.ws.root, freeze="rules/freeze.json")
        run_guard.write_freeze(self.ws.root, "rules-run2", RULES, freeze_record(run_id="run-2"))
        config = self.prepare()
        config["yara"]["freeze_record"] = "rules-run2/freeze.json"
        with self.assertRaisesRegex(ValueError, "Freeze record belongs to a different run"):
            self.run_with(config)

    def test_a_named_segment_cannot_be_dropped(self):
        # Regression: removing every AV (or YARA) row was accepted although the
        # configuration named that segment and the series held its reports.
        for tool in ("av", "yara"):
            def drop(rows, tool=tool):
                rows[:] = [row for row in rows if row["tool"] != tool]
            with self.subTest(tool=tool), self.assertRaisesRegex(ValueError, "exactly the reports of the named"):
                self.run_with(self.prepare(change=drop))
        config = self.prepare()
        config["yara"]["segment_id"] = None
        with self.assertRaisesRegex(ValueError, "must name one yara segment"):
            self.run_with(config)

    def test_yara_version_must_match_the_freeze_record(self):
        # Regression: the freeze record named 4.6.0 and the YARA report 4.7.0.
        newer = dict(self.yara({"E1": "MATCHED", "E1-v1": "NOT_MATCHED", "EB1": "NOT_MATCHED"}), yara_version="4.7.0")
        paths = self.reports()[:-1] + [self.store("newer-yara.json", newer)]
        with self.assertRaisesRegex(ValueError, "another YARA version than the freeze record"):
            self.run_with(self.prepare(paths))

    def test_av_only_runs_for_empty_or_failed_rule_sets(self):
        # Regression: EMPTY/FAILED runs have no YARA state, and accounting stopped with
        # "Missing tool state ID: yara" unless a placeholder was written.
        av_only = self.reports()[:-1]
        for status in ("EMPTY", "FAILED"):
            run_guard.write_freeze(self.ws.root, "rules-" + status, "", freeze_record(status))
            config = self.prepare(av_only)
            config["yara"] = {"state_id": None, "segment_id": None, "ruleset_status": status,
                              "ruleset_sha256": None, "freeze_record": "rules-" + status + "/freeze.json"}
            report = self.run_with(config)
            with self.subTest(status=status):
                supplement = report["supplementation"]
                if status == "EMPTY":
                    self.assertEqual("EVALUATED", supplement["status"])
                    self.assertEqual(supplement["tools"]["av"]["recall"], supplement["tools"]["combined"]["recall"])
                else:
                    self.assertEqual(("NOT_EVALUATED", "RULESET_FAILED"), (supplement["status"], supplement["reason"]))
                self.assertIsNone(report["tool_states"]["yara"])
        # A tool that did produce reports still needs its state ID.
        config = self.prepare()
        config["yara"]["state_id"] = None
        with self.assertRaises(ValueError):
            self.run_with(config)

    def test_control_mode_still_needs_both_state_ids(self):
        config = self.prepare()
        config.update(mode="control")
        config["yara"]["state_id"] = None
        with self.assertRaisesRegex(ValueError, "Missing tool state ID: yara"):
            self.run_with(config)

    def test_empty_observations_are_not_an_evaluation(self):
        # Regression: a header-only CSV gave supplementation EVALUATED with zero pairs.
        config = self.prepare(change=lambda rows: rows.clear(), series=[])
        report = self.run_with(config)
        self.assertEqual(("NOT_EVALUATED", "NO_PAIRED_RECORDS"),
                         (report["supplementation"]["status"], report["supplementation"]["reason"]))


class GuardTests(ResearchFixture):
    def test_av_requests_wait_for_the_final_rule_set(self):
        for sample_id in ("E1-v1", "EB1"):
            with self.subTest(sample_id=sample_id), self.assertRaisesRegex(ValueError, "only after the rule set"):
                run_guard.prepare_av_request(self.samples, sample_id, run_id="run-1", wait_seconds=7,
                                             workspace=self.ws.root)
        for sample_id in ("C1", "CB1", "E1"):
            request = run_guard.prepare_av_request(self.samples, sample_id, run_id="run-1", wait_seconds=7,
                                                   workspace=self.ws.root)
            self.assertIsNone(request["authorization"])
        request = run_guard.prepare_av_request(self.samples, "EB1", run_id="run-1", wait_seconds=7,
                                               workspace=self.ws.root, freeze="rules/freeze.json")
        self.assertEqual(("FROZEN", FROZEN_AT), (request["authorization"]["freeze_status"],
                                                 request["authorization"]["frozen_at_utc"]))
        self.assertEqual(1, len(request["files"]))
        for wait in (0, -1, "7"):
            with self.subTest(wait=wait), self.assertRaisesRegex(ValueError, "waiting period"):
                run_guard.prepare_av_request(self.samples, "C1", run_id="run-1", wait_seconds=wait,
                                             workspace=self.ws.root)

    def test_failed_or_empty_rule_sets_are_final_for_av_but_not_applied(self):
        for status in ("EMPTY", "FAILED"):
            run_guard.write_freeze(self.ws.root, "rules-" + status, "", freeze_record(status))
            relative = "rules-" + status + "/freeze.json"
            request = run_guard.prepare_av_request(self.samples, "EB1", run_id="run-1", wait_seconds=7,
                                                   workspace=self.ws.root, freeze=relative)
            self.assertEqual(status, request["authorization"]["freeze_status"])
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, "Only a FROZEN rule set"):
                run_guard.prepare_yara_request(self.samples, ["EB1"], run_id="run-1", yara_sha256="f" * 64,
                                               workspace=self.ws.root, freeze=relative)
        request = run_guard.prepare_yara_request(self.samples, ["E1", "EB1"], run_id="run-1", yara_sha256="f" * 64,
                                                 workspace=self.ws.root, freeze="rules/freeze.json")
        self.assertEqual(hashlib.sha256(RULES.encode()).hexdigest(), request["ruleset_sha256"])

    def test_freeze_records_are_validated_and_never_overwritten(self):
        with self.assertRaises(FileExistsError):
            run_guard.write_freeze(self.ws.root, "rules", RULES, freeze_record())
        bad = dict(freeze_record("EMPTY"), ruleset_sha256="a" * 64)
        run_guard.write_freeze(self.ws.root, "rules-bad", "", bad)
        with self.assertRaisesRegex(ValueError, "Only a FROZEN record"):
            run_guard.load_freeze(self.ws.root, "rules-bad/freeze.json")


class SegmentTests(ResearchFixture):
    def test_configuration_changes_start_new_segments(self):
        newer = dict(STATE_A, AntivirusSignatureVersion="1.463.14.0")
        paths = [self.store("s1.json", self.av("C1", started="2026-11-27T11:00:00+00:00")),
                 self.store("s3.json", self.av("E1", started="2026-11-27T11:40:00+00:00", state=newer)),
                 self.store("s2.json", self.av("CB1", started="2026-11-27T11:20:00+00:00")),
                 self.store("y.json", self.yara({"E1": "NOT_MATCHED"}))]
        result = scan_bridge.segments(paths, self.ws.root, "run-1")
        self.assertEqual([2, 1], [s["report_count"] for s in result["av"]])
        self.assertEqual(["reports/s1.json", "reports/s2.json"], result["av"][0]["reports"])
        self.assertEqual("1.463.14.0", result["av"][1]["versions"]["AntivirusSignatureVersion"])
        self.assertEqual(1, len(result["yara"]))
        with self.assertRaisesRegex(ValueError, "tool state changed"):
            scan_bridge.observations(paths, self.samples, "run-1", self.ws.root)
        manifest = self.ws.root / "manifest.csv"
        with manifest.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=aegis.SAMPLE_FIELDS)
            writer.writeheader()
            writer.writerows(self.ws.rows)
        arguments = ["--workspace", str(self.ws.root), "--manifest", str(manifest), "--run-id", "run-1",
                     "--reports", *paths]
        self.assertEqual(0, scan_bridge.main(arguments + ["--segments"]))
        self.assertEqual(1, scan_bridge.main(arguments))


if __name__ == "__main__":
    unittest.main()
