"""Detector-check decisions and the host bridge, with a fake Windows system.

No Defender, YARA or sample runs here: the fake system returns scripted
states, histories and process results, and every file is inert text.
"""
import copy
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
import aegis
import guest_research_scan as grs
import rule_workflow
import scan_bridge
from test_accounting import Workspace

STATE_A = {"AMEngineVersion": "1.1.1", "AMProductVersion": "4.18.1", "AntivirusEnabled": True,
           "RealTimeProtectionEnabled": True, "IsTamperProtected": True, "AntivirusSignatureVersion": "1.463.13.0"}
STATE_F = dict(STATE_A, RealTimeProtectionEnabled=False)


class FakeSystem:
    def __init__(self, states, threats=(), events=(), run=None):
        self.states = list(states)
        self.threat_calls = list(threats)
        self.event_calls = list(events)
        self.handler = run or (lambda args, timeout: {"exit_code": 0, "stdout": "", "stderr": ""})
        self.slept, self.commands = [], []

    def defender_state(self):
        value = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        if isinstance(value, Exception):
            raise value
        return dict(value)

    def threats(self):
        value = self.threat_calls.pop(0) if self.threat_calls else []
        if isinstance(value, Exception):
            raise value
        return value

    def events(self, since):
        self.since = since
        value = self.event_calls.pop(0) if self.event_calls else []
        if isinstance(value, Exception):
            raise value
        return value

    def defender_program(self):
        return "MpCmdRun.exe"

    def run(self, arguments, timeout):
        self.commands.append([str(a) for a in arguments])
        return self.handler(arguments, timeout)

    def sleep(self, seconds):
        self.slept.append(seconds)

    def now(self):
        return "2026-11-27T12:00:00+00:00"


NOW = "2026-11-27T12:00:05.1234567Z"      # .NET round-trip format, after the check started
YESTERDAY = "2026-11-26T12:00:05.0000000Z"


class AVCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.target = Path(self.temp.name) / "run-0f0f" / "sample.bin"
        self.target.parent.mkdir()
        self.target.write_text("Inert scan target\n")
        self.sha = grs.sha256(self.target)

    def tearDown(self):
        self.temp.cleanup()

    def check(self, system):
        return grs.av_check(system, self.target, self.sha, wait_seconds=7, run_id="run-1", sample_id="S1")

    def threat(self, path=None, when=NOW, source=3):
        return [{"ThreatID": 1, "Resources": ["file:_" + str(path or self.target)],
                 "InitialDetectionTime": when, "DetectionSourceTypeID": source}]

    def event(self, path=None, when=NOW, source="Real-Time Protection", event_id=1116):
        return [{"id": event_id, "record_id": 9, "time": when, "path": "file:_" + str(path or self.target),
                 "source": source}]

    def test_the_file_is_opened_once_before_the_wait(self):
        system = FakeSystem([STATE_A])
        opened = []
        original = grs._read_once
        grs._read_once = lambda path: opened.append((str(path), list(system.slept))) or "PermissionError"
        try:
            report = self.check(system)
        finally:
            grs._read_once = original
        # Opened before the calibrated wait; a refused open is recorded, not treated as a result.
        self.assertEqual(opened, [(str(self.target), [])])
        self.assertEqual(report["access"]["error"], "PermissionError")
        self.assertEqual(system.slept[0], 7)

    def test_state_must_be_A(self):
        report = self.check(FakeSystem([STATE_F]))
        self.assertEqual(("ERROR", ["STATE_MISMATCH"]), (report["status"], report["reasons"]))
        report = self.check(FakeSystem([OSError("no state")]))
        self.assertEqual("ERROR", report["status"])
        self.assertTrue(report["reasons"][0].startswith("STATE_READ_FAILED"))

    def test_realtime_detection_after_the_wait(self):
        system = FakeSystem([STATE_A], threats=[self.threat()])
        report = self.check(system)
        self.assertEqual(("DETECTED", "REALTIME"), (report["status"], report["detected_by"]))
        self.assertEqual([7], system.slept)
        self.assertEqual([], system.commands)
        events = FakeSystem([STATE_A], events=[self.event()])
        report = self.check(events)
        self.assertEqual("REALTIME", report["detected_by"])
        self.assertEqual(["Real-Time Protection"], report["realtime"]["sources"])
        self.assertEqual("2026-11-27T12:00:00+00:00", events.since)

    def test_a_late_realtime_record_never_becomes_a_negative(self):
        """A record written after the first lookup but dated before the custom scan."""
        class Clock(FakeSystem):
            tick = 0
            def now(self):
                Clock.tick += 1
                return "2026-11-27T12:00:%02d+00:00" % Clock.tick
        system = Clock([STATE_A], events=[[], self.event(when="2026-11-27T12:00:01.5000000Z")])
        report = self.check(system)
        self.assertEqual((report["status"], report["reasons"][0]),
                         ("INCONCLUSIVE", "DETECTION_RECORDED_AFTER_WAIT_BEFORE_SCAN"))
        self.assertTrue(report["custom_scan"]["late_records"]["detected"])
        self.assertFalse(report["custom_scan"]["lookup"]["detected"])
        scan_bridge.validate_av({**report, "platform": "Windows", "architecture": "ARM64", "code_sha256": "c" * 64})

    def test_old_or_other_path_records_do_not_count(self):
        # Regression: yesterday's event for the same path was taken as REALTIME, and the
        # event path was matched as an XML fragment.
        cases = (
            {"threats": [self.threat(when=YESTERDAY)] * 2},
            {"events": [self.event(when=YESTERDAY)] * 2},
            {"events": [self.event(path=str(self.target) + ".bak")] * 2},
            {"events": [self.event(path="C:\\other\\" + self.target.name)] * 2},
            {"events": [self.event(event_id=1001)] * 2},
        )
        for case in cases:
            with self.subTest(case=case):
                self.assertEqual("NOT_DETECTED", self.check(FakeSystem([STATE_A], **case))["status"])

    def test_undated_exact_path_record_is_unknown(self):
        undated = self.event(when=None)
        report = self.check(FakeSystem([STATE_A], events=[undated, undated]))
        self.assertEqual("INCONCLUSIVE", report["status"])
        self.assertIn("DETECTION_HISTORY_UNREADABLE", report["reasons"])

    def test_quarantined_without_a_record_is_not_negative(self):
        self.target.unlink()
        report = self.check(FakeSystem([STATE_A]))
        self.assertEqual(("INCONCLUSIVE", ["INPUT_MISSING_WITHOUT_DETECTION"]), (report["status"], report["reasons"]))

    def test_custom_scan_detection(self):
        system = FakeSystem([STATE_A], threats=[[], self.threat(source=1)])
        report = self.check(system)
        self.assertEqual(("DETECTED", "CUSTOM_SCAN"), (report["status"], report["detected_by"]))
        self.assertEqual(["MpCmdRun.exe", "-Scan", "-ScanType", "3", "-File", str(self.target)], system.commands[0])
        unknown_first = FakeSystem([STATE_A], threats=[OSError("history"), self.threat(source=1)])
        report = self.check(unknown_first)
        self.assertEqual(("INCONCLUSIVE", ["DETECTION_SOURCE_UNKNOWN"]), (report["status"], report["reasons"]))

    def test_recorded_source_must_fit_the_label(self):
        # Regression: a "User" event before the custom scan was labelled REALTIME, and a
        # "Real-Time Protection" event after its start was labelled CUSTOM_SCAN.
        cases = (
            ({"events": [self.event(source="User")]}, "DETECTION_SOURCE_CONFLICT"),
            ({"threats": [self.threat(source=1)]}, "DETECTION_SOURCE_CONFLICT"),
            ({"events": [[], self.event(source="Real-Time Protection")]}, "DETECTION_SOURCE_CONFLICT"),
            ({"threats": [[], self.threat(source=3)]}, "DETECTION_SOURCE_CONFLICT"),
            ({"events": [self.event(source=None)]}, "DETECTION_SOURCE_UNKNOWN"),
            ({"threats": [[], self.threat(source=None)]}, "DETECTION_SOURCE_UNKNOWN"),
        )
        for case, reason in cases:
            with self.subTest(case=case):
                report = self.check(FakeSystem([STATE_A], **case))
                self.assertEqual(("INCONCLUSIVE", "", [reason]),
                                 (report["status"], report["detected_by"], report["reasons"]))
        report = self.check(FakeSystem([STATE_A], events=[[], self.event(source="User")]))
        self.assertEqual(("DETECTED", "CUSTOM_SCAN"), (report["status"], report["detected_by"]))

    def test_complete_negative(self):
        report = self.check(FakeSystem([STATE_A]))
        self.assertEqual(("NOT_DETECTED", "", True), (report["status"], report["detected_by"], report["file_unchanged"]))

    def test_incomplete_negatives_stay_unknown(self):
        def exit_code(code):
            return lambda args, timeout: {"exit_code": code, "stdout": "", "stderr": ""}
        def timeout(args, seconds):
            raise subprocess.TimeoutExpired(args, seconds)
        cases = (
            (FakeSystem([STATE_A], run=timeout), "ERROR", "CUSTOM_SCAN_TIMEOUT"),
            # Exit code 2 can also mean a scan error; without a detection record it is not a result.
            (FakeSystem([STATE_A], run=exit_code(2)), "INCONCLUSIVE", "CUSTOM_SCAN_NOT_COMPLETED"),
            (FakeSystem([STATE_A], threats=[OSError("history")]), "INCONCLUSIVE", "DETECTION_HISTORY_UNREADABLE"),
            (FakeSystem([STATE_A, STATE_F]), "INCONCLUSIVE", "TOOL_STATE_CHANGED_OR_UNKNOWN"),
            (FakeSystem([STATE_A, dict(STATE_A, AntivirusSignatureVersion="1.463.14.0")]),
             "INCONCLUSIVE", "TOOL_STATE_CHANGED_OR_UNKNOWN"),
            # Regression: an engine change still produced NOT_DETECTED.
            (FakeSystem([STATE_A, dict(STATE_A, AMEngineVersion="1.1.2")]), "INCONCLUSIVE",
             "TOOL_STATE_CHANGED_OR_UNKNOWN"),
        )
        for system, status, reason in cases:
            with self.subTest(reason=reason, system=system.states):
                report = self.check(system)
                self.assertEqual(status, report["status"])
                self.assertIn(reason, report["reasons"])
                self.assertEqual("", report["detected_by"])

    def test_a_detection_under_changed_versions_is_not_valid(self):
        report = self.check(FakeSystem([STATE_A, dict(STATE_A, AMEngineVersion="1.1.2")], threats=[self.threat()]))
        self.assertEqual(("INCONCLUSIVE", ""), (report["status"], report["detected_by"]))

    def test_detection_must_name_this_exact_path(self):
        other = self.threat(str(self.target) + ".bak")
        report = self.check(FakeSystem([STATE_A], threats=[other, other]))
        self.assertEqual("NOT_DETECTED", report["status"])

    def test_time_parsing(self):
        self.assertEqual(123456, grs.parse_time(NOW).microsecond)
        with self.assertRaises(ValueError):
            grs.parse_time("2026-11-27T12:00:00")
        self.assertEqual("c:\\x\\a.exe", grs.resource_path("file:_C:\\x\\a.exe"))

    def test_real_system_only_in_windows(self):
        with self.assertRaisesRegex(ValueError, "Windows guest"):
            grs.WindowsSystem()


class YaraCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.yara = root / "yara64.exe"
        self.yara.write_text("stand-in for the pinned YARA executable\n")
        self.rules = root / "frozen.yar"
        self.rules.write_text("rule Aegis_Test { strings: $a = \"Marker\" condition: $a }\n")
        self.files = []
        for name in ("a", "b", "c"):
            path = root / (name + ".bin")
            path.write_text("Inert YARA target " + name + "\n")
            self.files.append((name.upper(), path, grs.sha256(path)))

    def tearDown(self):
        self.temp.cleanup()

    def run_check(self, handler, state=STATE_F, files=None):
        def run(args, timeout):
            if args[1] == "--version":
                return {"exit_code": 0, "stdout": "4.6.0\n", "stderr": ""}
            return handler(args, timeout)
        return grs.yara_check(FakeSystem([state], run=run), files or self.files, yara=self.yara,
                              yara_sha256=grs.sha256(self.yara), ruleset=self.rules,
                              ruleset_sha256=grs.sha256(self.rules), run_id="run-1")

    def test_outcomes(self):
        def handler(args, timeout):
            path = str(args[-1])
            if path.endswith("a.bin"):
                return {"exit_code": 0, "stdout": "Aegis_Test " + path + "\n", "stderr": ""}
            if path.endswith("b.bin"):
                return {"exit_code": 0, "stdout": "", "stderr": ""}
            raise subprocess.TimeoutExpired(args, timeout)
        report = self.run_check(handler)
        self.assertEqual([("A", "MATCHED", ["Aegis_Test"]), ("B", "NOT_MATCHED", []), ("C", "ERROR", [])],
                         [(f["sample_id"], f["status"], f["rules"]) for f in report["files"]])
        self.assertEqual("TIMEOUT", report["files"][2]["reason"])
        self.assertEqual("4.6.0", report["yara_version"])

    def test_errors_and_missing_inputs_are_not_negatives(self):
        def handler(args, timeout):
            path = str(args[-1])
            if path.endswith("a.bin"):
                return {"exit_code": 1, "stdout": "", "stderr": "error"}
            return {"exit_code": 0, "stdout": "Aegis_Test C:\\elsewhere\\x.bin\n", "stderr": ""}
        self.files[2][1].unlink()
        changed = (self.files[1][0], self.files[1][1], "a" * 64)
        report = self.run_check(handler, files=[self.files[0], changed, self.files[2]])
        self.assertEqual([("ERROR", "EXIT_1"), ("ERROR", "HASH_MISMATCH"), ("NOT_RUN", "MISSING_INPUT")],
                         [(f["status"], f["reason"]) for f in report["files"]])
        other = self.run_check(handler, files=[self.files[1]])
        self.assertEqual(("ERROR", "UNEXPECTED_OUTPUT"), (other["files"][0]["status"], other["files"][0]["reason"]))

    def test_failed_version_query_blocks_the_series(self):
        # Regression: exit code 7 with some output was stored as the version, and files were scanned.
        def run(args, timeout):
            if args[1] == "--version":
                return {"exit_code": 7, "stdout": "unexpected text\n", "stderr": ""}
            return {"exit_code": 0, "stdout": "", "stderr": ""}
        system = FakeSystem([STATE_F], run=run)
        report = grs.yara_check(system, self.files, yara=self.yara, yara_sha256=grs.sha256(self.yara),
                                ruleset=self.rules, ruleset_sha256=grs.sha256(self.rules), run_id="run-1")
        self.assertIsNone(report["yara_version"])
        self.assertEqual({("ERROR", "YARA_VERSION_UNKNOWN")}, {(f["status"], f["reason"]) for f in report["files"]})
        self.assertEqual(1, len(system.commands))

    def test_a_vanishing_file_does_not_stop_the_series(self):
        # Regression: a file removed during its scan raised FileNotFoundError for the whole batch.
        def handler(args, timeout):
            path = Path(args[-1])
            if path.name == "a.bin":
                path.unlink()
            return {"exit_code": 0, "stdout": "", "stderr": ""}
        report = self.run_check(handler)
        self.assertEqual([("ERROR", "FILE_CHANGED_DURING_SCAN"), ("NOT_MATCHED", None), ("NOT_MATCHED", None)],
                         [(f["status"], f["reason"]) for f in report["files"]])

    def test_state_F_and_pinned_files(self):
        report = self.run_check(lambda a, t: {"exit_code": 0, "stdout": "", "stderr": ""}, state=STATE_A)
        self.assertEqual({"ERROR"}, {f["status"] for f in report["files"]})
        self.assertEqual({"STATE_MISMATCH"}, {f["reason"] for f in report["files"]})
        with self.assertRaisesRegex(ValueError, "Frozen rule set"):
            grs.yara_check(FakeSystem([STATE_F]), self.files, yara=self.yara, yara_sha256=grs.sha256(self.yara),
                           ruleset=self.rules, ruleset_sha256="0" * 64, run_id="run-1")
        with self.assertRaisesRegex(ValueError, "YARA executable"):
            grs.yara_check(FakeSystem([STATE_F]), self.files, yara=self.yara, yara_sha256="0" * 64,
                           ruleset=self.rules, ruleset_sha256=grs.sha256(self.rules), run_id="run-1")

    def test_cold_f_boot_waits_for_defender_before_yara(self):
        startup = dict(STATE_F, AntivirusEnabled=False, AMEngineVersion="0.0.0.0",
                       AntivirusSignatureVersion=None)

        def run(args, timeout):
            return {"exit_code": 0, "stdout": "4.6.0\n" if args[1] == "--version" else "", "stderr": ""}

        for ready in (True, False):
            with self.subTest(ready=ready):
                system = FakeSystem([startup, STATE_F] if ready else [startup], run=run)
                report = grs.yara_check(system, self.files, yara=self.yara, yara_sha256=grs.sha256(self.yara),
                                        ruleset=self.rules, ruleset_sha256=grs.sha256(self.rules), run_id="run-1")
                self.assertEqual([5] if ready else [5] * 6, system.slept)
                self.assertEqual({"NOT_MATCHED"} if ready else {"ERROR"}, {f["status"] for f in report["files"]})

    def test_candidate_check_produces_the_acceptance_record(self):
        text = 'rule Candidate { strings: $a = "Marker" condition: $a }\n'

        def compiles(args, timeout):
            if str(args[-1]).endswith("empty.bin"):
                return {"exit_code": 0, "stdout": "", "stderr": ""}
            path = str(args[-1])
            return {"exit_code": 0, "stdout": ("Candidate " + path + "\n") if path.endswith("a.bin") else "",
                    "stderr": ""}
        startup = dict(STATE_F, AntivirusEnabled=False, AMEngineVersion="0.0.0.0",
                       AntivirusSignatureVersion=None)
        system = FakeSystem([startup, STATE_F], run=compiles)
        report = grs.candidate_check(system, text, self.files[:2], yara=self.yara, yara_sha256=grs.sha256(self.yara),
                                     workdir=Path(self.temp.name) / "candidate-1")
        self.assertEqual([5], system.slept)
        results = report["results"]
        self.assertEqual(rule_workflow.RESULT_FIELDS, set(results))
        self.assertTrue(results["compiled"])
        self.assertEqual({"A": "MATCHED", "B": "NOT_MATCHED"}, {k: v["status"] for k, v in results["matches"].items()})
        self.assertEqual(self.files[0][2], results["matches"]["A"]["sha256"])

        def fails(args, timeout):
            return {"exit_code": 1, "stdout": "", "stderr": "candidate.yar(1): error: syntax error\n"}
        failed = grs.candidate_check(FakeSystem([STATE_F], run=fails), text, self.files, yara=self.yara,
                                     yara_sha256=grs.sha256(self.yara), workdir=Path(self.temp.name) / "candidate-2")
        self.assertEqual((False, {}, ["candidate.yar(1): error: syntax error"]),
                         (failed["results"]["compiled"], failed["results"]["matches"], failed["results"]["compile_errors"]))

    def test_technical_yara_failure_is_not_a_compile_rejection(self):
        # Regression: an I/O error gave compiled=false, which acceptance reads as REJECTED_COMPILE.
        text = 'rule Candidate { strings: $a = "Marker" condition: $a }\n'
        def io_error(args, timeout):
            return {"exit_code": 1, "stdout": "", "stderr": "error: could not open file\n"}
        def unavailable(args, timeout):
            raise OSError("executable missing")
        for index, handler in enumerate((io_error, unavailable)):
            report = grs.candidate_check(FakeSystem([STATE_F], run=handler), text, self.files, yara=self.yara,
                                         yara_sha256=grs.sha256(self.yara),
                                         workdir=Path(self.temp.name) / ("technical-%d" % index))
            with self.subTest(handler=handler.__name__):
                self.assertIsNone(report["results"]["compiled"])
                self.assertEqual([], report["results"]["compile_errors"])
                self.assertTrue(report["technical_error"])


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ws = Workspace(Path(self.temp.name) / "bridge")
        self.ws.add("O1", "original", "evaluation", "proj-1")
        self.ws.add("O2", "original", "calibration", "proj-2")
        self.ws.add("B1", "benign", "evaluation", "benign-1")
        self.samples = self.ws.samples()
        (self.ws.root / "reports").mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def av_report(self, sample_id, status, detected_by="", **extra):
        report = {"schema": 1, "kind": "av_check", "run_id": "run-1", "scan_id": "av-" + sample_id,
                  "sample_id": sample_id, "sha256": self.samples[sample_id]["sha256"], "expected_state": "A",
                  "wait_seconds": 7, "access": {"at_utc": "2026-11-27T12:00:00+00:00", "error": None}, "started_at_utc": "2026-11-27T12:00:00+00:00",
                  "finished_at_utc": "2026-11-27T12:01:00+00:00", "defender_before": STATE_A,
                  "defender_after": STATE_A,
                  "realtime": self.lookup(detected_by == "REALTIME", "Real-Time Protection"),
                  "custom_scan": None if detected_by == "REALTIME" else {
                      "timed_out": False, "exit_code": 0,
                      "lookup": self.lookup(detected_by == "CUSTOM_SCAN", "User")},
                  "file_unchanged": True if status == "NOT_DETECTED" else None,
                  "status": status, "detected_by": detected_by, "reasons": [],
                  "platform": "Windows", "architecture": "ARM64", "code_sha256": "e" * 64}
        report.update(extra)
        return report

    @staticmethod
    def lookup(detected, source):
        events = [{"id": 1116, "time": "2026-11-27T12:00:30Z", "path": "file:_C:\\x", "source": source}]
        return {"known": True, "detected": detected, "threats": [], "events": events if detected else []}

    def yara_report(self, statuses):
        return {"schema": 1, "kind": "yara_check", "run_id": "run-1", "scan_id": "yara-batch",
                "expected_state": "F", "defender_state": STATE_F, "yara_version": "4.6.0", "yara_sha256": "f" * 64,
                "ruleset_sha256": "a" * 64, "started_at_utc": "2026-11-27T13:00:00+00:00",
                "finished_at_utc": "2026-11-27T13:01:00+00:00",
                "files": [{"sample_id": key, "sha256": self.samples[key]["sha256"], "status": status,
                           "rules": ["Aegis_X"] if status == "MATCHED" else [],
                           "reason": None if status in {"MATCHED", "NOT_MATCHED"} else "TIMEOUT"}
                          for key, status in statuses.items()],
                "platform": "Windows", "architecture": "ARM64", "code_sha256": "e" * 64}

    def store(self, name, value):
        (self.ws.root / "reports" / name).write_text(json.dumps(value))
        return "reports/" + name

    def test_reports_become_observations_that_accounting_accepts(self):
        paths = [self.store("o1.json", self.av_report("O1", "DETECTED", "REALTIME")),
                 self.store("o2.json", self.av_report("O2", "DETECTED", "CUSTOM_SCAN")),
                 self.store("b1.json", self.av_report("B1", "NOT_DETECTED")),
                 self.store("yara.json", self.yara_report({"O1": "MATCHED", "B1": "ERROR", "O2": "NOT_RUN"}))]
        rows, states = scan_bridge.observations(paths, self.samples, "run-1", self.ws.root)
        by_key = {(r["sample_id"], r["tool"]): r for r in rows}
        self.assertEqual(("DETECTED", "REALTIME"), (by_key[("O1", "av")]["status"], by_key[("O1", "av")]["detected_by"]))
        self.assertEqual("DETECTED", by_key[("O1", "yara")]["status"])
        self.assertEqual("ERROR", by_key[("B1", "yara")]["status"])
        self.assertEqual("NOT_RUN", by_key[("O2", "yara")]["status"])
        self.assertTrue(states["av"].startswith("defender-") and states["yara"].startswith("yara-"))
        config = {"run_id": "run-1", "av": {"state_id": states["av"]},
                  "yara": {"state_id": states["yara"], "ruleset_status": "FROZEN"}}
        detected = {}
        observations = aegis.validate_observations(copy.deepcopy(rows), self.samples, config, self.ws.root, detected)
        self.assertEqual({"O1": "REALTIME", "O2": "CUSTOM_SCAN"}, detected)
        report = aegis.summarize(self.samples, observations, "FROZEN", detected)
        self.assertEqual("REALTIME", {r["sample_id"]: r for r in report["rows"]}["O1"]["av_detected_by"])

    def test_cli_writes_observations_csv(self):
        manifest = self.ws.root / "manifest.csv"
        with manifest.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=aegis.SAMPLE_FIELDS)
            writer.writeheader()
            writer.writerows(self.ws.rows)
        path = self.store("o1.json", self.av_report("O1", "NOT_DETECTED"))
        output = self.ws.root / "observations.csv"
        arguments = ["--workspace", str(self.ws.root), "--manifest", str(manifest), "--run-id", "run-1",
                     "--reports", path, "--output", str(output)]
        self.assertEqual(0, scan_bridge.main(arguments))
        self.assertEqual(1, len(aegis.read_csv(output, aegis.OBSERVATION_FIELDS)))
        self.assertEqual(1, scan_bridge.main(arguments))

    def test_inconsistent_reports_refused(self):
        cases = (
            ([self.av_report("O1", "DETECTED")], "REALTIME or CUSTOM_SCAN"),
            ([self.av_report("O1", "NOT_DETECTED", "REALTIME")], "REALTIME or CUSTOM_SCAN"),
            ([self.av_report("O1", "NOT_DETECTED", file_unchanged=None)], "completed custom scan"),
            ([self.av_report("O1", "NOT_DETECTED", custom_scan={"exit_code": 2, "timed_out": False,
                                                                 "lookup": {"known": True, "detected": False}})],
             "completed custom scan"),
            # Regression: these contradictions were exported as valid responses.
            ([self.av_report("O1", "NOT_DETECTED", defender_after=STATE_F)], "state A and unchanged"),
            ([self.av_report("O1", "NOT_DETECTED", realtime={"known": False, "detected": False})], "readable history"),
            ([self.av_report("O1", "NOT_DETECTED", defender_after=dict(STATE_A, AMEngineVersion="9"))],
             "unchanged tool versions"),
            ([self.av_report("O1", "DETECTED", "REALTIME", realtime={"known": True, "detected": False})],
             "real-time detection record"),
            # Regression: a detection with empty record lists was exported.
            ([self.av_report("O1", "DETECTED", "REALTIME",
                             realtime={"known": True, "detected": True, "events": [], "threats": []})],
             "real-time detection record"),
            ([self.av_report("O1", "DETECTED", "REALTIME", realtime=self.lookup(True, "User"))],
             "real-time source"),
            ([self.av_report("O1", "DETECTED", "CUSTOM_SCAN", realtime={"known": False, "detected": False})],
             "clean real-time lookup"),
            ([self.av_report("O1", "NOT_DETECTED", sha256="b" * 64)], "stale hash"),
            ([self.av_report("O1", "NOT_DETECTED"), self.av_report("O1", "NOT_DETECTED")], "More than one"),
            ([self.av_report("O1", "NOT_DETECTED"),
              self.av_report("B1", "NOT_DETECTED", defender_before=dict(STATE_A, AntivirusSignatureVersion="2"),
                             defender_after=dict(STATE_A, AntivirusSignatureVersion="2"))],
             "tool state changed"),
            ([self.av_report("O1", "NOT_DETECTED", run_id="run-2")], "different run"),
            ([dict(self.av_report("O1", "NOT_DETECTED"), unexpected=True)], "Invalid AV report"),
        )
        for index, (reports, message) in enumerate(cases):
            paths = [self.store("case-%d-%d.json" % (index, n), value) for n, value in enumerate(reports)]
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                scan_bridge.observations(paths, self.samples, "run-1", self.ws.root)
        bad = self.yara_report({"O1": "MATCHED"})
        bad["files"][0]["rules"] = []
        with self.assertRaisesRegex(ValueError, "Invalid YARA file result"):
            scan_bridge.observations([self.store("bad-yara.json", bad)], self.samples, "run-1", self.ws.root)
        # Regression: a YARA DETECTED from a report recorded in state A without a version was exported.
        for name, change in (("state-a", {"defender_state": STATE_A}), ("no-version", {"yara_version": None}),
                             ("bad-version", {"yara_version": "unexpected text"})):
            wrong = dict(self.yara_report({"O1": "MATCHED"}), **change)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "state F and a recorded YARA version"):
                scan_bridge.observations([self.store(name + ".json", wrong)], self.samples, "run-1", self.ws.root)
        unexplained = self.yara_report({"O1": "ERROR"})
        unexplained["files"][0]["reason"] = None
        with self.assertRaisesRegex(ValueError, "needs its reason"):
            scan_bridge.observations([self.store("unexplained.json", unexplained)], self.samples, "run-1", self.ws.root)

    def test_accounting_rejects_detected_by_on_non_detections(self):
        rows, states = scan_bridge.observations(
            [self.store("o1.json", self.av_report("O1", "NOT_DETECTED"))], self.samples, "run-1", self.ws.root)
        config = {"run_id": "run-1", "av": {"state_id": states["av"]},
                  "yara": {"state_id": "unused", "ruleset_status": "FROZEN"}}
        rows[0]["detected_by"] = "REALTIME"
        with self.assertRaisesRegex(ValueError, "Only an AV detection"):
            aegis.validate_observations(rows, self.samples, config, self.ws.root)
        rows[0].update(status="DETECTED", detected_by="")
        with self.assertRaisesRegex(ValueError, "must name REALTIME"):
            aegis.validate_observations(rows, self.samples, config, self.ws.root)


if __name__ == "__main__":
    unittest.main()
