"""Functionality-card evaluation from recorded runs; nothing is executed.

Run records and Process Monitor rows are synthetic, shaped like the
laboratory's records for the harmless control program described in the
thesis card example (it writes `rezultatas.txt` with a marker).
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
import aegis
import functionality_card as fc

WORKDIR = "C:\\Users\\AegisLab\\AppData\\Local\\ProjectAegis\\run-0001\\work"
TOKEN = "KONTROLE-01"
SHA = "a" * 64
MON = "b" * 64


def card():
    return {"schema": 1, "kind": "functionality_card", "card_id": "card-control-01", "original_id": "O1",
            "created_at_utc": "2026-11-27T10:00:00+00:00",
            "input": {"arguments": ["{workdir}", "{token}"]}, "time_limit_seconds": 8,
            "expected": {"exit_code": 0, "stdout": None, "stderr_empty": True,
                         "files": [{"path": "rezultatas.txt", "content": "{token}"}]},
            "evidence": {"monitor": "process_monitor",
                         "operations": [{"operation": "WriteFile", "path": "rezultatas.txt", "result": "SUCCESS"}]}}


def run(**change):
    value = {"launch": "STARTED", "sample_sha256": SHA, "arguments": [WORKDIR, TOKEN], "pid": 4242,
             "exit_code": 0, "timed_out": False, "elapsed_seconds": 1.2,
             "stdout": "", "stderr": "", "workdir": WORKDIR, "token": TOKEN,
             "files": {"rezultatas.txt": hashlib.sha256(TOKEN.encode()).hexdigest()},
             "monitor": {"captured": True, "complete": True, "csv_sha256": MON}, "technical_error": None}
    value.update(change)
    return value


def rows(pid="4242", path=WORKDIR + "\\rezultatas.txt", operation="WriteFile", result="SUCCESS"):
    return [{"PID": "4242", "Operation": "Process Start", "Path": "", "Result": "SUCCESS"},
            {"PID": pid, "Operation": operation, "Path": path, "Result": result}]


class CardTests(unittest.TestCase):
    def test_card_hash_is_canonical_and_changes_with_content(self):
        first = fc.card_sha256(card())
        reordered = json.loads(json.dumps(card(), sort_keys=False))
        self.assertEqual(first, fc.card_sha256(reordered))
        changed = card()
        changed["time_limit_seconds"] = 9
        self.assertNotEqual(first, fc.card_sha256(changed))

    def test_invalid_cards_rejected(self):
        cases = (
            lambda c: c.update(extra=1),
            lambda c: c.update(time_limit_seconds=0),
            lambda c: c["expected"].update(exit_code="0"),
            lambda c: c["expected"]["files"].append({"path": "../escape.txt", "content": "x"}),
            lambda c: c["evidence"]["operations"].append({"operation": "WriteFile", "path": "C:\\x", "result": "SUCCESS"}),
            lambda c: c.update(created_at_utc="2026-11-27T10:00:00"),
            lambda c: (c["expected"].update(files=[]), c["evidence"].update(operations=[])),
        )
        for index, change in enumerate(cases):
            value = card()
            change(value)
            with self.subTest(case=index), self.assertRaises(ValueError):
                fc.validate_card(value)


class EvaluatorTests(unittest.TestCase):
    def status(self, run_record, monitor=None):
        record, details = fc.evaluate(card(), run_record, rows() if monitor is None else monitor, SHA, monitor_sha256=MON)
        return record["status"], details["reasons"]

    def test_all_conditions_met_is_pass(self):
        record, details = fc.evaluate(card(), run(), rows(), SHA, monitor_sha256=MON)
        self.assertEqual(("PASS", []), (record["status"], details["reasons"]))
        self.assertEqual({"schema", "kind", "record_id", "sample_sha256", "card_sha256", "status", "synthetic"},
                         set(record))
        self.assertEqual(fc.card_sha256(card()), record["card_sha256"])
        self.assertEqual(record["record_id"], details["record_id"])

    def test_confirmed_time_limit_overrun_is_fail(self):
        # Decision F3: the program ran, monitoring was complete, the card's limit passed.
        self.assertEqual(("FAIL", ["TIME_LIMIT_EXCEEDED"]), self.status(run(timed_out=True)))
        self.assertEqual(("FAIL", ["TIME_LIMIT_EXCEEDED"]), self.status(run(elapsed_seconds=8.5)))

    def test_technical_faults_are_inconclusive(self):
        # Decision F3: a fault that hides the outcome is never a FAIL, even with a timeout.
        cases = (
            (run(timed_out=True, monitor={"captured": True, "complete": False, "csv_sha256": MON}), "MONITORING_INCOMPLETE"),
            (run(monitor={"captured": False, "complete": False, "csv_sha256": None}), "MONITORING_INCOMPLETE"),
            (run(timed_out=True, technical_error="VM_PAUSED"), "TECHNICAL_ERROR:VM_PAUSED"),
            (run(launch="FAILED_TO_START", pid=None), "LAUNCH_NOT_CONFIRMED"),
            (run(pid=None), "PROCESS_ID_UNKNOWN"),
        )
        for value, reason in cases:
            with self.subTest(reason=reason):
                status, reasons = self.status(value)
                self.assertEqual("INCONCLUSIVE", status)
                self.assertIn(reason, reasons)
        self.assertEqual(("INCONCLUSIVE", ["MONITOR_HAS_NO_EVENTS_FOR_PROCESS"]),
                         self.status(run(timed_out=True), monitor=rows(pid="9999")[1:]))

    def test_unreliable_times_never_pass(self):
        # Regression: elapsed null, -1, "9" or NaN gave PASS; a NaN limit was accepted.
        for elapsed in (None, -1, "9", float("nan"), float("inf"), True):
            with self.subTest(elapsed=elapsed):
                status, reasons = self.status(run(elapsed_seconds=elapsed))
                self.assertEqual(("INCONCLUSIVE", ["ELAPSED_TIME_UNRECORDED"]), (status, reasons))
        self.assertEqual(("INCONCLUSIVE", ["TIMEOUT_FLAG_UNRECORDED"]), self.status(run(timed_out=None)))
        for limit in (float("nan"), float("inf"), True, 0):
            with self.subTest(limit=limit), self.assertRaisesRegex(ValueError, "finite positive time limit"):
                fc.validate_card(dict(card(), time_limit_seconds=limit))

    def test_input_must_follow_the_card(self):
        # Regression: a changed card argument still gave PASS for the same run.
        changed = card()
        changed["input"]["arguments"] = ["{workdir}", "{token}", "--extra"]
        record, details = fc.evaluate(changed, run(), rows(), SHA, monitor_sha256=MON)
        self.assertEqual(("INCONCLUSIVE", ["INPUT_DIFFERS_FROM_CARD"]), (record["status"], details["reasons"]))
        self.assertEqual(("INCONCLUSIVE", ["INPUT_DIFFERS_FROM_CARD"]),
                         self.status(run(arguments=[WORKDIR, "KONTROLE-02"])))

    def test_evidence_must_belong_to_this_file_and_trace(self):
        # Regression: one run record and one trace gave PASS for two different file hashes.
        with self.assertRaisesRegex(ValueError, "different file"):
            fc.evaluate(card(), run(), rows(), "c" * 64, monitor_sha256=MON)
        with self.assertRaisesRegex(ValueError, "does not belong to this run"):
            fc.evaluate(card(), run(), rows(), SHA, monitor_sha256="d" * 64)

    def test_missing_trace_hashes_are_refused(self):
        # Regression: captured=true with no csv_sha256 and monitor_sha256=None gave PASS.
        for monitor, given in (({"captured": True, "complete": True}, None),
                               ({"captured": True, "complete": True, "csv_sha256": None}, None),
                               ({"captured": True, "complete": True, "csv_sha256": "x"}, "x")):
            with self.subTest(monitor=monitor), self.assertRaisesRegex(ValueError, "does not belong to this run"):
                fc.evaluate(card(), run(monitor=monitor), rows(), SHA, monitor_sha256=given)

    def test_unrecorded_outputs_are_inconclusive(self):
        # Regression: stderr null or exit_code false gave PASS, exit_code null gave FAIL.
        cases = ((run(stderr=None), "OUTPUT_UNRECORDED"), (run(stdout=None), "OUTPUT_UNRECORDED"),
                 (run(exit_code=False), "EXIT_CODE_UNRECORDED"), (run(exit_code=None), "EXIT_CODE_UNRECORDED"),
                 (run(exit_code="0"), "EXIT_CODE_UNRECORDED"), (run(files=None), "FILES_UNRECORDED"),
                 (run(files={"rezultatas.txt": "short"}), "FILES_UNRECORDED"))
        for value, reason in cases:
            with self.subTest(reason=reason, value={k: value[k] for k in ("exit_code", "stdout", "stderr", "files")}):
                self.assertEqual(("INCONCLUSIVE", [reason]), self.status(value))
        # A process killed at the time limit may have no exit code; the overrun decides.
        self.assertEqual(("FAIL", ["TIME_LIMIT_EXCEEDED", "EXIT_CODE"]), self.status(run(timed_out=True, exit_code=None)))

    def test_not_launched_is_not_run(self):
        self.assertEqual(("NOT_RUN", ["PROGRAM_NOT_LAUNCHED"]), self.status(run(launch="NOT_ATTEMPTED", pid=None)))

    def test_unmet_conditions_are_fail(self):
        cases = (
            (run(exit_code=1), None, "EXIT_CODE"),
            (run(stderr="warning"), None, "STDERR_NOT_EMPTY"),
            (run(files={"rezultatas.txt": hashlib.sha256(b"other").hexdigest()}), None, "FILE:rezultatas.txt"),
            (run(files={}), None, "FILE:rezultatas.txt"),
            (run(), rows(result="ACCESS DENIED"), "NOT_OBSERVED:WriteFile:rezultatas.txt"),
            (run(), rows(path=WORKDIR + "\\other.txt"), "NOT_OBSERVED:WriteFile:rezultatas.txt"),
            # A write by another process is not evidence for this one.
            (run(), [rows()[0], rows(pid="5151")[1]], "NOT_OBSERVED:WriteFile:rezultatas.txt"),
        )
        for value, monitor, reason in cases:
            with self.subTest(reason=reason, monitor=monitor):
                status, reasons = self.status(value, monitor)
                self.assertEqual("FAIL", status)
                self.assertIn(reason, reasons)

    def test_stdout_template(self):
        value = card()
        value["expected"]["stdout"] = "LABEL:{token}"
        record, _ = fc.evaluate(value, run(stdout="LABEL:" + TOKEN + "\r\n"), rows(), SHA, monitor_sha256=MON)
        self.assertEqual("PASS", record["status"])
        record, details = fc.evaluate(value, run(stdout="LABEL:other"), rows(), SHA, monitor_sha256=MON)
        self.assertEqual(("FAIL", ["STDOUT"]), (record["status"], details["reasons"]))

    def test_invalid_run_records_rejected(self):
        for change in ({"launch": "MAYBE"}, {"extra": 1}):
            value = run(**change) if "extra" not in change else dict(run(), **change)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "Invalid run record"):
                fc.evaluate(card(), value, rows(), SHA, monitor_sha256=MON)
        with self.assertRaisesRegex(ValueError, "Invalid sample hash"):
            fc.evaluate(card(), run(), rows(), "not-a-hash", monitor_sha256=MON)

    def test_record_is_accepted_by_the_manifest(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "ws"
            (root / "records").mkdir(parents=True)
            (root / "o1.txt").write_text("Inert evaluated file\n")
            sha = aegis.digest(root / "o1.txt")
            record, _ = fc.evaluate(card(), run(sample_sha256=sha), rows(), sha, monitor_sha256=MON)
            (root / "records/o1.json").write_text(json.dumps(record))
            row = dict(zip(aegis.SAMPLE_FIELDS, ["O1", "proj", "fam", "evaluation", "original", "", "", "", sha,
                                                 "o1.txt", "PASS", fc.card_sha256(card()), "records/o1.json",
                                                 "inert", "v1", "synthetic", "text", "none"]))
            samples = aegis.validate_samples([row], root)
            self.assertFalse(samples["O1"]["functionality_synthetic"])
            row["card_sha256"] = fc.card_sha256(dict(card(), time_limit_seconds=9))
            with self.assertRaisesRegex(ValueError, "does not match"):
                aegis.validate_samples([row], root)


class MonitorAndBuildTests(unittest.TestCase):
    def test_monitor_csv_in_utf16_and_utf8(self):
        with tempfile.TemporaryDirectory() as name:
            for encoding in ("utf-16", "utf-8-sig"):
                path = Path(name) / (encoding + ".csv")
                with path.open("w", encoding=encoding, newline="") as stream:
                    writer = csv.DictWriter(stream, fieldnames=["Time of Day", "PID", "Operation", "Path", "Result"])
                    writer.writeheader()
                    writer.writerow({"Time of Day": "10:00", "PID": "4242", "Operation": "WriteFile",
                                     "Path": WORKDIR + "\\rezultatas.txt", "Result": "SUCCESS"})
                with self.subTest(encoding=encoding):
                    parsed = fc.read_monitor_csv(path)
                    self.assertEqual("WriteFile", parsed[0]["Operation"])
            bad = Path(name) / "bad.csv"
            bad.write_text("a,b\n1,2\n")
            with self.assertRaisesRegex(ValueError, "columns"):
                fc.read_monitor_csv(bad)

    def test_control_build_conditions(self):
        build = {"source_sha256": "1" * 64, "compiler": {"name": "cl", "version": "19.40", "sha256": "2" * 64},
                 "settings": ["/O2", "/Brepro"], "output_sha256": "3" * 64}
        self.assertEqual("IDENTICAL", fc.check_control_build(build, copy.deepcopy(build))["reproducible"])
        self.assertEqual("DIFFERENT", fc.check_control_build(build, dict(build, output_sha256="4" * 64))["reproducible"])
        for key, value in (("settings", ["/O2"]), ("source_sha256", "5" * 64),
                           ("compiler", {"name": "cl", "version": "19.41", "sha256": "2" * 64})):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "same conditions"):
                fc.check_control_build(build, dict(build, **{key: value}))
        with self.assertRaisesRegex(ValueError, "Invalid build record"):
            fc.check_control_build(build, {"source_sha256": "1" * 64})
        # Regression: two builds with compiler {} counted as the same conditions.
        for compiler in ({}, {"name": "", "version": "19.40", "sha256": "2" * 64},
                         {"name": "cl", "version": "19.40", "sha256": "short"}):
            empty = dict(build, compiler=compiler)
            with self.subTest(compiler=compiler), self.assertRaisesRegex(ValueError, "compiler needs"):
                fc.check_control_build(empty, copy.deepcopy(empty))

    def test_cli(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            (base / "card.json").write_text(json.dumps(card()))
            with (base / "monitor.csv").open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=["PID", "Operation", "Path", "Result"])
                writer.writeheader()
                writer.writerows(rows())
            trace = aegis.digest(base / "monitor.csv")
            (base / "run.json").write_text(json.dumps(run(monitor={"captured": True, "complete": True,
                                                                   "csv_sha256": trace})))
            arguments = ["evaluate", "--card", str(base / "card.json"), "--run", str(base / "run.json"),
                         "--monitor-csv", str(base / "monitor.csv"), "--sample-sha256", SHA,
                         "--record", str(base / "record.json"), "--details", str(base / "details.json")]
            self.assertEqual(0, fc.main(arguments))
            self.assertEqual("PASS", json.loads((base / "record.json").read_text())["status"])
            self.assertEqual(1, fc.main(arguments))
            self.assertEqual(0, fc.main(["card-hash", "--card", str(base / "card.json")]))


if __name__ == "__main__":
    unittest.main()
