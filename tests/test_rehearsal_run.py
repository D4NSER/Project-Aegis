"""A whole rehearsal run with the fake VM: plan -> guarded checks -> one series -> accounting.

Nothing runs in Windows. The "programs" are tiny inert PE stubs that carry
the work-directory token and a marker string; the fake guest answers each
action with the real guest-side decision code on a fake Windows system.
"""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
import guest_research_lab as lab
import guest_research_scan as grs
import rehearsal_run
import run_guard
import vm_research_lab
from test_research_lab import FakeMonitorLab, FakeVM, LOCAL, key
from test_research_scan import FakeSystem, STATE_A, STATE_F

OLD = "1" * 32
YARA = b"inert stand-in for the pinned YARA executable"
TOOLS = {"guest_root": LOCAL + r"\AegisLabKit-x", "yara_sha256": hashlib.sha256(YARA).hexdigest(),
         "procmon_sha256": "b" * 64}
SNAPSHOT = "Aegis-Inert-" + "5" * 16


def program(label):
    header = bytearray(0x80)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    header[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", header, 0x44, 0x14C)
    payload = (b"\0\0" + ("C:\\Lab\\AegisLabKit-x\\work-" + OLD + "\\runs").encode("utf-16le") + b"\0\0"
               + (label + ":").encode("utf-16le") + b"\0\0" + "AEGIS_OK:".encode("utf-16le") + b"\0\0")
    return bytes(header) + payload


class Clock(FakeSystem):
    """The guest's clock is real time here, so the freeze order can be checked."""

    def now(self):
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()


class FakeYara(Clock):
    """YARA stand-in: the rehearsal rule matches files holding the baseline marker in UTF-16."""

    def __init__(self, state):
        super().__init__([state], run=self.answer)

    def answer(self, arguments, timeout):
        arguments = [str(a) for a in arguments]
        if arguments[1] == "--version":
            return {"exit_code": 0, "stdout": "4.6.0\n", "stderr": ""}
        _, _, rules, target = arguments
        content, text = Path(target).read_bytes(), Path(rules).read_text()
        if not content:
            return {"exit_code": 0, "stdout": "", "stderr": ""}  # the empty compile-check file
        # The rule's single wide string, searched in UTF-16 as YARA's `wide` would.
        needle, name = text.split('"')[1], text.split()[1]
        hit = needle.encode("utf-16le") in content
        return {"exit_code": 0, "stdout": (name + " " + target + "\n") if hit else "", "stderr": ""}


class RehearsalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.panel = base / "panel"
        self.panel.mkdir()
        programs = {}
        for name, label in (("baseline", "AEGIS_REHEARSAL_BASELINE"), ("variant", "AEGIS_REHEARSAL_VARIANT")):
            path = base / (name + ".exe")
            path.write_bytes(program(label))
            programs[name] = {"path": str(path), "workdir": "C:\\Lab\\AegisLabKit-x\\work-" + OLD + "\\runs\\" + name}
        self.inputs = {"snapshot": SNAPSHOT, "tools": TOOLS, "programs": programs}
        self.state = STATE_A
        self.vm = FakeVM([SNAPSHOT], self.answer)
        self.guest = base / "guest"
        self.guest.mkdir()
        self.lab = vm_research_lab.ResearchLab(self.vm, self.panel, username="AegisLab", credential="x",
                                               tools=TOOLS, prompt=lambda m: None, progress=lambda m: None,
                                               poll_seconds=0, wait_limit=5)
        self.lab.register_a(SNAPSHOT)
        self.state = STATE_F
        self.lab.make_f()
        self.run = rehearsal_run.RehearsalRun(self.panel, self.inputs)

    def tearDown(self):
        self.temp.cleanup()

    def local(self, kit, relative, name):
        target = self.guest / name
        target.write_bytes(self.vm.fs[key(kit + "\\" + relative.replace("/", "\\"))])
        return target

    def answer(self, action, request, kit, vm, elevated):
        code = {"platform": "Windows", "architecture": "ARM64",
                "code_sha256": grs.sha256(ROOT / "src" / "guest_research_scan.py")}
        if action == "probe":
            return {"kind": "lab_probe", "run_id": request["run_id"], "defender": dict(self.state),
                    "state": "A" if self.state["RealTimeProtectionEnabled"] else "F",
                    "active_network_adapters": [], "inventory_error": None}
        if action == "av":
            (item,) = request["files"]
            target = self.local(kit, item["path"], item["sample_id"] + ".bin")
            return {**grs.av_check(Clock([STATE_A]), target, item["sha256"],
                                   wait_seconds=request["wait_seconds"], run_id=request["run_id"],
                                   sample_id=item["sample_id"]), **code}
        yara = self.guest / "yara64.exe"
        yara.write_bytes(YARA)
        files = [(f["sample_id"], self.local(kit, f["path"], f["sample_id"] + "-" + action + ".bin"), f["sha256"])
                 for f in request.get("files", [])]
        if action == "candidate":
            work = self.guest / ("candidate-" + request["run_id"] + str(len(list(self.guest.iterdir()))))
            value = grs.candidate_check(FakeYara(STATE_F), request["rule_text"], files, yara=yara,
                                        yara_sha256=request["yara_sha256"], workdir=work)
            return {**value, "yara_version": "4.6.0", "run_id": request["run_id"]}
        if action == "yara":
            ruleset = self.local(kit, "frozen.yar", "frozen.yar")
            return {**grs.yara_check(FakeYara(STATE_F), files, yara=yara, yara_sha256=request["yara_sha256"],
                                     ruleset=ruleset, ruleset_sha256=request["ruleset_sha256"],
                                     run_id=request["run_id"]), **code}
        if action == "functionality":
            procmon = self.guest / "Procmon64a.exe"
            procmon.write_bytes(b"inert procmon stand-in")
            folder = self.guest / ("functionality-" + request["run_id"])
            folder.mkdir()
            runs = []
            for f in request["files"]:
                local = self.local(kit, f["path"], f["sample_id"] + ".exe")
                runs.append({**f, "path": str(local), "workdir": str(folder / "runs" / f["sample_id"])})
            report = lab.functionality(FakeMonitorLab([STATE_F]), request["card"], runs, procmon=procmon,
                                       procmon_sha256=lab.sha256(procmon), work=folder)
            vm.fs[key(kit + "\\work\\" + report["csv"])] = (folder / report["csv"]).read_bytes()
            return {**report, "run_id": request["run_id"]}
        raise AssertionError(action)

    def whole_run(self):
        self.run.prepare_plan()
        self.run.model_control(self.lab)
        self.run.functionality(self.lab)
        self.run.calibration_av(self.lab, 10)
        self.run.rules(self.lab)
        self.run.final_av(self.lab, 10)
        self.run.final_yara(self.lab)
        return self.run.accounting()

    def test_one_series_from_the_frozen_plan_is_accepted_by_accounting(self):
        result, comparison = self.whole_run()
        self.assertEqual((result["mode"], result["experiment_results"]), ("rehearsal", False))
        self.assertTrue(all(item["same"] for item in comparison.values()), comparison)
        series = json.loads((self.run.root / "series.json").read_text())
        run_ids = {json.loads((self.run.root / r).read_text())["run_id"] for r in series["reports"]}
        self.assertEqual(run_ids, {self.run.run_id})
        # Five AV reports (one per planned file) and one YARA report, all in one series.
        self.assertEqual(len(series["reports"]), 6)
        checked = set()
        for relative in series["reports"]:
            report = json.loads((self.run.root / relative).read_text())
            checked |= {report["sample_id"]} if report["kind"] == "av_check" else {f["sample_id"] for f in report["files"]}
        self.assertEqual(checked, {"C1", "CB1", "E1", "E1-v1", "EB1"})
        control = json.loads((self.run.root / "model-control.json").read_text())
        self.assertEqual((control["rule"]["passed"], control["code"]["outcome"], control["model_ready"]),
                         (True, "NOT_RUN_TOOLCHAIN_NOT_CHOSEN", False))
        records = rehearsal_run.generation_log.GenerationLog(self.run.root / "model" / "log", create=False).records()
        self.assertEqual([(r["task"], r["outcome"], r["repairs"], r["artifacts"]["turn_statuses"]) for r in records],
                         [("rule_control", "ACCEPTED", 1, ["REJECTED_CHANGED_COPY_MATCH", "ACCEPTED"]),
                          ("rule", "ACCEPTED", 1, ["REJECTED_FEATURE_NOT_IN_DESCRIPTION", "ACCEPTED"])])
        self.assertEqual(sorted(p.name for p in (self.run.root / "tables").iterdir()),
                         ["costs.csv", "costs.tex", "generation.csv", "incomplete_checks.csv"])
        # The frozen rule is the model's accepted answer, and no model text reaches the log.
        frozen = (self.run.root / "rules" / "freeze" / "frozen.yar").read_text()
        self.assertIn("AEGIS_REHEARSAL_BASELINE", frozen)
        self.assertNotIn("AEGIS_REHEARSAL", json.dumps(records))
        refusals = json.loads((self.run.root / "guard-refusals.json").read_text())["refusals"]
        self.assertEqual([r["attempt"] for r in refusals], ["av_without_freeze", "yara_without_freeze"])

    def test_the_guard_stops_final_checks_before_the_freeze(self):
        self.run.prepare_plan()
        self.run.model_control(self.lab)
        self.run.functionality(self.lab)
        self.run.calibration_av(self.lab, 10)
        with self.assertRaisesRegex((ValueError, OSError), "rule set is final|freeze|No such file"):
            self.run.final_av(self.lab, 10)
        with self.assertRaises((ValueError, OSError)):
            self.run.final_yara(self.lab)
        self.assertFalse((self.run.root / "final-av.json").exists())

    def test_only_planned_files_can_be_requested(self):
        self.run.prepare_plan()
        self.run.functionality(self.lab)
        samples = self.run.samples()
        with self.assertRaisesRegex(ValueError, "Unknown sample"):
            run_guard.prepare_av_request(samples, "NOT-IN-PLAN", run_id=self.run.run_id, wait_seconds=10,
                                         workspace=self.run.root)
        # A file whose bytes differ from the plan is refused before anything reaches the guest.
        request = run_guard.prepare_av_request(samples, "C1", run_id=self.run.run_id, wait_seconds=10,
                                               workspace=self.run.root)
        other = Path(self.temp.name) / "other.bin"
        other.write_bytes(b"not the planned file")
        with self.assertRaisesRegex(ValueError, "differs from the plan"):
            self.lab.av_request(request, {"C1": other})

    def test_a_changed_plan_stops_the_run(self):
        self.run.prepare_plan()
        (self.run.root / "expected.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "frozen plan changed"):
            self.run.functionality(self.lab)

    def test_a_report_of_another_run_is_refused(self):
        self.whole_run_until_reports()
        foreign = self.run.root / "reports" / "99-foreign.json"
        value = json.loads((self.run.root / "reports" / "01-av-C1.json").read_text())
        foreign.write_text(json.dumps({**value, "run_id": "run-other"}))
        with self.assertRaisesRegex(ValueError, "outside this run"):
            self.run.accounting()

    def whole_run_until_reports(self):
        self.run.prepare_plan()
        self.run.model_control(self.lab)
        self.run.functionality(self.lab)
        self.run.calibration_av(self.lab, 10)
        self.run.rules(self.lab)
        self.run.final_av(self.lab, 10)
        self.run.final_yara(self.lab)

    def test_the_rule_control_uses_the_planned_marker_copy(self):
        self.run.prepare_plan()
        planned = (self.run.root / "plan" / "control-marker.bin").read_bytes()
        # A later change of the source program does not reach the control ...
        Path(self.inputs["programs"]["baseline"]["path"]).write_bytes(program("AEGIS_REHEARSAL_CHANGEDX"))
        self.run.model_control(self.lab)
        checked = [p.read_bytes() for p in (self.run.root / "control").glob("*/marker.bin")]
        self.assertTrue(checked and all(content == planned for content in checked))

    def test_a_changed_planned_marker_copy_stops_the_control(self):
        self.run.prepare_plan()
        (self.run.root / "plan" / "control-marker.bin").write_bytes(program("AEGIS_REHEARSAL_CHANGEDX"))
        with self.assertRaisesRegex(ValueError, "frozen plan changed"):
            self.run.model_control(self.lab)

    def test_accounting_can_be_retried_after_a_stop(self):
        self.whole_run_until_reports()
        log = self.run.root / "model" / "log"
        (first, *_) = sorted(log.glob("*.json"))
        copy = log / ("999-" + first.name.split("-", 1)[1])
        copy.write_text(first.read_text())
        with self.assertRaisesRegex(ValueError, "more than once"):
            self.run.accounting()
        self.assertTrue((self.run.root / "series.json").exists())
        copy.unlink()
        result, comparison = self.run.accounting()
        self.assertTrue(all(item["same"] for item in comparison.values()), comparison)
        kept = list(self.run.root.glob("accounting-attempt-*"))
        self.assertEqual(len(kept), 1)
        self.assertTrue((kept[0] / "series.json").is_file())
        with self.assertRaisesRegex(ValueError, "already complete"):
            self.run.accounting()

    def test_an_interrupted_final_report_does_not_mark_accounting_complete(self):
        self.whole_run_until_reports()
        original = rehearsal_run.write_json

        def failing(path, value):
            if Path(path).name.startswith(".accounting.json"):
                Path(path).write_text('{"run_id": "partial')  # a write that stopped half way
                raise OSError("disk full")
            return original(path, value)
        rehearsal_run.write_json = failing
        try:
            with self.assertRaisesRegex(OSError, "disk full"):
                self.run.accounting()
        finally:
            rehearsal_run.write_json = original
        self.assertFalse((self.run.root / "accounting.json").exists())
        self.assertFalse(self.run.done("accounting"))
        # Even a broken final file left by older code is not taken as complete, and is set aside on retry.
        (self.run.root / "accounting.json").write_text('{"run_id": "partial')
        self.assertFalse(self.run.done("accounting"))
        result, comparison = self.run.accounting()
        self.assertTrue(self.run.done("accounting"))
        self.assertTrue(all(item["same"] for item in comparison.values()))
        self.assertTrue(any((p / "accounting.json").is_file() for p in self.run.root.glob("accounting-attempt-*")))

    def test_stand_ins_are_distinct_copies_with_their_own_work_directory(self):
        content = rehearsal_run.stand_in(program("AEGIS_REHEARSAL_BASELINE"), OLD, "2" * 32)
        self.assertIn(("work-" + "2" * 32).encode("utf-16le"), content)
        self.assertEqual(len(content), len(program("AEGIS_REHEARSAL_BASELINE")))
        with self.assertRaisesRegex(ValueError, "exactly one"):
            rehearsal_run.stand_in(b"MZ no token", OLD, "2" * 32)


if __name__ == "__main__":
    unittest.main()
