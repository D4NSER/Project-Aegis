"""The desktop laboratory section: fixed inputs, step order, operator prompts.

Uses the fake VM of `test_research_lab`; nothing runs in Windows. The
rehearsal programs are inert byte strings standing in for the two PE files.
"""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
import research_session
from desktop_backend import DesktopBackend
from test_research_lab import FakeVM, LOCAL, STATE_A, STATE_F

SNAPSHOT = "Aegis-Inert-" + "5" * 16
TOKEN = "c" * 32


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) if not isinstance(value, str) else value)


def prepared_workspace(base):
    panel = base / "panel"
    write(panel / "vm-controls" / "active-session.json", {"snapshot": SNAPSHOT})
    prep = panel / "lab-preparation" / ("preparation-" + "d" * 32)
    fixtures = {}
    for key in ("baseline", "variant"):
        content = ("inert " + key + " stand-in").encode()
        path = prep / "artifacts" / ("work-" + TOKEN) / (key + ".exe")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        fixtures[key] = {"pe": {"sha256": hashlib.sha256(content).hexdigest()},
                         "run": {"observed_path": LOCAL + "\\AegisLabKit-x\\work-" + TOKEN + "\\runs\\" + key
                                 + "\\observed.txt"}}
    write(prep / "baseline-ready.json", {"snapshot": SNAPSHOT})
    write(prep / "resolved.json", {"all_checks_passed": True})
    write(prep / "report.json", {"run_id": "rehearsal-" + TOKEN, "fixtures": fixtures})
    write(prep / "pending.json", {"guest_root": LOCAL + "\\AegisLabKit-x",
                                  "files": {"yara64.exe": "a" * 64, "Procmon64a.exe": "b" * 64}})
    return panel


class InputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.panel = prepared_workspace(Path(self.temp.name))

    def tearDown(self):
        self.temp.cleanup()

    def test_inputs_come_from_the_verified_rehearsal(self):
        inputs = research_session.lab_inputs(self.panel)
        self.assertEqual(inputs["snapshot"], SNAPSHOT)
        self.assertTrue(inputs["programs"]["baseline"]["workdir"].endswith("\\runs\\baseline"))
        self.assertEqual(json.loads(Path(inputs["card"]).read_text()), research_session.CARD)
        self.assertIn("AEGIS_REHEARSAL_BASELINE", Path(inputs["ruleset"]).read_text())

    def test_changed_inputs_and_programs_are_refused(self):
        inputs = research_session.lab_inputs(self.panel)
        Path(inputs["ruleset"]).write_text("rule changed { condition: true }\n")
        with self.assertRaisesRegex(ValueError, "input changed"):
            research_session.lab_inputs(self.panel)
        Path(inputs["ruleset"]).write_text(research_session.RULESET)
        Path(inputs["programs"]["variant"]["path"]).write_bytes(b"different")
        with self.assertRaisesRegex(ValueError, "changed or is missing"):
            research_session.lab_inputs(self.panel)

    def test_unverified_tool_kit_is_refused(self):
        write(next(self.panel.glob("lab-preparation/*")) / "resolved.json", {"all_checks_passed": False})
        with self.assertRaisesRegex(ValueError, "No verified tool kit"):
            research_session.lab_inputs(self.panel)


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.panel = prepared_workspace(Path(self.temp.name))
        self.state = STATE_A
        self.vm = FakeVM([SNAPSHOT], self.answer)
        self.session = research_session.ResearchSession(self.panel, {"guest_username": "AegisLab"},
                                                        connect=lambda credential: self.vm)

    def tearDown(self):
        if not self.session.busy:
            self.session.disconnect()
        self.temp.cleanup()

    def answer(self, action, request, kit, vm, elevated):
        if action == "probe":
            return {"kind": "lab_probe", "run_id": request["run_id"], "defender": dict(self.state),
                    "state": "A" if self.state["RealTimeProtectionEnabled"] else "F",
                    "active_network_adapters": [], "windows": {"CurrentBuild": "26300", "UBR": 1}}
        if action == "eicar_realtime":
            return {"kind": "eicar_realtime_control", "run_id": request["run_id"], "status": "DETECTED",
                    "source_verdict": "SUPPORTED", "seconds_to_record": 1.5,
                    "trigger": getattr(self, "trigger", "read"),
                    "records": {"events": [{"source": "Real-Time Protection"}], "threats": []}}
        raise AssertionError(action)

    def settle(self, waiting=False):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if (waiting and self.session.waiting) or (not waiting and not self.session.busy):
                return self.session.snapshot()
            time.sleep(0.01)
        self.fail("session did not settle")

    def allowed(self):
        return [s["id"] for s in self.session.snapshot()["steps"] if s["allowed"]]

    def test_steps_open_in_protocol_order(self):
        self.session.submit("connect", ("vm-fixture", "lab-fixture"))
        view = self.settle()
        self.assertTrue(view["connected"])
        self.assertNotIn("fixture", json.dumps(view))
        self.assertEqual(self.allowed(), ["register_a"])
        with self.assertRaisesRegex(ValueError, "neprieinamas"):
            self.session.submit("step", "av_control")
        self.session.submit("step", "register_a")
        view = self.settle()
        self.assertTrue(view["steps"][0]["result"]["ok"], view["status"])
        self.assertIn("sutampa su laukiamu", view["status"])
        self.assertEqual(self.allowed(), ["eicar_realtime", "make_f"])
        # The real-time control needs the lab desktop: the session waits for the operator.
        self.session.submit("step", "eicar_realtime")
        view = self.settle(waiting=True)
        self.assertIn("AegisLab darbalaukio", view["waiting"])
        self.assertIn("Atlikau – tęsti", view["waiting"])
        self.assertNotIn("Enter", view["waiting"])
        self.session.submit("continue")
        view = self.settle()
        result = view["steps"][1]["result"]
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["wait_seconds"], 10)
        self.assertIn("av_control", self.allowed())

    def test_a_record_only_after_copying_does_not_calibrate(self):
        self.trigger = "copy"
        self.session.submit("connect", ("vm-fixture", "lab-fixture"))
        self.settle()
        self.session.submit("step", "register_a")
        self.settle()
        self.session.submit("step", "eicar_realtime")
        self.settle(waiting=True)
        self.session.submit("continue")
        view = self.settle()
        result = view["steps"][1]["result"]
        self.assertFalse(result["ok"])
        self.assertIn("tik nukopijavus", result["summary"])
        self.assertNotIn("av_control", self.allowed())

    def test_cancel_stops_the_step_without_a_result(self):
        self.session.submit("connect", ("vm-fixture", "lab-fixture"))
        self.settle()
        self.session.submit("step", "register_a")
        self.settle()
        self.session.submit("step", "eicar_realtime")
        self.settle(waiting=True)
        with self.assertRaisesRegex(ValueError, "Palauk"):
            self.session.submit("step", "make_f")
        self.session.submit("cancel")
        view = self.settle()
        self.assertIn("atšauktas", view["status"])
        self.assertIsNone(view["steps"][1]["result"])
        with self.assertRaisesRegex(ValueError, "nieko nelaukiama"):
            self.session.submit("continue")

    def test_a_guest_in_the_wrong_state_is_shown_as_a_mismatch(self):
        self.state = STATE_F
        self.session.submit("connect", ("vm-fixture", "lab-fixture"))
        self.settle()
        self.session.submit("step", "register_a")
        view = self.settle()
        self.assertIn("Nepavyko", view["status"])
        self.assertFalse(view["steps"][0]["result"]["ok"])
        self.assertEqual(self.allowed(), ["register_a"])


class OutcomeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cycle = Path(self.temp.name) / "cycle-x"
        self.cycle.mkdir()
        write(self.cycle / "cycle.json", {"started_at_utc": "2026-11-28T09:00:00+00:00", "action": "av"})
        write(self.cycle / "report.json", {"status": "NOT_DETECTED", "reasons": ["COMPLETE_NEGATIVE"]})

    def tearDown(self):
        self.temp.cleanup()

    def test_only_a_finished_validated_cycle_counts(self):
        report, error = research_session._outcome(self.cycle)
        self.assertEqual((report, error), (None, "Ciklas nebaigtas"))
        write(self.cycle / "finished.json", {"report_sha256": hashlib.sha256(
            (self.cycle / "report.json").read_bytes()).hexdigest()})
        self.assertEqual(research_session._outcome(self.cycle)[0]["status"], "NOT_DETECTED")
        # A rejected report: the error wins even when a report and a finish record exist.
        write(self.cycle / "error-1.json", {"message": "AV report does not match"})
        result = research_session.judge("av_control", self.cycle, *research_session._outcome(self.cycle), {})
        self.assertEqual((result["ok"], result["summary"]), (False, "AV report does not match"))

    def test_a_changed_report_does_not_count(self):
        write(self.cycle / "finished.json", {"report_sha256": "0" * 64})
        self.assertEqual(research_session._outcome(self.cycle), (None, "Ataskaita pasikeitė po patvirtinimo"))

    def test_restore_status_is_shown_separately(self):
        self.assertEqual(research_session.restore_status(self.cycle), "NOT_REVERTED")
        write(self.cycle / "reverted.json", {"snapshot": "Aegis-StateF-" + "8" * 16})
        self.assertEqual(research_session.restore_status(self.cycle), "PENDING")
        # A proof from a boot of another snapshot does not verify this revert.
        write(self.cycle / "restored.json", {"booted_snapshot": SNAPSHOT, "vm_restore_verified": True})
        self.assertEqual(research_session.restore_status(self.cycle), "PENDING")
        write(self.cycle / "restored-1.json", {"booted_snapshot": "Aegis-StateF-" + "8" * 16,
                                               "vm_restore_verified": True})
        self.assertEqual(research_session.restore_status(self.cycle), "VERIFIED")

    def test_a_rejected_registration_is_never_shown_as_a_match(self):
        report = {"kind": "lab_probe", "state": "A", "defender": {}, "windows": {}}
        states = {"A": {"probe_cycle": "cycle-other", "snapshot": SNAPSHOT}, "F": None}
        self.assertFalse(research_session.judge("register_a", self.cycle, report, None, states)["ok"])
        self.assertFalse(research_session.judge("register_a", self.cycle, None, "Network adapters", states)["ok"])
        states["A"]["probe_cycle"] = self.cycle.name
        self.assertTrue(research_session.judge("register_a", self.cycle, report, None, states)["ok"])


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.status = base / "lab.json"
        self.status.write_text("{}")
        self.bridge = DesktopBackend(base / "panel", self.status)

    def tearDown(self):
        self.temp.cleanup()

    def test_overview_and_guards(self):
        view = self.bridge.dispatch("refresh", {})["research"]
        self.assertEqual([s["id"] for s in view["steps"]], research_session.STEP_IDS)
        self.assertFalse(any(s["allowed"] for s in view["steps"]))
        with self.assertRaisesRegex(ValueError, "prisijunk"):
            self.bridge.dispatch("research_action", {"action": "step", "step": "register_a"})
        self.bridge.lab = SimpleNamespace(busy=False)
        with self.assertRaisesRegex(ValueError, "kontrolių laboratorijos"):
            self.bridge.dispatch("research_connect", {"vm_credential": "x", "lab_credential": "y"})
        self.bridge.lab = None
        self.bridge.research = SimpleNamespace(busy=False)
        with self.assertRaisesRegex(ValueError, "tyrimo laboratorijos"):
            self.bridge.dispatch("lab_connect", {"vm_credential": "x", "lab_credential": "y"})
        self.bridge.research = None
        with self.assertRaisesRegex(ValueError, "Neatpažintas"):
            self.bridge.research = SimpleNamespace(busy=False, submit=lambda *a: None, snapshot=lambda: {})
            self.bridge.dispatch("research_action", {"action": "run_anything"})


if __name__ == "__main__":
    unittest.main()
