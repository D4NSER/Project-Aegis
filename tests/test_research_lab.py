"""Stage-3 laboratory controls with a fake VM and a fake Windows system.

No VM, Defender, Process Monitor or sample runs here. The fake VM keeps an
in-memory guest file system with cold snapshots, so a revert really removes
a cycle's kit; the fake guest answers each action with a scripted report.
The EICAR text is never written: the fake system only records the request.
"""
import base64
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
import functionality_card
import guest_research_lab as lab
import guest_research_scan as grs
import vm_research_lab
from fusion_control import ManualBootRequired
from test_research_scan import FakeSystem, NOW, STATE_A, STATE_F

LOCAL = r"C:\Lab\AppData\Local"
TOOLS = {"guest_root": LOCAL + r"\AegisLabKit-" + "d" * 32, "yara_sha256": "a" * 64, "procmon_sha256": "b" * 64}
PYTHON = LOCAL + r"\Programs\Python\Python314-arm64\python.exe"


class FakeLab(FakeSystem):
    """Adds the laboratory operations; the EICAR text is only noted, never materialized."""

    def __init__(self, *args, elevated=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.clock, self.is_elevated, self.written, self.actions = 0.0, elevated, [], []

    def sleep(self, seconds):
        super().sleep(seconds)
        self.clock += seconds

    def monotonic(self):
        return self.clock

    def elevated(self):
        return self.is_elevated

    def defender_details(self):
        return {"status": {"OnAccessProtectionEnabled": True}, "preferences": {"RealTimeScanDirection": 0}}

    def read_back(self, path):
        self.actions.append(("read", str(path)))
        return None

    def copy_file(self, source, target):
        self.actions.append(("copy", str(target)))
        Path(target).write_bytes(Path(source).read_bytes())
        return None

    def write_eicar(self, path):
        self.actions.append(("write", str(path)))
        self.written.append(str(path))
        Path(path).write_bytes(lab.EICAR)
        return None


def record(path, source, event_id=1117):
    return {"id": event_id, "record_id": 7, "time": NOW, "path": "file:_" + str(path), "source": source}


class EicarControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.work = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def target(self, system):
        return system.written[0]

    def test_realtime_record_time_and_source_are_kept(self):
        system = FakeLab([STATE_A])

        def poll_events(since):
            # The record appears on the third lookup.
            calls.append(since)
            return [record(system.written[0], "Real-Time Protection", 1116)] if len(calls) >= 3 else []
        calls = []
        system.events = poll_events
        report = lab.eicar_realtime(system, self.work, limit=10, step=0.5)
        self.assertEqual((report["status"], report["trigger"]), ("DETECTED", "write"))
        self.assertEqual(report["seconds_to_record"], 1.0)
        self.assertEqual(report["source_verdict"], "SUPPORTED")
        self.assertEqual(report["records"]["events"][0]["source"], "Real-Time Protection")

    def test_no_record_within_limit_is_a_negative_calibration(self):
        system = FakeLab([STATE_A])
        report = lab.eicar_realtime(system, self.work, limit=3, step=0.5)
        self.assertEqual((report["status"], report["seconds_to_record"]), ("NOT_DETECTED", None))
        # Every action was tried before giving up, and the diagnostics were kept.
        self.assertEqual([a for a, _ in system.actions], ["write", "read", "copy"])
        self.assertEqual([p["action"] for p in report["phases"]], ["write", "read", "copy"])
        self.assertEqual(report["defender_details"]["preferences"]["RealTimeScanDirection"], 0)

    def test_a_record_only_after_reading_names_the_read_as_trigger(self):
        system = FakeLab([STATE_A])
        system.events = lambda since: ([record(system.written[0], "Real-Time Protection", 1116)]
                                       if any(a == "read" for a, _ in system.actions) else [])
        report = lab.eicar_realtime(system, self.work, limit=6, step=0.5)
        self.assertEqual((report["status"], report["trigger"]), ("DETECTED", "read"))
        self.assertEqual(report["reason"], "SOURCE_SUPPORTED_AFTER_READ")
        self.assertEqual(len(report["phases"]), 2)

    def test_a_record_of_the_copy_counts(self):
        system = FakeLab([STATE_A])
        system.events = lambda since: ([record(a[1], "Real-Time Protection", 1116) for a in system.actions
                                        if a[0] == "copy"])
        report = lab.eicar_realtime(system, self.work, limit=6, step=0.5)
        self.assertEqual((report["status"], report["trigger"]), ("DETECTED", "copy"))

    def test_realtime_control_needs_state_a(self):
        system = FakeLab([STATE_F])
        report = lab.eicar_realtime(system, self.work)
        self.assertEqual((report["status"], report["reason"]), ("ERROR", "STATE_MISMATCH"))
        self.assertEqual(system.written, [])

    def test_user_source_is_not_accepted_as_realtime(self):
        system = FakeLab([STATE_A])
        system.events = lambda since: [record(system.written[0], "User")]
        report = lab.eicar_realtime(system, self.work, limit=2)
        self.assertEqual((report["status"], report["source_verdict"]), ("DETECTED", "CONFLICT"))

    def test_custom_scan_positive_in_state_f(self):
        system = FakeLab([STATE_F])
        scanned = []
        system.handler = lambda args, timeout: scanned.append(args) or {"exit_code": 2, "stdout": "", "stderr": ""}
        system.events = lambda since: [record(system.written[0], "User")] if scanned else []
        report = lab.eicar_custom(system, self.work)
        self.assertEqual((report["status"], report["source_verdict"]), ("DETECTED", "SUPPORTED"))
        self.assertTrue(report["present_before_scan"])
        self.assertEqual(report["custom_scan"]["exit_code_use"], "diagnostic only")

    def test_custom_control_is_inconclusive_when_realtime_removed_the_file(self):
        system = FakeLab([STATE_F])
        system.write_eicar = lambda path: system.written.append(str(path))  # nothing stays on disk
        report = lab.eicar_custom(system, self.work)
        self.assertEqual((report["status"], report["reason"]), ("INCONCLUSIVE", "NOT_PRESENT_FOR_CUSTOM_SCAN"))
        self.assertEqual(system.commands, [])

    def test_elevated_actions_need_elevation(self):
        system = FakeLab([STATE_A], elevated=False)
        with self.assertRaisesRegex(ValueError, "UAC"):
            lab.perform(system, "av", {}, self.work)


CARD = {"schema": 1, "kind": "functionality_card", "card_id": "card-baseline", "original_id": "baseline",
        "created_at_utc": "2026-11-28T10:00:00+00:00", "input": {"arguments": ["{workdir}", "{token}"]},
        "time_limit_seconds": 8,
        "expected": {"exit_code": 0, "stdout": "AEGIS_REHEARSAL_BASELINE:{token}", "stderr_empty": True,
                     "files": [{"path": "observed.txt", "content": "AEGIS_OK:{token}"}]},
        "evidence": {"monitor": "process_monitor",
                     "operations": [{"operation": "WriteFile", "path": "observed.txt", "result": "SUCCESS"}]}}


class FakeMonitorLab(FakeLab):
    """A harmless stand-in for the rehearsal program and Process Monitor."""

    def __init__(self, *args, behave=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.behave, self.rows, self.pid = behave, [], 4100

    def license_accepted(self):
        return True

    def monitor_running(self):
        return False

    def start_monitor(self, procmon, trace):
        self.trace = Path(trace)

    def stop_monitor(self, procmon):
        self.trace.write_bytes(b"trace")
        return 0

    def export_monitor(self, procmon, trace, csv_path):
        lines = ["PID,Operation,Path,Result"] + [",".join(row) for row in self.rows]
        Path(csv_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 0

    def launch(self, arguments, timeout):
        self.pid += 1
        _, workdir, token = arguments
        if self.behave:
            (Path(workdir) / "observed.txt").write_text("AEGIS_OK:" + token, encoding="utf-8")
            self.rows.append((str(self.pid), "WriteFile", workdir + "\\observed.txt", "SUCCESS"))
        return {"launch": "STARTED", "pid": self.pid, "exit_code": 0 if self.behave else 3, "timed_out": False,
                "elapsed_seconds": 0.4, "stdout": ("AEGIS_REHEARSAL_BASELINE:" + token + "\n") if self.behave else "",
                "stderr": "", "technical_error": None}


class FunctionalityRunTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.procmon = self.root / "Procmon64a.exe"
        self.procmon.write_bytes(b"inert procmon stand-in")
        self.sample = self.root / "baseline.exe"
        self.sample.write_bytes(b"inert sample stand-in")

    def tearDown(self):
        self.temp.cleanup()

    def runs(self, name="baseline"):
        return [{"sample_id": "baseline", "path": str(self.sample), "sha256": lab.sha256(self.sample),
                 "workdir": str(self.root / "runs" / name)}]

    def run_card(self, system, runs=None):
        return lab.functionality(system, CARD, runs or self.runs(), procmon=self.procmon,
                                 procmon_sha256=lab.sha256(self.procmon), work=self.root)

    def test_run_records_have_the_evaluator_fields_and_pass(self):
        report = self.run_card(FakeMonitorLab([STATE_F]))
        run = report["runs"][0]["run"]
        self.assertEqual(set(run), functionality_card.RUN_FIELDS)
        rows = functionality_card.read_monitor_csv(self.root / report["csv"])
        record, details = functionality_card.evaluate(CARD, run, rows, lab.sha256(self.sample),
                                                      monitor_sha256=report["monitor"]["csv_sha256"])
        self.assertEqual(record["status"], "PASS", details["reasons"])

    def test_misbehaving_program_fails_its_card(self):
        report = self.run_card(FakeMonitorLab([STATE_F], behave=False))
        rows = functionality_card.read_monitor_csv(self.root / report["csv"])
        # The CSV has no rows for this PID, so the outcome is unknown rather than a failure.
        record, details = functionality_card.evaluate(CARD, report["runs"][0]["run"], rows, lab.sha256(self.sample),
                                                      monitor_sha256=report["monitor"]["csv_sha256"])
        self.assertEqual((record["status"], details["reasons"]), ("INCONCLUSIVE", ["MONITOR_HAS_NO_EVENTS_FOR_PROCESS"]))

    def test_existing_work_directory_and_changed_tools_are_refused(self):
        (self.root / "runs" / "baseline").mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "must be new"):
            self.run_card(FakeMonitorLab([STATE_F]))
        with self.assertRaisesRegex(ValueError, "Process Monitor does not match"):
            lab.functionality(FakeMonitorLab([STATE_F]), CARD, self.runs("other"), procmon=self.procmon,
                              procmon_sha256="0" * 64, work=self.root)

    def test_unaccepted_license_stops_the_check(self):
        system = FakeMonitorLab([STATE_F])
        system.license_accepted = lambda: False
        with self.assertRaisesRegex(ValueError, "license"):
            self.run_card(system)


def key(path):
    return str(path).rstrip("\\").casefold()


class FakeVM:
    """VIX-like connection with an in-memory guest disk and cold snapshots."""

    def __init__(self, snapshots, guest):
        base = {key(PYTHON): b"python", key(LOCAL): None, key(r"C:\Lab\Desktop"): None}
        self.snapshots = {name: dict(base) for name in snapshots}
        self.fs, self.on, self.pending = dict(base), False, False
        self.guest, self.calls, self.manual_boot, self.uac_approved = guest, [], False, True
        self.keep_on_revert = None

    def state(self):
        return {"powered_on": self.on, "powered_off": not self.on}

    def shutdown(self):
        self.calls.append("shutdown")
        self.on = False

    def revert_cold_snapshot(self, name):
        if self.on:
            raise ValueError("Revert requires a powered-off VM")
        survivor = {k: v for k, v in self.fs.items() if self.keep_on_revert and k.startswith(self.keep_on_revert)}
        self.fs = {**self.snapshots[name], **survivor}
        self.calls.append("revert:" + name)

    def create_cold_snapshot(self, name):
        if self.on:
            raise ValueError("Snapshot requires a powered-off VM")
        self.snapshots[name] = dict(self.fs)
        self.calls.append("snapshot:" + name)

    def power_on(self):
        if self.manual_boot:
            raise ManualBootRequired("Start the VM in Fusion")
        self.on = True

    def reopen(self):
        self.on = True
        return self.state()

    def wait_tools(self):
        pass

    def login(self, username, credential, interactive=False):
        self.calls.append("login-desktop" if interactive else "login")

    def environment(self, name):
        return {"LOCALAPPDATA": LOCAL, "USERPROFILE": r"C:\Lab"}[name]

    def exists(self, path):
        return key(path) in self.fs

    def mkdir(self, path):
        self.fs[key(path)] = None

    def copy_to(self, source, destination):
        if key(destination) in self.fs:
            raise ValueError("Refusing to overwrite guest data")
        self.fs[key(destination)] = Path(source).read_bytes()

    def copy_from(self, source, destination, *, timeout=45):
        if Path(destination).exists():
            raise ValueError("Expected a new host result")
        Path(destination).write_bytes(self.fs[key(source)])

    def run(self, program, arguments, *, wait=True, timeout=60):
        if program == vm_research_lab.POWERSHELL:
            script = base64.b64decode(arguments.rsplit(" ", 1)[1]).decode("utf-16le")
            if script.startswith("Remove-Item"):
                folder = key(re.search(r"-LiteralPath '([^']+)'", script).group(1))
                self.fs = {k: v for k, v in self.fs.items() if not (k == folder or k.startswith(folder + "\\"))}
                return 0
            if self.uac_approved:
                self.guest_run(re.search(r"-ArgumentList '(.+)' -Wait", script).group(1).replace("''", "'"),
                               elevated=True)
            return 0
        self.calls.append("run")
        return self.guest_run(arguments, elevated=False)

    def guest_run(self, arguments, *, elevated):
        _, _, action, _, request_path, _, output = arguments.split(" ")
        request = json.loads(self.fs[key(request_path)])
        kit = request_path.rsplit("\\", 1)[0]
        try:
            report = self.guest(action, request, kit, self, elevated)
            self.fs[key(output)] = json.dumps(report).encode()
            return 0
        except Exception as exc:
            failure = output.rsplit("\\", 1)[0] + "\\failure-report.json"
            self.fs[key(failure)] = json.dumps({"kind": "lab_failure", "error_type": type(exc).__name__,
                                                "message": str(exc)}).encode()
            return 1

    def close(self):
        self.calls.append("close")


class HostLabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp.name) / "panel"
        self.workspace.mkdir()
        self.state = STATE_A
        self.vm = FakeVM(["Aegis-Inert-" + "5" * 16], self.answer)
        self.prompts = []
        self.lab = vm_research_lab.ResearchLab(self.vm, self.workspace, username="AegisLab", credential="x",
                                               tools=TOOLS, prompt=self.prompts.append, progress=lambda m: None,
                                               poll_seconds=0, wait_limit=5)
        self.sample = Path(self.temp.name) / "baseline.exe"
        self.sample.write_bytes(b"inert sample stand-in")

    def tearDown(self):
        self.temp.cleanup()

    def answer(self, action, request, kit, vm, elevated):
        if action in lab.ELEVATED and not elevated:
            raise ValueError("Approve the ordinary Windows UAC prompt for this check")
        if action == "probe":
            return {"kind": "lab_probe", "run_id": request["run_id"], "defender": dict(self.state),
                    "state": "A" if self.state["RealTimeProtectionEnabled"] else "F",
                    "active_network_adapters": [], "windows": {"CurrentBuild": "26300"},
                    "vmware_tools": {"present": True, "version": "13.0"}, "realtime_policy": {}}
        if action == "av":
            (item,) = request["files"]
            target = Path(self.temp.name) / (item["sample_id"] + ".bin")
            target.write_bytes(vm.fs[key(kit + "\\" + item["path"].replace("/", "\\"))])
            system = FakeSystem([STATE_A])
            report = grs.av_check(system, target, item["sha256"], wait_seconds=request["wait_seconds"],
                                  run_id=request["run_id"], sample_id=item["sample_id"])
            report.update(platform="Windows", architecture="ARM64",
                          code_sha256=grs.sha256(ROOT / "src" / "guest_research_scan.py"))
            return report
        if action == "functionality":
            folder = Path(self.temp.name) / "guest"
            folder.mkdir(exist_ok=True)
            sample = folder / "baseline.exe"
            sample.write_bytes(vm.fs[key(kit + "\\files\\baseline.exe")])
            procmon = folder / "Procmon64a.exe"
            procmon.write_bytes(b"inert procmon stand-in")
            runs = [{**f, "path": str(sample), "workdir": str(folder / "runs" / "baseline")}
                    for f in request["files"]]
            report = lab.functionality(FakeMonitorLab([STATE_F]), request["card"], runs, procmon=procmon,
                                       procmon_sha256=lab.sha256(procmon), work=folder)
            vm.fs[key(kit + "\\work\\" + report["csv"])] = (folder / report["csv"]).read_bytes()
            return {**report, "run_id": request["run_id"]}
        raise AssertionError(action)

    def register(self):
        return self.lab.register_a("Aegis-Inert-" + "5" * 16)

    def test_register_a_records_the_probe_and_restores(self):
        state = self.register()
        self.assertEqual((state["state"], state["snapshot"]), ("A", "Aegis-Inert-" + "5" * 16))
        self.assertEqual(state["windows"], {"CurrentBuild": "26300"})
        cycle = next(self.workspace.glob("research-lab/cycles/cycle-*"))
        self.assertTrue((cycle / "reverted.json").is_file())
        self.assertFalse(any("aegisresearch-" in k for k in self.vm.fs))
        self.assertEqual(self.vm.calls[-2:], ["shutdown", "revert:Aegis-Inert-" + "5" * 16])

    def test_register_a_refuses_a_guest_with_protection_off(self):
        self.state = STATE_F
        with self.assertRaisesRegex(ValueError, "not in state A"):
            self.register()
        self.assertFalse((self.workspace / "research-lab/states/A.json").exists())
        self.assertIn("revert:Aegis-Inert-" + "5" * 16, self.vm.calls)

    def test_next_boot_proves_the_previous_kit_is_gone(self):
        self.register()
        first = next(self.workspace.glob("research-lab/cycles/cycle-*"))
        self.assertFalse(vm_research_lab.restore_verified(first))
        self.lab.probe("A")
        (proof,) = first.glob("restored-*.json")
        self.assertEqual(json.loads(proof.read_text())["booted_snapshot"], "Aegis-Inert-" + "5" * 16)
        self.assertTrue(vm_research_lab.restore_verified(first))

    def test_a_boot_of_another_snapshot_is_no_restore_proof(self):
        self.register()
        self.state = STATE_F
        record = self.lab.make_f()
        self.lab.probe("F")  # reverted to F
        f_cycle = max(self.workspace.glob("research-lab/cycles/cycle-*"), key=lambda p: p.stat().st_mtime_ns)
        self.state = STATE_A
        self.lab.probe("A")  # booting A says nothing about the F revert
        self.assertFalse(vm_research_lab.restore_verified(f_cycle))
        self.assertEqual(list(f_cycle.glob("restored*.json")), [])
        self.state = STATE_F
        self.lab.probe("F")
        (proof,) = f_cycle.glob("restored-*.json")
        self.assertEqual(json.loads(proof.read_text())["booted_snapshot"], record["snapshot"])

    def test_a_failed_preparation_leaves_the_vm_off_and_reverted(self):
        self.register()
        original = self.vm.environment
        def environment(name):
            if name == "USERPROFILE":
                raise ValueError("Lab environment value is absent")
            return original(name)
        self.vm.environment = environment
        with self.assertRaisesRegex(ValueError, "environment value"):
            self.lab.av("baseline", self.sample, 5)
        self.assertFalse(self.vm.on)
        self.assertEqual(self.vm.calls[-1], "revert:Aegis-Inert-" + "5" * 16)

    def test_surviving_work_blocks_the_next_cycle(self):
        self.register()
        self.vm.keep_on_revert = key(LOCAL + r"\AegisResearch-")
        self.lab.probe("A")  # this cycle's kit survives its revert
        with self.assertRaisesRegex(ValueError, "survived the restore"):
            self.lab.probe("A")

    def test_cancel_at_the_desktop_prompt_leaves_the_vm_off_and_reverted(self):
        self.register()
        calls = len(self.vm.calls)

        def operator(message):
            if "darbalaukio" in message:
                raise ValueError("Žingsnis atšauktas; VM atkuriama")
        self.lab.prompt = operator
        with self.assertRaisesRegex(ValueError, "atšauktas"):
            self.lab.av("baseline", self.sample, 5)
        self.assertFalse(self.vm.on)
        self.assertEqual(self.vm.calls[calls:][-2:], ["shutdown", "revert:Aegis-Inert-" + "5" * 16])

    def test_an_unread_network_inventory_is_not_a_disconnected_network(self):
        original = self.answer
        def answer(action, request, kit, vm, elevated):
            value = original(action, request, kit, vm, elevated)
            value.pop("active_network_adapters")
            return {**value, "inventory_error": "CommandNotFoundException"}
        self.vm.guest = answer
        with self.assertRaisesRegex(ValueError, "Network adapters"):
            self.register()
        self.assertFalse((self.workspace / "research-lab/states/A.json").exists())
        cycle = next(self.workspace.glob("research-lab/cycles/cycle-*"))
        self.assertTrue(list(cycle.glob("error-*.json")))
        self.assertFalse((cycle / "finished.json").exists())

    def test_a_rejected_report_is_recorded_as_an_error(self):
        self.register()
        original = self.answer
        self.vm.guest = lambda *args: {**original(*args), "sha256": "0" * 64}
        with self.assertRaises(ValueError):
            self.lab.av("baseline", self.sample, 5)
        cycle = max(self.workspace.glob("research-lab/cycles/cycle-*"), key=lambda p: p.stat().st_mtime_ns)
        self.assertTrue((cycle / "report.json").is_file() and list(cycle.glob("error-*.json")))
        self.assertFalse((cycle / "finished.json").exists())
        self.assertTrue((cycle / "reverted.json").is_file())

    def test_the_vm_is_restored_even_when_the_error_record_cannot_be_written(self):
        self.register()
        original_env = self.vm.environment
        def environment(name):
            if name == "USERPROFILE":
                raise ValueError("Lab environment value is absent")
            return original_env(name)
        self.vm.environment = environment
        original_write = vm_research_lab.write_json
        def write_json(path, value):
            if Path(path).name.startswith("error-"):
                raise OSError("disk full")
            return original_write(path, value)
        # An unfinished cycle of this snapshot needs an error record, which cannot be written.
        stale = self.workspace / "research-lab" / "cycles" / ("cycle-" + "e" * 32)
        stale.mkdir()
        (stale / "cycle.json").write_text(json.dumps({"snapshot": "Aegis-Inert-" + "5" * 16, "action": "av",
                                                      "state": "A", "started_at_utc": "2026-11-28T00:00:00+00:00"}))
        vm_research_lab.write_json = write_json
        try:
            with self.assertRaisesRegex(OSError, "disk full"):
                self.lab.av("baseline", self.sample, 5)
            self.assertFalse(self.vm.on)
            self.assertEqual(self.vm.calls[-1], "revert:Aegis-Inert-" + "5" * 16)
            # The same holds while preparing state F.
            self.vm.environment = original_env
            self.lab.prompt = lambda message: (_ for _ in ()).throw(ValueError("Žingsnis atšauktas"))
            with self.assertRaises(ValueError):
                self.lab.make_f()
            self.assertFalse(self.vm.on)
            self.assertEqual(self.vm.calls[-1], "revert:Aegis-Inert-" + "5" * 16)
        finally:
            vm_research_lab.write_json = original_write

    def test_cancel_or_failure_in_make_f_discards_the_changes(self):
        self.register()
        def operator(message):
            if "Tamper Protection" in message:
                raise ValueError("Žingsnis atšauktas; VM atkuriama")
        self.lab.prompt = operator
        with self.assertRaisesRegex(ValueError, "atšauktas"):
            self.lab.make_f()
        self.assertFalse(self.vm.on)
        self.assertEqual(self.vm.calls[-1], "revert:Aegis-Inert-" + "5" * 16)
        # Protection never turned off: every attempt is recorded and the VM is restored to A.
        self.lab.prompt = lambda message: None
        with self.assertRaisesRegex(ValueError, "not in state F"):
            self.lab.make_f()
        self.assertFalse(self.vm.on)
        self.assertEqual(self.vm.calls[-1], "revert:Aegis-Inert-" + "5" * 16)
        self.assertFalse(any(c.startswith("snapshot:") for c in self.vm.calls))
        probes = [c for c in self.workspace.glob("research-lab/cycles/cycle-*")
                  if json.loads((c / "cycle.json").read_text())["state"] == "F"]
        self.assertEqual(len(probes), 3)
        self.assertTrue(all(list(c.glob("error-*.json")) for c in probes))

    def test_manual_boot_waits_for_the_operator(self):
        self.vm.manual_boot = True
        self.register()
        self.assertTrue(any("Paleisk VM" in p for p in self.prompts))

    def test_make_f_snapshots_only_a_verified_state_f(self):
        self.register()
        with self.assertRaisesRegex(ValueError, "not in state F"):
            self.lab.make_f()  # the operator has not turned protection off
        self.assertFalse(any(c.startswith("snapshot:") for c in self.vm.calls))
        self.state = STATE_F
        record = self.lab.make_f()
        self.assertRegex(record["snapshot"], r"^Aegis-StateF-[0-9a-f]{16}$")
        self.assertFalse(any("aegisresearch-" in k for k in self.vm.snapshots[record["snapshot"]]))
        self.assertTrue(any("Tamper Protection" in p for p in self.prompts))

    def test_make_f_lets_the_operator_retry_without_a_new_revert(self):
        self.register()

        def operator(message):
            self.prompts.append(message)
            if "dar įjungta" in message:
                self.state = STATE_F  # the policy took effect after the first probe
        self.lab.prompt = operator
        reverts = self.vm.calls.count("revert:Aegis-Inert-" + "5" * 16)
        record = self.lab.make_f()
        self.assertEqual(record["state"], "F")
        self.assertEqual(self.vm.calls.count("revert:Aegis-Inert-" + "5" * 16), reverts + 1)
        self.assertFalse(any("aegisresearch-" in k for k in self.vm.snapshots[record["snapshot"]]))

    def test_av_check_needs_uac_and_validates_the_report(self):
        self.register()
        cycle, report = self.lab.av("baseline", self.sample, 5)
        self.assertEqual((report["status"], report["sha256"]), ("NOT_DETECTED", grs.sha256(self.sample)))
        self.assertIn("login-desktop", self.vm.calls)
        record = json.loads((cycle / "cycle.json").read_text())
        self.assertRegex(record["launcher"], r"Desktop\\Aegis-Research-[0-9a-f]{8}\.cmd$")
        self.assertTrue((cycle / "reverted.json").is_file())

    def test_unapproved_uac_times_out_and_still_restores(self):
        self.register()
        self.vm.uac_approved = False
        self.lab.wait_limit = 0.05
        with self.assertRaises(TimeoutError):
            self.lab.av("baseline", self.sample, 5)
        cycle = max(self.workspace.glob("research-lab/cycles/cycle-*"), key=lambda p: p.stat().st_mtime_ns)
        self.assertTrue((cycle / "reverted.json").is_file())
        self.assertFalse((cycle / "report.json").exists())

    def test_guest_failure_is_reported_and_restored(self):
        self.register()
        original = self.answer
        self.vm.guest = lambda *args: (_ for _ in ()).throw(ValueError("Close the running Process Monitor"))
        with self.assertRaisesRegex(ValueError, "Close the running Process Monitor"):
            self.lab.av("baseline", self.sample, 5)
        self.vm.guest = original
        cycle = max(self.workspace.glob("research-lab/cycles/cycle-*"), key=lambda p: p.stat().st_mtime_ns)
        self.assertTrue((cycle / "failure.json").is_file() and (cycle / "reverted.json").is_file())

    def test_checks_need_a_registered_state(self):
        with self.assertRaisesRegex(ValueError, "State F is not registered"):
            self.lab.eicar_custom()
        self.assertEqual(self.vm.calls, [])

    def test_functionality_cycle_evaluates_the_card(self):
        self.register()
        self.state = STATE_F
        self.lab.make_f()
        card = Path(self.temp.name) / "card.json"
        card.write_text(json.dumps(CARD))
        workdir = TOOLS["guest_root"] + r"\work-1\runs\baseline"
        cycle, results = self.lab.functionality(card, [("baseline", self.sample, workdir)])
        self.assertEqual(results, [{"sample_id": "baseline", "status": "PASS", "reasons": []}])
        record = json.loads((cycle / "record-baseline.json").read_text())
        self.assertEqual((record["synthetic"], record["card_sha256"]), (True, functionality_card.card_sha256(CARD)))

    def test_snapshot_names_and_guest_paths_are_checked(self):
        for name in ("Aegis-StateB-" + "0" * 16, "Other", "Aegis-StateA-xyz"):
            with self.assertRaises(ValueError):
                vm_research_lab.snapshot_name(name)
        with self.assertRaises(ValueError):
            vm_research_lab.guest_path(r"C:\Lab\..\Windows")
        card = Path(self.temp.name) / "card.json"
        card.write_text(json.dumps(CARD))
        with self.assertRaisesRegex(ValueError, "at least one file"):
            self.lab.functionality(card, [])


if __name__ == "__main__":
    unittest.main()
