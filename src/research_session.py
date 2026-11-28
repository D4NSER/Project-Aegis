"""The desktop app's laboratory section: seven stage-3 controls, one at a time.

Wraps `vm_research_lab.ResearchLab` in a worker thread for the desktop
bridge. Each step is one cold VM cycle with fixed, harmless inputs: the two
managed PE programs of the earlier rehearsal and the official EICAR text,
which the guest creates itself. When the operator must act (start the VM in
Fusion, log in to the lab desktop, prepare state F, approve UAC), the session
shows the request and waits for "continue". Step results are read back from
the cycle records on disk, so they survive restarts; each is compared with the
outcome written down before the run.
"""
import json
import math
from pathlib import Path, PureWindowsPath
import queue
import threading

import aegis
from control_workspace import write_json

STEPS = (
    {"id": "register_a", "title": "Užregistruoti būseną A", "state": "A", "uac": False,
     "what": "Esama švari kopija tikrinama ir įrašoma kaip būsena A: apsauga realiu laiku įjungta.",
     "expected": "Būsena A, apsauga įjungta, tinklo nėra; įrašomos Windows ir VMware Tools versijos."},
    {"id": "eicar_realtime", "title": "EICAR realaus laiko kontrolė", "state": "A", "uac": True,
     "what": "Windows viduje sukuriamas standartinis EICAR testinis tekstas (ne virusas, nepaleidžiamas). "
             "Matuojama, per kiek laiko Defender jį užfiksuoja.",
     "expected": "Aptikta realiu laiku įrašius arba atidarius; šaltinis atitinka „Real-Time Protection“."},
    {"id": "av_control", "title": "AV patikra nekenksmingai programai", "state": "A", "uac": True,
     "what": "Mūsų nekenksminga repeticijos programa tikrinama taip, kaip bus tikrinami tyrimo failai.",
     "expected": "Neaptikta (pilna neigiama patikra)."},
    {"id": "make_f", "title": "Sukurti būseną F", "state": "A", "uac": False,
     "what": "Tu VM lange išjungi Tamper Protection ir apsaugą realiu laiku. Programa patikrina ir sukuria švarią "
             "F kopiją.",
     "expected": "Būsena F: antivirusinė įjungta, apsauga realiu laiku išjungta."},
    {"id": "eicar_custom", "title": "EICAR atskiros patikros kontrolė", "state": "F", "uac": True,
     "what": "Be apsaugos realiu laiku EICAR tekstas lieka diske, todėl jį gali aptikti tik atskira Defender patikra.",
     "expected": "Aptikta atskira patikra; šaltinis atitinka „User“."},
    {"id": "yara_control", "title": "YARA kontrolė", "state": "F", "uac": False,
     "what": "Kontrolinė taisyklė taikoma abiem nekenksmingoms programoms.",
     "expected": "baseline – žymuo rastas; variant – žymens nėra."},
    {"id": "functionality_control", "title": "Funkcionalumo kontrolė", "state": "F", "uac": True,
     "what": "Abi programos paleidžiamos su Process Monitor ir vertinamos pagal tą pačią kortelę.",
     "expected": "baseline – atitinka (PASS); variant – neatitinka dėl išvesties (FAIL: STDOUT)."},
)
STEP_IDS = [step["id"] for step in STEPS]
CARD = {"schema": 1, "kind": "functionality_card", "card_id": "lab-control-baseline",
        "original_id": "lab-control-baseline", "created_at_utc": "2026-11-28T12:00:00+00:00",
        "input": {"arguments": ["{workdir}", "{token}"]}, "time_limit_seconds": 8,
        "expected": {"exit_code": 0, "stdout": "AEGIS_REHEARSAL_BASELINE:{token}", "stderr_empty": True,
                     "files": [{"path": "observed.txt", "content": "AEGIS_OK:{token}"}]},
        "evidence": {"monitor": "process_monitor",
                     "operations": [{"operation": "WriteFile", "path": "observed.txt", "result": "SUCCESS"}]}}
RULESET = ('rule Aegis_Lab_Control_Baseline\n{\n    strings:\n        $s = "AEGIS_REHEARSAL_BASELINE" ascii wide\n'
           '    condition:\n        $s\n}\n')


def _read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write_fixed(path, text):
    """Inputs are written once; a different existing file is refused, never replaced."""
    path = Path(path)
    if path.exists():
        if path.read_text(encoding="utf-8") != text:
            raise ValueError("A fixed laboratory input changed: " + path.name)
    else:
        path.write_text(text, encoding="utf-8")
    return path


def lab_inputs(workspace):
    """The current prepared baseline, its tool kit and the rehearsal programs, from the saved records."""
    workspace = aegis.external_path(workspace)
    active = _read(workspace / "vm-controls" / "active-session.json")
    snapshot = active["snapshot"]
    chosen = None
    for folder in sorted(workspace.glob("lab-preparation/preparation-*")):
        ready, resolved = folder / "baseline-ready.json", folder / "resolved.json"
        if ready.is_file() and _read(ready).get("snapshot") == snapshot and resolved.is_file() \
                and _read(resolved).get("all_checks_passed") is True:
            chosen = folder
    if chosen is None:
        raise ValueError("No verified tool kit belongs to the current baseline " + snapshot)
    report = _read(chosen / "report.json")
    programs = {}
    for key in ("baseline", "variant"):
        observed = PureWindowsPath(report["fixtures"][key]["run"]["observed_path"])
        work = chosen / "artifacts" / ("work-" + report["run_id"].removeprefix("rehearsal-"))
        path = work / (key + ".exe")
        if not path.is_file() or aegis.digest(path) != report["fixtures"][key]["pe"]["sha256"]:
            raise ValueError("Rehearsal program changed or is missing: " + key)
        programs[key] = {"path": str(path), "workdir": str(observed.parent)}
    inputs = workspace / "research-lab" / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    card = _write_fixed(inputs / "card-baseline.json", json.dumps(CARD, indent=2) + "\n")
    ruleset = _write_fixed(inputs / "control-ruleset.yar", RULESET)
    pending = _read(chosen / "pending.json")
    tools = {"guest_root": pending["guest_root"], "yara_sha256": pending["files"]["yara64.exe"],
             "procmon_sha256": pending["files"]["Procmon64a.exe"]}
    return {"snapshot": snapshot, "tools": tools, "programs": programs, "card": str(card), "ruleset": str(ruleset)}


def _cycles(root):
    rows = []
    for folder in root.glob("cycles/cycle-*"):
        try:
            rows.append((_read(folder / "cycle.json")["started_at_utc"], folder))
        except (OSError, ValueError, KeyError):
            continue
    return [folder for _, folder in sorted(rows)]


def _outcome(folder):
    """(report or None, error text or None) of one cycle.

    Only a finished cycle without an error record counts: its report passed
    the host's validation and is the one whose hash was recorded.
    """
    errors = [_read(path).get("message") for path in sorted(folder.glob("error-*.json"))]
    if errors:
        return None, errors[-1] or "Klaida"
    finished = folder / "finished.json"
    report_path = folder / "report.json"
    if not finished.is_file() or not report_path.is_file():
        return None, "Ciklas nebaigtas"
    if _read(finished).get("report_sha256") != aegis.digest(report_path):
        return None, "Ataskaita pasikeitė po patvirtinimo"
    return _read(report_path), None


def restore_status(folder):
    """VERIFIED after a later boot of the same snapshot found the kit gone; PENDING until then."""
    from vm_research_lab import restore_verified
    if restore_verified(folder):
        return "VERIFIED"
    if (folder / "reverted.json").is_file():
        return "PENDING"
    finished = folder / "finished.json"
    if finished.is_file() and _read(finished).get("snapshot_created"):
        return "SNAPSHOT_CREATED"
    return "NOT_REVERTED"


def step_results(workspace):
    """The latest recorded attempt of each step, judged against its expected outcome."""
    root = aegis.external_path(workspace) / "research-lab"
    states = {}
    for name in ("A", "F"):
        path = root / "states" / (name + ".json")
        states[name] = _read(path) if path.is_file() else None
    results = {}
    for folder in _cycles(root):
        cycle = _read(folder / "cycle.json")
        action = cycle["action"]
        if action == "probe":
            finished = _read(folder / "finished.json") if (folder / "finished.json").is_file() else {}
            if cycle["state"] == "F" and cycle["snapshot"] == (states["A"] or {}).get("snapshot"):
                step = "make_f"
            elif states["A"] and states["A"]["probe_cycle"] == folder.name:
                step = "register_a"
            elif not states["A"] and cycle["state"] == "A":
                step = "register_a"
            else:
                continue
        else:
            step = {"eicar_realtime": "eicar_realtime", "av": "av_control", "eicar_custom": "eicar_custom",
                    "yara": "yara_control", "functionality": "functionality_control"}.get(action)
            if step is None:
                continue
        report, error = _outcome(folder)
        results[step] = judge(step, folder, report, error, states)
    return states, results


def judge(step, folder, report, error, states):
    value = {"cycle": folder.name, "at": _read(folder / "cycle.json")["started_at_utc"], "ok": False,
             "summary": error or "Ataskaitos nėra", "details": None, "restore": restore_status(folder)}
    if report is None:
        return value
    if step in {"register_a", "make_f"}:
        defender = report.get("defender") or {}
        windows = report.get("windows") or {}
        value["summary"] = ("Būsena " + str(report.get("state")) + " · apsauga realiu laiku "
                            + ("įjungta" if defender.get("RealTimeProtectionEnabled") else "išjungta")
                            + " · Windows " + str(windows.get("CurrentBuild", "?")) + "."
                            + str(windows.get("UBR", "?")))
        name = "A" if step == "register_a" else "F"
        # The state counts only through the validated cycle that its registration record names.
        registered = states.get(name) and states[name].get("probe_cycle") == folder.name
        value["ok"] = bool(report.get("state") == name and not error and registered)
        if step == "make_f" and registered:
            value["summary"] += " · kopija " + states[name]["snapshot"]
    elif step in {"eicar_realtime", "eicar_custom"}:
        sources = sorted({str(e.get("source")) for e in (report.get("records") or {}).get("events", [])})
        trigger = {"write": "po įrašymo", "read": "atidarius", "copy": "tik nukopijavus"}.get(
            report.get("trigger"), "")
        value["summary"] = (str(report.get("status")) + (" " + trigger if trigger else "")
                            + (" per " + str(report["seconds_to_record"]) + " s"
                               if report.get("seconds_to_record") is not None else "")
                            + (" · šaltinis: " + ", ".join(sources) if sources else ""))
        value["ok"] = report.get("status") == "DETECTED" and report.get("source_verdict") == "SUPPORTED"
        if step == "eicar_realtime":
            # Real-time protection must record the text when it is written or first opened; the AV
            # check opens each file once, so either calibrates the waiting period.
            value["ok"] = value["ok"] and report.get("trigger", "write") in {"write", "read"}
            if value["ok"]:
                value["wait_seconds"] = max(10, math.ceil(2 * report["seconds_to_record"]))
    elif step == "av_control":
        value["summary"] = str(report.get("status")) + " · " + ", ".join(report.get("reasons") or [])
        value["ok"] = report.get("status") == "NOT_DETECTED"
    elif step == "yara_control":
        files = {f["sample_id"]: f["status"] for f in report.get("files", [])}
        value["summary"] = " · ".join(k + ": " + v for k, v in files.items())
        value["ok"] = files == {"baseline": "MATCHED", "variant": "NOT_MATCHED"}
    elif step == "functionality_control":
        outcomes = {}
        for sample in ("baseline", "variant"):
            path = folder / ("details-" + sample + ".json")
            if path.is_file():
                details = _read(path)
                outcomes[sample] = (details["status"], details["reasons"])
        value["summary"] = " · ".join(k + ": " + s + (" (" + ", ".join(r) + ")" if r else "")
                                      for k, (s, r) in outcomes.items()) or value["summary"]
        value["ok"] = outcomes == {"baseline": ("PASS", []), "variant": ("FAIL", ["STDOUT"])}
    return value


class ResearchSession:
    """One VIX connection and one step at a time; credentials only in memory."""

    def __init__(self, workspace, config, *, connect=None):
        self.workspace = aegis.external_path(workspace)
        self.config = config
        self.connect_vm = connect or self._connect
        self.lab = None
        self.busy = False
        self.running = None
        self.status = "Įvesk abu laboratorijos slaptažodžius."
        self.history = ""
        self.waiting = None
        self.answer = threading.Event()
        self.closed = self.cancelled = False
        self.actions = queue.Queue()
        self.thread = threading.Thread(target=self.worker, daemon=True)
        self.thread.start()

    def _connect(self, vm_credential):
        from fusion_guest_ops import FusionGuestOps
        bundle = Path(self.config["vm_bundle"])
        vmx = bundle / (bundle.stem + ".vmx")
        if not vmx.is_file():
            import control_panel
            control_panel.mount_vm_storage(self.config)
        connection = FusionGuestOps(timeout=20)
        connection.open(vmx, vm_credential)
        return connection

    def log(self, message):
        self.status = message
        self.history = (self.history + message + "\n")[-16000:]

    def ask(self, message):
        """Called from the worker: show the request and wait for the operator."""
        self.answer.clear()
        # The command-line wording asks for Enter; here the operator presses the button.
        self.waiting = message.replace("spausk Enter", "spausk „Atlikau – tęsti“").rstrip(" …").rstrip() + "."
        self.log("Laukiama tavo veiksmo.")
        while not self.answer.wait(0.5):
            if self.closed:
                raise ValueError("Sesija uždaryta")
        self.waiting = None
        if self.cancelled:
            self.cancelled = False
            # The cycle restores the VM on its way out.
            raise ValueError("Žingsnis atšauktas; VM atkuriama")

    def submit(self, action, payload=None):
        if action in {"continue", "cancel"}:
            if not self.waiting:
                raise ValueError("Šiuo metu nieko nelaukiama.")
            self.cancelled = action == "cancel"
            self.answer.set()
            return
        if self.busy:
            raise ValueError("Palauk, kol baigsis dabartinis žingsnis.")
        if action == "connect":
            if self.lab:
                raise ValueError("Sesija jau atverta.")
            if (not isinstance(payload, (tuple, list)) or len(payload) != 2
                    or not all(isinstance(v, str) and 0 < len(v) <= 1024 and "\0" not in v for v in payload)):
                raise ValueError("Užpildyk abu esamų slaptažodžių laukus.")
        elif action == "step":
            if not self.lab:
                raise ValueError("Pirmiausia prisijunk prie laboratorijos.")
            if payload not in self.allowed():
                raise ValueError("Šis žingsnis dabar neprieinamas.")
        else:
            raise ValueError("Neatpažintas laboratorijos veiksmas.")
        self.busy = True
        self.running = payload if action == "step" else None
        self.actions.put((action, payload))

    def allowed(self):
        states, results = step_results(self.workspace)
        a, f = states["A"], states["F"]
        calibrated = (results.get("eicar_realtime") or {}).get("wait_seconds")
        return [step for step, ready in (
            ("register_a", not a), ("eicar_realtime", bool(a)), ("av_control", bool(a and calibrated)),
            ("make_f", bool(a and not f)), ("eicar_custom", bool(f)), ("yara_control", bool(f)),
            ("functionality_control", bool(f))) if ready]

    def worker(self):
        while True:
            action, payload = self.actions.get()
            if action == "close":
                return
            try:
                if action == "connect":
                    self.connect(*payload)
                else:
                    self.run_step(payload)
            except Exception as exc:  # The cycle records keep the details; the UI shows the message.
                self.log("Nepavyko: " + (str(exc) if isinstance(exc, (ValueError, OSError, TimeoutError))
                                         else type(exc).__name__))
            finally:
                payload = None
                self.busy, self.running, self.waiting = False, None, None

    def connect(self, vm_credential, lab_credential):
        from vm_research_lab import ResearchLab
        self.log("Jungiamasi prie VM…")
        inputs = lab_inputs(self.workspace)
        connection = self.connect_vm(vm_credential)
        self.lab = ResearchLab(connection, self.workspace, username=self.config.get("guest_username", "AegisLab"),
                               credential=lab_credential, tools=inputs["tools"], prompt=self.ask, progress=self.log)
        self.log("Prisijungta. Pasirink žingsnį.")

    def run_step(self, step):
        inputs = lab_inputs(self.workspace)
        title = next(s["title"] for s in STEPS if s["id"] == step)
        self.log("Vykdoma: " + title + "…")
        programs = inputs["programs"]
        if step == "register_a":
            self.lab.register_a(inputs["snapshot"])
        elif step == "eicar_realtime":
            self.lab.eicar_realtime(60)
        elif step == "av_control":
            wait = step_results(self.workspace)[1]["eicar_realtime"]["wait_seconds"]
            self.lab.av("baseline", programs["baseline"]["path"], wait)
        elif step == "make_f":
            self.lab.make_f()
        elif step == "eicar_custom":
            self.lab.eicar_custom()
        elif step == "yara_control":
            self.lab.yara([(k, programs[k]["path"]) for k in ("baseline", "variant")], inputs["ruleset"])
        elif step == "functionality_control":
            self.lab.functionality(inputs["card"], [(k, programs[k]["path"], programs[k]["workdir"])
                                                    for k in ("baseline", "variant")])
        result = step_results(self.workspace)[1].get(step, {})
        self.log(title + ": " + str(result.get("summary", "baigta"))
                 + (" — sutampa su laukiamu." if result.get("ok") else " — NESUTAMPA su laukiamu, peržiūrėk."))

    def snapshot(self):
        states, results = step_results(self.workspace)
        allowed = [] if self.busy or not self.lab else self.allowed()
        return {"connected": bool(self.lab), "busy": self.busy, "running": self.running, "status": self.status,
                "waiting": self.waiting, "history": self.history,
                "states": {k: ({"snapshot": v["snapshot"], "registered_at_utc": v["registered_at_utc"]} if v else None)
                           for k, v in states.items()},
                "steps": [{**step, "allowed": step["id"] in allowed, "result": results.get(step["id"])}
                          for step in STEPS]}

    def disconnect(self):
        if self.busy:
            raise ValueError("Pirmiausia užbaik arba atšauk dabartinį žingsnį.")
        self.closed = True
        self.answer.set()
        self.actions.put(("close", None))
        self.thread.join(timeout=20)
        if self.lab:
            self.lab.close()
            self.lab = None


def overview(workspace):
    """Read-only view for the section before a session is opened."""
    states, results = step_results(workspace)
    return {"connected": False, "busy": False, "running": None, "status": "Įvesk abu laboratorijos slaptažodžius.",
            "waiting": None, "history": "",
            "states": {k: ({"snapshot": v["snapshot"], "registered_at_utc": v["registered_at_utc"]} if v else None)
                       for k, v in states.items()},
            "steps": [{**step, "allowed": False, "result": results.get(step["id"])} for step in STEPS]}
