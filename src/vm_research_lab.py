"""Host side of the stage-3 laboratory controls: one cold VM cycle per check.

Every check starts from a named cold snapshot: state A (real-time protection
on) for AV checks, state F (off) for YARA and functionality. The host copies
a small kit and the selected files into the guest, runs one action of
`guest_research_lab.py`, keeps the report outside the VM, then shuts the
guest down and reverts the snapshot. At the next boot the host proves that
the previous kit is gone before any new work starts. Checks that read
Defender's history or start Process Monitor need ordinary administrator
rights: the operator approves Windows UAC in the VM window.

The operator types both credentials into hidden terminal prompts; they stay
in memory and are never saved, logged or passed to guest programs. Nothing
here changes Defender, network or license settings; state F is prepared by
the operator by hand and only recorded here.
"""
import argparse
import base64
from datetime import datetime, timezone
import getpass
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import secrets
import subprocess
import sys
import time
import uuid

import aegis
import functionality_card
import guest_research_lab
import scan_bridge
from control_workspace import write_json
from fusion_control import ManualBootRequired

SOURCES = ("aegis.py", "control_workspace.py", "guest_control.py", "guest_scanners.py",
           "guest_research_scan.py", "guest_research_lab.py")
STATE_OF = {"eicar_realtime": "A", "av": "A", "eicar_custom": "F", "yara": "F", "candidate": "F",
            "functionality": "F"}
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
REPORT_LIMIT = 4 * 1024 * 1024
CSV_LIMIT = 128 * 1024 * 1024
STATE_F_STEPS = """Būsenos F paruošimas (VM lange, AegisLab paskyroje):
 1. Windows Security -> Virus & threat protection -> Manage settings:
    išjunk Tamper Protection.
 2. Win+R -> gpedit.msc -> Computer Configuration -> Administrative Templates ->
    Windows Components -> Microsoft Defender Antivirus -> Real-time Protection ->
    „Turn off real-time protection“ = Enabled. Jei gpedit nėra, registre
    HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection
    sukurk DWORD DisableRealtimeMonitoring = 1.
 3. Neišjunk pačios antivirusinės ir nekeisk tinklo. Uždaryk Windows Security.
Kai baigsi, spausk Enter: programa patikrins faktinę būseną ir tik tada
sukurs šaltą F kopiją."""


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def windows_arguments(*values):
    return subprocess.list2cmdline([str(value) for value in values])


def guest_path(value):
    path = PureWindowsPath(str(value))
    if not path.is_absolute() or ".." in path.parts or len(str(path)) > 240:
        raise ValueError("Expected an absolute guest path without '..': " + str(value))
    return path


def snapshot_name(value):
    if not isinstance(value, str) or not re.fullmatch(r"Aegis-(Inert|StateA|StateF)-[0-9a-f]{16}", value):
        raise ValueError("Expected a managed cold snapshot name")
    return value


def restore_verified(cycle):
    """True when a restore proof was taken on a boot of the snapshot this cycle reverted to."""
    reverted = Path(cycle) / "reverted.json"
    if not reverted.is_file():
        return False
    snapshot = read_json(reverted).get("snapshot")
    return any(read_json(path).get("booted_snapshot") == snapshot and read_json(path).get("vm_restore_verified") is True
               for path in sorted(Path(cycle).glob("restored*.json")))


def read_json(path, limit=REPORT_LIMIT):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > limit:
        raise ValueError("Unexpected record: " + path.name)
    return json.loads(path.read_text(encoding="utf-8"))


class ResearchLab:
    def __init__(self, connection, workspace, *, username, credential, tools, prompt=input,
                 progress=print, poll_seconds=3, wait_limit=1200):
        self.connection = connection
        self.workspace = aegis.external_path(workspace)
        self.root = self.workspace / "research-lab"
        for folder in (self.root, self.root / "states", self.root / "cycles"):
            if folder.is_symlink():
                raise ValueError("Unexpected laboratory folder link")
            folder.mkdir(parents=True, exist_ok=True)
        self.username, self.credential = username, credential
        if set(tools) != {"guest_root", "yara_sha256", "procmon_sha256"}:
            raise ValueError("The prepared tool kit needs its guest folder and pinned hashes")
        self.tools = {**tools, "guest_root": str(guest_path(tools["guest_root"]))}
        self.prompt, self.progress = prompt, progress
        self.poll_seconds, self.wait_limit = poll_seconds, wait_limit
        self.source = Path(__file__).resolve().parent
        self.python = None
        self.booted = None

    # --- registry of cold states -------------------------------------------------
    def state(self, name):
        path = self.root / "states" / (name + ".json")
        if not path.is_file():
            raise ValueError("State " + name + " is not registered yet")
        record = read_json(path)
        if record.get("state") != name:
            raise ValueError("State record mismatch: " + name)
        snapshot_name(record["snapshot"])
        return record

    def _register(self, name, snapshot, probe_cycle, report, note):
        path = self.root / "states" / (name + ".json")
        write_json(path, {"schema": 1, "kind": "lab_state", "state": name, "snapshot": snapshot,
                          "registered_at_utc": now(), "probe_cycle": probe_cycle.name,
                          "probe_sha256": digest(probe_cycle / "report.json"), "defender": report["defender"],
                          "windows": report.get("windows"), "vmware_tools": report.get("vmware_tools"),
                          "realtime_policy": report.get("realtime_policy"), "note": note})
        return read_json(path)

    # --- VM lifecycle ------------------------------------------------------------
    def boot(self, snapshot, *, desktop=False):
        """Revert to a cold snapshot, start it and log in; then prove earlier kits are gone."""
        snapshot_name(snapshot)
        if not self.connection.state()["powered_off"]:
            self.progress("VM įjungta: įprastai išjungiama prieš atkūrimą…")
            self.connection.shutdown()
        self.connection.revert_cold_snapshot(snapshot)
        self.booted = None
        try:
            self.connection.power_on()
        except ManualBootRequired:
            while True:
                self.prompt("Paleisk VM Fusion lange ir spausk Enter… ")
                if self.connection.reopen()["powered_on"]:
                    break
        self.connection.wait_tools()
        if desktop:
            self.prompt("Fusion lange prisijunk prie AegisLab darbalaukio ir spausk Enter… ")
        self.login()
        self.booted = snapshot
        self.verify_restores()

    def login(self):
        self.connection.login(self.username, self.credential)
        base = guest_path(self.connection.environment("LOCALAPPDATA"))
        self.python = str(base / "Programs/Python/Python314-arm64/python.exe")
        if not self.connection.exists(self.python):
            raise ValueError("Prepared Windows ARM Python is absent")
        return base

    def verify_restores(self):
        """A reverted cycle is complete only once a fresh boot of the same snapshot shows its kit gone.

        Booting another snapshot proves nothing about this revert, so such a
        cycle stays pending until its own snapshot is booted again.
        """
        for cycle in sorted(self.root.glob("cycles/cycle-*")):
            if not (cycle / "reverted.json").is_file() or restore_verified(cycle):
                continue
            if read_json(cycle / "reverted.json").get("snapshot") != self.booted:
                continue
            record = read_json(cycle / "cycle.json")
            remaining = [p for p in (record["guest_root"], record["launcher"]) if p and self.connection.exists(p)]
            if remaining:
                raise ValueError("Work from an earlier cycle survived the restore: " + cycle.name)
            write_json(cycle / ("restored-" + uuid.uuid4().hex[:8] + ".json"), {
                "checked_at_utc": now(), "booted_snapshot": self.booted,
                "absent": [p for p in (record["guest_root"], record["launcher"]) if p], "vm_restore_verified": True})

    def abandon(self, snapshot):
        """Leave the VM off and reverted after a cancelled or failed step; nothing of it is kept."""
        if getattr(self.connection, "pending", False):
            raise ValueError("A VM operation has an unknown outcome; restore the VM before continuing")
        if not self.connection.state()["powered_off"]:
            self.connection.shutdown()
        self.connection.revert_cold_snapshot(snapshot)
        self.booted = None

    def revert(self, cycle, snapshot):
        self.connection.shutdown()
        self.connection.revert_cold_snapshot(snapshot)
        self.booted = None
        write_json(cycle / "reverted.json", {"reverted_at_utc": now(), "snapshot": snapshot,
                                             "restore_proof": "checked at the next boot"})

    # --- one action in the guest ---------------------------------------------------
    def prepare(self, action, request, files, *, state, snapshot):
        token = uuid.uuid4().hex
        cycle = self.root / "cycles" / ("cycle-" + token)
        cycle.mkdir()
        kit = guest_path(self.connection.environment("LOCALAPPDATA")) / ("AegisResearch-" + token)
        elevated = action in guest_research_lab.ELEVATED
        launcher = (guest_path(self.connection.environment("USERPROFILE")) / "Desktop"
                    / ("Aegis-Research-" + token[:8] + ".cmd")) if elevated else None
        request = {**request, "action": action, "run_id": request.get("run_id") or "lab-" + token}
        write_json(cycle / "request.json", request)
        sources = {"src/" + name: self.source / name for name in SOURCES}
        sources["rules/control-marker.yar"] = self.source.parent / "rules" / "control-marker.yar"
        hashes = {name: digest(path) for name, path in {**sources, **files}.items()}
        # Written before anything reaches the guest, so a later boot can prove its absence.
        write_json(cycle / "cycle.json", {"schema": 1, "kind": "lab_cycle", "action": action, "state": state,
                                          "snapshot": snapshot, "guest_root": str(kit),
                                          "launcher": str(launcher) if launcher else None,
                                          "started_at_utc": now(), "files": hashes,
                                          "request_sha256": digest(cycle / "request.json")})
        return cycle, kit, launcher, request, {**sources, **files, "request.json": cycle / "request.json"}

    def upload(self, kit, uploads):
        for folder in sorted({PureWindowsPath(name).parent for name in uploads}, key=lambda p: len(p.parts)):
            self.connection.mkdir(str(kit / folder) if str(folder) != "." else str(kit))
        for name, path in uploads.items():
            self.connection.copy_to(path, str(kit / PureWindowsPath(name)))

    def execute(self, action, cycle, kit, launcher):
        output = kit / "report.json"
        failure = kit / "failure-report.json"
        arguments = windows_arguments(kit / "src" / "guest_research_lab.py", "--action", action,
                                      "--request", kit / "request.json", "--output", output)
        if launcher is None:
            code = self.connection.run(self.python, arguments, timeout=300)
            if not (self.connection.exists(str(output)) or self.connection.exists(str(failure))):
                raise ValueError("Guest check left no report (exit code " + str(code) + ")")
        else:
            script = ("Start-Process -FilePath '" + self.python.replace("'", "''") + "' -Verb RunAs -ArgumentList '"
                      + arguments.replace("'", "''") + "' -Wait")
            encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
            host_launcher = cycle / "launcher.cmd"
            host_launcher.write_bytes(("@echo off\r\npowershell.exe -NoLogo -NoProfile -EncodedCommand " + encoded
                                       + "\r\n").encode("ascii"))
            self.connection.copy_to(host_launcher, str(launcher))
            # Ordinary UAC stays on: the operator approves it in the VM's desktop session.
            self.connection.login(self.username, self.credential, interactive=True)
            self.connection.run(POWERSHELL, "-NoLogo -NoProfile -EncodedCommand " + encoded, wait=False)
            self.progress("VM lange patvirtink Windows UAC užklausą. Jei jos nėra, darbalaukyje paleisk "
                          + launcher.name + ".")
        deadline = time.monotonic() + self.wait_limit
        while not (self.connection.exists(str(output)) or self.connection.exists(str(failure))):
            if time.monotonic() >= deadline:
                raise TimeoutError("No guest report arrived; the VM will be restored without a result")
            time.sleep(self.poll_seconds)
        if self.connection.exists(str(failure)):
            self.connection.copy_from(str(failure), cycle / "failure.json")
            value = read_json(cycle / "failure.json")
            raise ValueError("Guest check failed: " + str(value.get("error_type")) + ": " + str(value.get("message")))
        self.connection.copy_from(str(output), cycle / "report.json")
        report = read_json(cycle / "report.json")
        if report.get("run_id") != read_json(cycle / "request.json")["run_id"]:
            raise ValueError("Guest report belongs to another request")
        return report

    def cycle(self, action, request, files=None, *, state=None, snapshot=None, fetch=None, check=None):
        """Run one action from a cold state and restore; returns (cycle folder, report).

        `fetch` copies further evidence; `check` validates the report. A cycle
        is finished only after both succeed; otherwise its error is recorded.
        """
        state = state or STATE_OF.get(action)
        snapshot = snapshot or self.state(state)["snapshot"]
        files = files or {}
        try:
            self.boot(snapshot, desktop=action in guest_research_lab.ELEVATED)
            cycle, kit, launcher, request, uploads = self.prepare(action, request, files, state=state,
                                                                  snapshot=snapshot)
        except BaseException as exc:
            # A cancelled or failed boot or preparation never leaves the VM running,
            # even when the error record itself cannot be written.
            try:
                failed = [c for c in self.root.glob("cycles/cycle-*") if (c / "cycle.json").is_file()
                          and not (c / "reverted.json").exists() and not (c / "finished.json").exists()
                          and not list(c.glob("error-*.json"))
                          and read_json(c / "cycle.json").get("snapshot") == snapshot]
                for folder in failed:
                    write_json(folder / ("error-" + uuid.uuid4().hex[:8] + ".json"),
                               {"at_utc": now(), "error_type": type(exc).__name__, "message": str(exc)[:2000]})
            finally:
                self.abandon(snapshot)
            raise
        try:
            self.upload(kit, uploads)
            report = self.execute(action, cycle, kit, launcher)
            if fetch:
                fetch(cycle, kit, report)
            if check:
                check(cycle, report)
            write_json(cycle / "finished.json", {"finished_at_utc": now(), "report_sha256": digest(cycle / "report.json")})
            return cycle, report
        except Exception as exc:
            write_json(cycle / ("error-" + uuid.uuid4().hex[:8] + ".json"),
                       {"at_utc": now(), "error_type": type(exc).__name__, "message": str(exc)[:2000]})
            raise
        finally:
            if not getattr(self.connection, "pending", False):
                self.revert(cycle, snapshot)

    # --- states ------------------------------------------------------------------
    def register_a(self, snapshot):
        snapshot_name(snapshot)
        if (self.root / "states" / "A.json").exists():
            raise ValueError("State A is already registered")
        cycle, report = self.cycle("probe", {}, state="A", snapshot=snapshot,
                                   check=lambda _, value: self._check_probe(value, "A"))
        return self._register("A", snapshot, cycle, report, "Existing prepared baseline; real-time protection on")

    def make_f(self, attempts=3):
        if (self.root / "states" / "F.json").exists():
            raise ValueError("State F is already registered")
        base = self.state("A")
        try:
            self.boot(base["snapshot"], desktop=True)
            return self._make_f(base, attempts)
        except BaseException as exc:
            # Until the F snapshot exists, a cancel or failure discards the operator's changes.
            if not (self.root / "states" / "F.json").exists():
                try:
                    for cycle in self.root.glob("cycles/cycle-*"):
                        if not (cycle / "cycle.json").is_file():
                            continue  # a preparation that failed before its record was written
                        record = read_json(cycle / "cycle.json")
                        if (record["action"] == "probe" and record["state"] == "F"
                                and not (cycle / "finished.json").exists() and not list(cycle.glob("error-*.json"))):
                            write_json(cycle / ("error-" + uuid.uuid4().hex[:8] + ".json"),
                                       {"at_utc": now(), "error_type": type(exc).__name__,
                                        "message": str(exc)[:2000]})
                finally:
                    # The restore must not depend on the error record being written.
                    self.abandon(base["snapshot"])
            raise

    def _make_f(self, base, attempts):
        self.prompt(STATE_F_STEPS + "\n")
        for attempt in range(1, attempts + 1):
            # Each probe's kit is removed before the snapshot or the next attempt.
            cycle, kit, _, _, uploads = self.prepare("probe", {}, {}, state="F", snapshot=base["snapshot"])
            self.upload(kit, uploads)
            report = self.execute("probe", cycle, kit, None)
            script = "Remove-Item -LiteralPath '" + str(kit).replace("'", "''") + "' -Recurse -Force"
            encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
            self.connection.run(POWERSHELL, "-NoLogo -NoProfile -NonInteractive -EncodedCommand " + encoded)
            if self.connection.exists(str(kit)):
                raise ValueError("The probe kit could not be removed before the snapshot")
            try:
                self._check_probe(report, "F")
                break
            except ValueError as exc:
                write_json(cycle / ("error-" + uuid.uuid4().hex[:8] + ".json"),
                           {"at_utc": now(), "error_type": "ValueError", "message": str(exc)[:2000]})
                if attempt == attempts:
                    raise
                self.prompt("Realaus laiko apsauga dar įjungta. Patikrink žingsnius ir spausk Enter… ")
        name = "Aegis-StateF-" + secrets.token_hex(8)
        self.connection.shutdown()
        self.connection.create_cold_snapshot(name)
        self.booted = None
        write_json(cycle / "finished.json", {"finished_at_utc": now(), "report_sha256": digest(cycle / "report.json"),
                                             "snapshot_created": name, "probe_kit_removed": True})
        return self._register("F", name, cycle, report,
                              "Operator turned off Tamper Protection and real-time protection by policy")

    @staticmethod
    def _check_probe(report, state):
        defender = report.get("defender") or {}
        if report.get("kind") != "lab_probe" or report.get("state") != state:
            raise ValueError("The guest is not in state " + state + ": " + json.dumps(defender))
        # An unreadable inventory is not evidence of a disconnected network.
        if report.get("inventory_error") is not None or report.get("active_network_adapters") != []:
            raise ValueError("Network adapters must be read and found disconnected")

    # --- checks ------------------------------------------------------------------
    def probe(self, state):
        return self.cycle("probe", {}, state=state)

    def eicar_realtime(self, limit=60):
        return self.cycle("eicar_realtime", {"limit_seconds": limit},
                          check=lambda _, value: self._expect(value, "eicar_realtime_control"))

    def eicar_custom(self):
        return self.cycle("eicar_custom", {}, check=lambda _, value: self._expect(value, "eicar_custom_control"))

    @staticmethod
    def _expect(report, kind):
        if report.get("kind") != kind:
            raise ValueError("Unexpected report kind: " + str(report.get("kind")))

    def _sample(self, sample_id, path, suffix):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", str(sample_id)):
            raise ValueError("Invalid sample id")
        path = aegis.external_path(path)
        if path.is_symlink() or not path.is_file():
            raise ValueError("Expected a regular file: " + str(path))
        return {"sample_id": sample_id, "sha256": digest(path), "path": "files/" + sample_id + suffix}, path

    def av(self, sample_id, path, wait_seconds):
        if type(wait_seconds) not in (int, float) or wait_seconds <= 0:
            raise ValueError("The calibrated waiting period must be positive")
        item, source = self._sample(sample_id, path, ".bin")
        def check(_, report):
            scan_bridge.validate_av(report)
            if (report["sha256"] != item["sha256"]
                    or report["code_sha256"] != digest(self.source / "guest_research_scan.py")):
                raise ValueError("AV report does not match the file or scanner that was sent")
        return self.cycle("av", {"kind": "av_check", "wait_seconds": wait_seconds, "files": [item]},
                          {item["path"]: source}, check=check)

    def yara(self, samples, ruleset):
        ruleset = aegis.external_path(ruleset)
        items, files = [], {"frozen.yar": ruleset}
        for sample_id, path in samples:
            item, source = self._sample(sample_id, path, ".bin")
            items.append(item)
            files[item["path"]] = source
        request = {"kind": "yara_check", "files": items, "ruleset_sha256": digest(ruleset),
                   "yara": str(PureWindowsPath(self.tools["guest_root"]) / "yara64.exe"),
                   "yara_sha256": self.tools["yara_sha256"]}
        def check(_, report):
            scan_bridge.validate_yara(report)
            if (report["ruleset_sha256"] != request["ruleset_sha256"] or report["yara_sha256"] != request["yara_sha256"]
                    or [f["sha256"] for f in report["files"]] != [i["sha256"] for i in items]):
                raise ValueError("YARA report does not match what was sent")
        return self.cycle("yara", request, files, check=check)

    # --- requests built by run_guard ---------------------------------------------
    @staticmethod
    def _request_files(request, sources):
        """Upload exactly the request's files; each source must hash to the request's SHA-256."""
        files = {}
        for item in request["files"]:
            source = aegis.external_path(sources[item["sample_id"]])
            if source.is_symlink() or not source.is_file() or digest(source) != item["sha256"]:
                raise ValueError("A requested file is missing or differs from the plan: " + item["sample_id"])
            if item["path"] != "files/" + item["sample_id"] + ".bin":
                raise ValueError("Unexpected guest path in the request: " + item["sample_id"])
            files[item["path"]] = source
        return files

    def av_request(self, request, sources):
        """Run one guarded AV request (`run_guard.prepare_av_request`) unchanged; its run ID is kept."""
        if request.get("kind") != "av_check" or len(request.get("files", [])) != 1 or not request.get("run_id"):
            raise ValueError("Expected one guarded AV request")
        (item,) = request["files"]

        def check(_, report):
            scan_bridge.validate_av(report)
            if (report["run_id"] != request["run_id"] or report["sample_id"] != item["sample_id"]
                    or report["sha256"] != item["sha256"] or report["wait_seconds"] != request["wait_seconds"]
                    or report["code_sha256"] != digest(self.source / "guest_research_scan.py")):
                raise ValueError("AV report does not match its guarded request")
        return self.cycle("av", request, self._request_files(request, sources), check=check)

    def yara_request(self, request, sources, ruleset):
        """Run one guarded YARA request (`run_guard.prepare_yara_request`) with its frozen rule set."""
        ruleset = aegis.external_path(ruleset)
        if request.get("kind") != "yara_check" or digest(ruleset) != request.get("ruleset_sha256"):
            raise ValueError("Expected a guarded YARA request with its frozen rule set")
        if request.get("yara_sha256") != self.tools["yara_sha256"]:
            raise ValueError("The request names another YARA executable than the prepared one")
        files = {**self._request_files(request, sources), "frozen.yar": ruleset}
        guest = {**request, "yara": str(PureWindowsPath(self.tools["guest_root"]) / "yara64.exe")}

        def check(_, report):
            scan_bridge.validate_yara(report)
            if (report["run_id"] != request["run_id"] or report["ruleset_sha256"] != request["ruleset_sha256"]
                    or report["yara_sha256"] != request["yara_sha256"]
                    or [(f["sample_id"], f["sha256"]) for f in report["files"]]
                    != [(f["sample_id"], f["sha256"]) for f in request["files"]]):
                raise ValueError("YARA report does not match its guarded request")
        return self.cycle("yara", guest, files, check=check)

    def candidate(self, rule_text, files, sources, *, run_id):
        """Compile check and calibration matches of one candidate rule (state F)."""
        request = {"kind": "candidate_check", "run_id": run_id, "rule_text": rule_text, "files": files,
                   "yara": str(PureWindowsPath(self.tools["guest_root"]) / "yara64.exe"),
                   "yara_sha256": self.tools["yara_sha256"]}

        def check(_, report):
            results = report.get("results") if report.get("kind") == "candidate_check" else None
            if (not isinstance(results, dict) or results.get("rule_sha256")
                    != hashlib.sha256(rule_text.encode("utf-8")).hexdigest()):
                raise ValueError("Candidate results do not belong to this rule text")
        return self.cycle("candidate", request, self._request_files(request, sources), check=check)

    def functionality(self, card_path, runs):
        """`runs`: [(sample_id, host path, guest work directory)] judged by one card."""
        card = json.loads(aegis.external_path(card_path).read_text(encoding="utf-8"))
        card_hash = functionality_card.card_sha256(card)
        if not runs:
            raise ValueError("A functionality check needs at least one file")
        items, files = [], {}
        for sample_id, path, workdir in runs:
            item, source = self._sample(sample_id, path, ".exe")
            items.append({**item, "workdir": str(guest_path(workdir))})
            files[item["path"]] = source
        request = {"card": card, "card_sha256": card_hash, "files": items,
                   "procmon": str(PureWindowsPath(self.tools["guest_root"]) / "Procmon64a.exe"),
                   "procmon_sha256": self.tools["procmon_sha256"]}

        def fetch(cycle, kit, report):
            if report.get("csv"):
                target = cycle / "process-monitor.csv"
                self.connection.copy_from(str(kit / "work" / report["csv"]), target, timeout=180)
                if target.stat().st_size > CSV_LIMIT or digest(target) != report["monitor"]["csv_sha256"]:
                    raise ValueError("Process Monitor export changed in transport")

        results = []
        cycle, _ = self.cycle("functionality", request, files, fetch=fetch,
                              check=lambda folder, report: results.extend(self.evaluate(folder, card, items, report)))
        return cycle, results

    @staticmethod
    def evaluate(cycle, card, items, report):
        if report.get("kind") != "functionality_runs" or [r["sample_id"] for r in report["runs"]] != [
                i["sample_id"] for i in items]:
            raise ValueError("Functionality report does not match the request")
        csv_path = cycle / "process-monitor.csv"
        rows = functionality_card.read_monitor_csv(csv_path) if csv_path.is_file() else []
        monitor_sha = digest(csv_path) if csv_path.is_file() else None
        results = []
        for item, entry in zip(items, report["runs"]):
            record, details = functionality_card.evaluate(card, entry["run"], rows, item["sha256"],
                                                          monitor_sha256=monitor_sha, synthetic=True)
            for name, value in (("record", record), ("details", details), ("run", entry["run"])):
                write_json(cycle / (name + "-" + item["sample_id"] + ".json"), value)
            results.append({"sample_id": item["sample_id"], "status": record["status"], "reasons": details["reasons"]})
        return results

    def close(self):
        self.credential = None
        self.connection.close()


def summary(cycle, report):
    keys = ("kind", "state", "status", "reason", "detected_by", "seconds_to_record", "source_verdict", "records",
            "defender", "windows", "vmware_tools", "realtime_policy", "reasons", "files")
    return {"cycle": str(cycle), **{k: report[k] for k in keys if isinstance(report, dict) and k in report}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="external laboratory workspace (panel folder)")
    parser.add_argument("--lab-status", required=True, help="lab-status.json with the VM paths and user name")
    parser.add_argument("--tool-kit", required=True, help="pending.json of the prepared tool kit")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("register-a").add_argument("--snapshot", required=True)
    commands.add_parser("make-f")
    commands.add_parser("probe").add_argument("--state", choices=["A", "F"], required=True)
    commands.add_parser("eicar-realtime").add_argument("--limit", type=float, default=60)
    commands.add_parser("eicar-custom")
    command = commands.add_parser("av")
    command.add_argument("--sample-id", required=True)
    command.add_argument("--file", required=True)
    command.add_argument("--wait", type=float, required=True)
    command = commands.add_parser("yara")
    command.add_argument("--sample", action="append", required=True, help="ID=PATH")
    command.add_argument("--ruleset", required=True)
    command = commands.add_parser("functionality")
    command.add_argument("--job", required=True, help='{"card": path, "runs": [{"sample_id","path","workdir"}]}')
    args = parser.parse_args(argv)
    config = read_json(aegis.external_path(args.lab_status))
    pending = read_json(aegis.external_path(args.tool_kit))
    tools = {"guest_root": pending["guest_root"], "yara_sha256": pending["files"]["yara64.exe"],
             "procmon_sha256": pending["files"]["Procmon64a.exe"]}
    bundle = Path(config["vm_bundle"])
    vmx = bundle / (bundle.stem + ".vmx")
    if not vmx.is_file():
        import control_panel
        control_panel.mount_vm_storage(config)
    from fusion_guest_ops import FusionGuestOps
    connection = FusionGuestOps(timeout=20)
    connection.open(vmx, getpass.getpass("VM šifravimo slaptažodis: "))
    lab = ResearchLab(connection, args.workspace, username=config.get("guest_username", "AegisLab"),
                      credential=getpass.getpass("AegisLab paskyros slaptažodis: "), tools=tools)
    try:
        if args.command == "register-a":
            print(json.dumps(lab.register_a(args.snapshot), indent=2, ensure_ascii=False))
            return 0
        if args.command == "make-f":
            print(json.dumps(lab.make_f(), indent=2, ensure_ascii=False))
            return 0
        if args.command == "probe":
            result = lab.probe(args.state)
        elif args.command == "eicar-realtime":
            result = lab.eicar_realtime(args.limit)
        elif args.command == "eicar-custom":
            result = lab.eicar_custom()
        elif args.command == "av":
            result = lab.av(args.sample_id, args.file, args.wait)
        elif args.command == "yara":
            result = lab.yara([tuple(value.split("=", 1)) for value in args.sample], args.ruleset)
        else:
            job = read_json(aegis.external_path(args.job))
            cycle, results = lab.functionality(job["card"], [(r["sample_id"], r["path"], r["workdir"])
                                                             for r in job["runs"]])
            print(json.dumps({"cycle": str(cycle), "results": results}, indent=2, ensure_ascii=False))
            return 0
        print(json.dumps(summary(*result), indent=2, ensure_ascii=False))
        return 0
    except (ValueError, OSError, TimeoutError) as exc:
        print("Laboratorijos patikra nepavyko: " + str(exc), file=sys.stderr)
        return 1
    finally:
        lab.close()


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
