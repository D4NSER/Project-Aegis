"""Guest-side laboratory controls for the evaluation protocol (stage 3).

Runs inside the Windows guest from a kit that the host prepared. Actions:

* probe          - Windows build, VMware Tools version, Defender state and the
                   real-time protection policy, active network adapters;
* eicar_realtime - state A: the official EICAR test text is written in the
                   guest only and never executed; the time until Defender
                   records it for that exact path calibrates the waiting
                   period, and the recorded source names are kept;
* eicar_custom   - state F: the same text stays on disk with real-time
                   protection off, so a positive answer can only come from the
                   separate custom scan; its recorded source names are kept;
* av / yara      - the protocol checks of `guest_research_scan` on files the
                   host supplied;
* functionality  - files are launched under Process Monitor exactly as their
                   functionality card says; the run records and the CSV export
                   go back to the host, which applies the card evaluator.

Nothing here changes protection, network or license settings. A failed
action leaves a failure record instead of a report.
"""
import argparse
import base64
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time
import uuid

import guest_research_scan as scan

# The official harmless 68-byte EICAR test text; written only inside the guest.
EICAR = base64.b64decode("WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=")
ACTIONS = ("probe", "eicar_realtime", "eicar_custom", "av", "yara", "functionality")
ELEVATED = {"eicar_realtime", "eicar_custom", "av", "functionality"}
POLICY_KEY = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class LabSystem(scan.WindowsSystem):
    """Windows access for the laboratory controls; tests supply a fake."""

    def elevated(self):
        return bool(ctypes.windll.shell32.IsUserAnAdmin())

    def monotonic(self):
        return time.monotonic()

    def inventory(self):
        ps = self.scanners.powershell_json
        windows = ps("Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' | Select-Object "
                     "ProductName,EditionID,DisplayVersion,CurrentBuild,UBR | ConvertTo-Json -Compress")
        tools = ps("$p=Join-Path $env:ProgramFiles 'VMware\\VMware Tools\\vmtoolsd.exe'; [pscustomobject]@{"
                   "present=(Test-Path -LiteralPath $p);version=$(if(Test-Path -LiteralPath $p){"
                   "(Get-Item -LiteralPath $p).VersionInfo.ProductVersion}else{$null})} | ConvertTo-Json -Compress")
        policy = ps("$k='" + POLICY_KEY + "'; [pscustomobject]@{DisableRealtimeMonitoring=$(if(Test-Path $k){"
                    "(Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).DisableRealtimeMonitoring}else{$null})}"
                    " | ConvertTo-Json -Compress")
        adapters = ps("ConvertTo-Json -InputObject @(Get-NetAdapter | Where-Object Status -eq 'Up' | "
                      "Select-Object -ExpandProperty Name) -Compress") or []
        return {"windows": windows, "vmware_tools": tools, "realtime_policy": policy,
                "active_network_adapters": [adapters] if isinstance(adapters, str) else adapters}

    def defender_details(self):
        """Settings that decide whether real-time protection scans a file and when (read only)."""
        ps = self.scanners.powershell_json
        status = ps("Get-MpComputerStatus | Select-Object AMRunningMode,OnAccessProtectionEnabled,"
                    "IoavProtectionEnabled,BehaviorMonitorEnabled,RealTimeProtectionEnabled | ConvertTo-Json -Compress")
        prefs = ps("$p=Get-MpPreference; [pscustomobject]@{RealTimeScanDirection=$p.RealTimeScanDirection;"
                   "DisableRealtimeMonitoring=$p.DisableRealtimeMonitoring;DisableIOAVProtection=$p.DisableIOAVProtection;"
                   "DisableBehaviorMonitoring=$p.DisableBehaviorMonitoring;DisableScanOnRealtimeEnable="
                   "$p.DisableScanOnRealtimeEnable;EnableControlledFolderAccess=$p.EnableControlledFolderAccess;"
                   "ExclusionPathCount=@($p.ExclusionPath).Where({$_}).Count;ExclusionExtensionCount="
                   "@($p.ExclusionExtension).Where({$_}).Count;ExclusionProcessCount=@($p.ExclusionProcess).Where({$_})"
                   ".Count} | ConvertTo-Json -Compress")
        return {"status": status, "preferences": prefs}

    def read_back(self, path):
        """Open and read a file, as a program would before using it."""
        try:
            Path(path).read_bytes()
            return None
        except OSError as exc:
            return type(exc).__name__

    def copy_file(self, source, target):
        try:
            Path(target).write_bytes(Path(source).read_bytes())
            return None
        except OSError as exc:
            return type(exc).__name__

    def write_eicar(self, path):
        try:
            with Path(path).open("xb") as stream:
                stream.write(EICAR)
                stream.flush()
                os.fsync(stream.fileno())
            return None
        except OSError as exc:
            return type(exc).__name__

    def license_accepted(self):
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Sysinternals\Process Monitor") as key:
                return winreg.QueryValueEx(key, "EulaAccepted")[0] == 1
        except OSError:
            return False

    def monitor_running(self):
        value = self.scanners.powershell_json(
            "ConvertTo-Json -InputObject @(Get-Process -ErrorAction SilentlyContinue | Where-Object "
            "{$_.ProcessName -match '^Procmon(64a|64)?$'} | Select-Object -ExpandProperty Id) -Compress")
        return bool(value)

    def start_monitor(self, procmon, trace):
        self._monitor = subprocess.Popen([str(procmon), "/Quiet", "/Minimized", "/BackingFile", str(trace)])

    def stop_monitor(self, procmon):
        result = self.run([procmon, "/Terminate", "/Quiet"], 20)
        self._monitor.wait(timeout=15)
        return result["exit_code"]

    def export_monitor(self, procmon, trace, csv_path):
        return self.run([procmon, "/OpenLog", trace, "/SaveAs", csv_path, "/Quiet"], 60)["exit_code"]

    def launch(self, arguments, timeout):
        """One process run: outcome fields of the functionality run record."""
        started = time.monotonic()
        try:
            process = subprocess.Popen([str(a) for a in arguments], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, errors="replace")
        except OSError as exc:
            return {"launch": "FAILED_TO_START", "pid": None, "exit_code": None, "timed_out": False,
                    "elapsed_seconds": None, "stdout": None, "stderr": None,
                    "technical_error": "NOT_STARTED:" + type(exc).__name__}
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            stdout, stderr = process.communicate(timeout=10)
        elapsed = time.monotonic() - started
        # A killed process has no exit code of its own.
        return {"launch": "STARTED", "pid": process.pid, "exit_code": None if timed_out else process.returncode,
                "timed_out": timed_out, "elapsed_seconds": round(elapsed, 3), "stdout": stdout[:8192],
                "stderr": stderr[:8192], "technical_error": None}


def probe(system):
    state, error = scan._state(system)
    value = {"schema": 1, "kind": "lab_probe", "observed_at_utc": system.now(), "defender": state,
             "defender_error": error, "elevated": system.elevated()}
    try:
        value.update(system.inventory())
        value["inventory_error"] = None
    except Exception as exc:  # An unreadable field stays visibly unknown.
        value["inventory_error"] = type(exc).__name__
    value["state"] = "A" if scan.state_matches(state, "A") else "F" if scan.state_matches(state, "F") else None
    return value


def _poll(system, target, since, limit, step):
    """Look up records for `target` until one appears or `limit` seconds pass."""
    start = system.monotonic()
    while True:
        lookup = scan._lookup(system, target, since)
        elapsed = system.monotonic() - start
        if lookup["detected"] or elapsed >= limit:
            return lookup, (round(elapsed, 3) if lookup["detected"] else None)
        system.sleep(step)


def _sources(lookup):
    return {"events": [{"id": e.get("id"), "source": e.get("source"), "path": e.get("path"), "time": e.get("time")}
                       for e in lookup.get("events", [])],
            "threats": [{"DetectionSourceTypeID": t.get("DetectionSourceTypeID"),
                         "InitialDetectionTime": t.get("InitialDetectionTime"),
                         "Resources": t.get("Resources")} for t in lookup.get("threats", [])]}


def _details(system):
    try:
        return system.defender_details()
    except Exception as exc:  # Diagnostics only; an unreadable setting stays visible as an error.
        return {"error": type(exc).__name__}


def _poll_all(system, targets, since, limit, step):
    """Look up records for any of `targets` until one appears or `limit` seconds pass."""
    start = system.monotonic()
    while True:
        lookups = [scan._lookup(system, t, since) for t in targets]
        detected = [l for l in lookups if l["detected"]]
        elapsed = system.monotonic() - start
        if detected or elapsed >= limit:
            merged = {"known": all(l["known"] for l in lookups), "detected": bool(detected),
                      "events": [e for l in lookups for e in l["events"]],
                      "threats": [t for l in lookups for t in l["threats"]]}
            return merged, (round(elapsed, 3) if detected else None)
        system.sleep(step)


def eicar_realtime(system, work, *, limit=60, step=0.5):
    """State A: which file action makes Defender record the EICAR text, how fast, under which source.

    The text is first written; if nothing is recorded within a third of the
    limit it is read back, then copied to a second name. The first action
    followed by a record is the trigger. The AV check opens each file once, so
    a record after the write or the read calibrates its waiting period.
    """
    before, error = scan._state(system)
    token = uuid.uuid4().hex[:8]
    target = Path(work) / ("eicar-realtime-" + token + ".txt")
    copy = Path(work) / ("eicar-realtime-" + token + "-copy.txt")
    started = system.now()
    report = {"schema": 1, "kind": "eicar_realtime_control", "expected_state": "A", "target": str(target),
              "defender_before": before, "defender_details": _details(system), "started_at_utc": started,
              "limit_seconds": limit}
    if not scan.state_matches(before, "A"):
        report.update(status="ERROR", reason="STATE_MISMATCH" if before else "STATE_READ_FAILED:" + str(error))
        return report
    phase_limit = limit / 3
    actions = (("write", lambda: system.write_eicar(target), [target]),
               ("read", lambda: system.read_back(target), [target]),
               ("copy", lambda: system.copy_file(target, copy), [target, copy]))
    phases, lookup, seconds, trigger = [], None, None, None
    for name, action, targets in actions:
        if name != "write" and not target.is_file():
            phases.append({"action": name, "skipped": "FILE_GONE"})
            break
        at = system.now()
        phases.append({"action": name, "at_utc": at, "error": action()})
        lookup, seconds = _poll_all(system, targets, started, phase_limit, step)
        phases[-1]["detected"] = lookup["detected"]
        if lookup["detected"] or not lookup["known"]:
            trigger = name if lookup["detected"] else None
            break
    after, _ = scan._state(system)
    verdict = scan.source_check(lookup, "REALTIME") if lookup and lookup["detected"] else None
    stable = scan.state_matches(after, "A") and scan.versions_stable(before, after)
    report.update(defender_after=after, phases=phases, trigger=trigger, write_error=phases[0]["error"],
                  lookup_known=bool(lookup and lookup["known"]), detected=bool(lookup and lookup["detected"]),
                  seconds_to_record=seconds, records=_sources(lookup or {}), source_verdict=verdict,
                  exists_after=target.is_file(), copy_exists_after=copy.is_file(), finished_at_utc=system.now())
    if not stable or not report["lookup_known"]:
        report.update(status="INCONCLUSIVE", reason="TOOL_STATE_CHANGED" if not stable else "HISTORY_UNREADABLE")
    elif not report["detected"]:
        report.update(status="NOT_DETECTED", reason="NO_RECORD_AFTER_WRITE_READ_OR_COPY")
    else:
        report.update(status="DETECTED", reason="SOURCE_" + verdict + "_AFTER_" + trigger.upper())
    return report


def eicar_custom(system, work, *, settle=5, limit=30, step=1, scan_timeout=60):
    """State F: a positive answer can come only from the separate custom scan."""
    before, error = scan._state(system)
    target = Path(work) / ("eicar-custom-" + uuid.uuid4().hex[:8] + ".txt")
    started = system.now()
    report = {"schema": 1, "kind": "eicar_custom_control", "expected_state": "F", "target": str(target),
              "defender_before": before, "started_at_utc": started}
    if not scan.state_matches(before, "F"):
        report.update(status="ERROR", reason="STATE_MISMATCH" if before else "STATE_READ_FAILED:" + str(error))
        return report
    report["write_error"] = system.write_eicar(target)
    system.sleep(settle)
    present = target.is_file() and sha256(target) == hashlib.sha256(EICAR).hexdigest()
    early = scan._lookup(system, target, started)
    report.update(present_before_scan=present, realtime_records=_sources(early), realtime_known=early["known"])
    if not present or early["detected"] or not early["known"]:
        report.update(status="INCONCLUSIVE", reason="NOT_PRESENT_FOR_CUSTOM_SCAN" if not present or early["detected"]
                      else "HISTORY_UNREADABLE", defender_after=scan._state(system)[0], finished_at_utc=system.now())
        return report
    scan_started = system.now()
    try:
        result = system.run([system.defender_program(), "-Scan", "-ScanType", "3", "-File", target], scan_timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        report.update(status="ERROR", reason="CUSTOM_SCAN_FAILED:" + type(exc).__name__,
                      defender_after=scan._state(system)[0], finished_at_utc=system.now())
        return report
    lookup, seconds = _poll(system, target, scan_started, limit, step)
    after, _ = scan._state(system)
    verdict = scan.source_check(lookup, "CUSTOM_SCAN") if lookup["detected"] else None
    stable = scan.state_matches(after, "F") and scan.versions_stable(before, after)
    report.update(custom_scan={"started_at_utc": scan_started, **result, "exit_code_use": "diagnostic only"},
                  defender_after=after, lookup_known=lookup["known"], detected=lookup["detected"],
                  seconds_to_record=seconds, records=_sources(lookup), source_verdict=verdict,
                  exists_after=target.is_file(), finished_at_utc=system.now())
    if not stable or not lookup["known"]:
        report.update(status="INCONCLUSIVE", reason="TOOL_STATE_CHANGED" if not stable else "HISTORY_UNREADABLE")
    elif not lookup["detected"]:
        report.update(status="NOT_DETECTED", reason="NO_RECORD_AFTER_CUSTOM_SCAN")
    else:
        report.update(status="DETECTED", reason="SOURCE_" + verdict)
    return report


def _pinned(path, expected, label):
    if not Path(path).is_file() or sha256(path) != expected:
        raise ValueError(label + " does not match its pinned SHA-256")
    return Path(path)


def functionality(system, card, runs, *, procmon, procmon_sha256, work):
    """Run each file once under one Process Monitor trace, exactly as the card says.

    `runs`: [{"sample_id", "path", "sha256", "workdir"}]. Returns the run
    records (fields of `functionality_card.RUN_FIELDS`) and the export name.
    """
    procmon = _pinned(procmon, procmon_sha256, "Process Monitor")
    if not system.license_accepted():
        raise ValueError("The operator has not accepted the Process Monitor license")
    if system.monitor_running():
        raise ValueError("Close the running Process Monitor before this check")
    work = Path(work)
    trace, csv_path = work / "process-monitor.pml", work / "process-monitor.csv"
    prepared = []
    for item in runs:
        _pinned(item["path"], item["sha256"], "Sample " + item["sample_id"])
        workdir = Path(item["workdir"])
        if workdir.exists():
            raise ValueError("A run's work directory must be new: " + item["sample_id"])
        workdir.mkdir(parents=True)
        prepared.append((item, workdir, uuid.uuid4().hex))
    records = []
    system.start_monitor(procmon, trace)
    stopped = None
    try:
        system.sleep(1.5)
        for item, workdir, token in prepared:
            arguments = [a.replace("{workdir}", str(workdir)).replace("{token}", token)
                         for a in card["input"]["arguments"]]
            result = system.launch([item["path"], *arguments], card["time_limit_seconds"])
            files = {}
            for expected in card["expected"]["files"]:
                owned = workdir.joinpath(*expected["path"].split("/"))
                files[expected["path"]] = sha256(owned) if owned.is_file() else None
            records.append({"sample_id": item["sample_id"], "run": {
                "launch": result["launch"], "sample_sha256": item["sha256"], "arguments": arguments,
                "pid": result["pid"], "exit_code": result["exit_code"], "timed_out": result["timed_out"],
                "elapsed_seconds": result["elapsed_seconds"], "stdout": result["stdout"], "stderr": result["stderr"],
                "workdir": str(workdir), "token": token, "files": files, "monitor": None,
                "technical_error": result["technical_error"]}})
        # Process Monitor drains driver events asynchronously.
        system.sleep(2)
    finally:
        stopped = system.stop_monitor(procmon)
    exported = system.export_monitor(procmon, trace, csv_path) if stopped == 0 and trace.is_file() else None
    captured = exported == 0 and csv_path.is_file()
    monitor = {"captured": captured, "complete": captured and stopped == 0,
               "csv_sha256": sha256(csv_path) if captured else None, "stop_exit_code": stopped,
               "export_exit_code": exported}
    for record in records:
        record["run"]["monitor"] = monitor
    return {"schema": 1, "kind": "functionality_runs", "card_id": card["card_id"], "runs": records,
            "monitor": monitor, "csv": csv_path.name if captured else None, "finished_at_utc": system.now()}


def write_new(path, value):
    scan.write_new(path, value)


def perform(system, action, request, root):
    """The report for one action; `root` is the kit folder holding the request."""
    if action in ELEVATED and not system.elevated():
        raise ValueError("Approve the ordinary Windows UAC prompt for this check")
    work = root / "work"
    work.mkdir(exist_ok=True)
    if action == "probe":
        value = probe(system)
    elif action == "eicar_realtime":
        value = eicar_realtime(system, work, limit=request.get("limit_seconds", 60))
    elif action == "eicar_custom":
        value = eicar_custom(system, work)
    elif action == "av":
        (item,) = request["files"]
        value = scan.av_check(system, root / item["path"], item["sha256"], wait_seconds=request["wait_seconds"],
                              run_id=request["run_id"], sample_id=item["sample_id"])
    elif action == "yara":
        files = [(f["sample_id"], root / f["path"], f["sha256"]) for f in request["files"]]
        value = scan.yara_check(system, files, yara=request["yara"], yara_sha256=request["yara_sha256"],
                                ruleset=root / "frozen.yar", ruleset_sha256=request["ruleset_sha256"],
                                run_id=request["run_id"])
    elif action == "functionality":
        runs = [{**f, "path": str(root / f["path"])} for f in request["files"]]
        value = functionality(system, request["card"], runs, procmon=request["procmon"],
                              procmon_sha256=request["procmon_sha256"], work=work)
    else:
        raise ValueError("Unknown laboratory action")
    code = root / "src" / ("guest_research_scan.py" if action in {"av", "yara"} else "guest_research_lab.py")
    value.update(platform=platform.system(), architecture=platform.machine(), code_sha256=sha256(code))
    if action not in {"av", "yara"}:
        value["run_id"] = request["run_id"]
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=ACTIONS, required=True)
    parser.add_argument("--request", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    output = Path(args.output)
    try:
        request = json.loads(Path(args.request).read_text(encoding="utf-8"))
        if request.get("action") != args.action:
            raise ValueError("Request is for another action")
        write_new(output, perform(LabSystem(), args.action, request, Path(args.request).parent))
    except Exception as exc:
        failure = output.with_name("failure-" + output.name)
        if not failure.exists():
            write_new(failure, {"kind": "lab_failure", "action": args.action, "error_type": type(exc).__name__,
                                "message": str(exc)[:2000],
                                "at_utc": datetime.now(timezone.utc).isoformat()})
        raise


if __name__ == "__main__":
    main()
