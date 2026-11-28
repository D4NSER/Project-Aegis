"""Guest-side detector checks of selected files, following the evaluation protocol.

Files are scanned, never executed. Each check returns one of the five
outcomes and never turns an incomplete check into a negative:

* AV (state A, real-time protection on): one file per run. The file is
  opened once (real-time protection scans on access); after the fixed
  waiting period, Defender's threat history and detection events are read
  for the file's unique path; a hit is DETECTED by REALTIME. Otherwise a
  separate custom scan runs; a hit is DETECTED by CUSTOM_SCAN. NOT_DETECTED
  needs a completed custom scan, unchanged bytes, readable history, protection
  on before and after and unchanged signatures. A timeout is ERROR. The scan's
  exit code is kept for diagnostics only.
* YARA (state F, real-time protection off): a frozen rule set, verified by
  hash, applied to each file; a timeout or unexpected output is ERROR.
* Candidate rules: compile check on an empty file, then per-file matches,
  returned as the results record that rule acceptance expects.

`WindowsSystem` talks to Defender and processes; tests supply a fake system.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import uuid

DETECTION_EVENTS = {1116, 1117}
DEFENDER_FIELDS = ("AMEngineVersion", "AMProductVersion", "AntivirusEnabled",
                   "RealTimeProtectionEnabled", "IsTamperProtected", "AntivirusSignatureVersion")
VERSION_FIELDS = ("AMProductVersion", "AMEngineVersion", "AntivirusSignatureVersion")
STATE_REALTIME = {"A": True, "F": False}
VALID = {"DETECTED", "NOT_DETECTED"}
# Which recorded detection sources support each label. Event `Detection Source Name`
# values and MpThreatDetection DetectionSourceTypeID (1 user, 2 system, 3 real-time)
# are to be confirmed against the laboratory's EICAR controls before the experiment.
SOURCES = {"REALTIME": {"events": {"real-time protection"}, "threats": {3}},
           "CUSTOM_SCAN": {"events": {"user", "system"}, "threats": {1, 2}}}
YARA_VERSION = re.compile(r"\d+\.\d+\.\d+")


def source_check(lookup, label):
    """'SUPPORTED', 'CONFLICT' or 'UNKNOWN': do all records' sources fit the label?"""
    allowed = SOURCES[label]
    verdicts = []
    for item in lookup.get("events", []):
        source = item.get("source")
        verdicts.append(None if not source else str(source).strip().casefold() in allowed["events"])
    for item in lookup.get("threats", []):
        source = item.get("DetectionSourceTypeID")
        verdicts.append(None if source is None else source in allowed["threats"])
    if not verdicts or False in verdicts:
        return "CONFLICT" if False in verdicts else "UNKNOWN"
    return "UNKNOWN" if None in verdicts else "SUPPORTED"
COMPILE_ERROR = re.compile(r".*candidate\.yar\(\d+\): (error|warning)", re.IGNORECASE)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _same_bytes(path, expected):
    """True/False for present files; None when the file vanished or cannot be read."""
    try:
        return sha256(path) == expected
    except OSError:
        return None


def _read_once(path):
    """Open and read a file once; the error name when access was refused (e.g. blocked by real-time protection)."""
    try:
        Path(path).read_bytes()
        return None
    except OSError as exc:
        return type(exc).__name__


def parse_time(value):
    """ISO time with a zone; .NET round-trip fractions are cut to microseconds."""
    text = str(value).replace("Z", "+00:00")
    head, dot, rest = text.partition(".")
    if dot:
        digits = re.match(r"\d*", rest).group(0)
        text = head + "." + digits[:6].ljust(6, "0") + rest[len(digits):]
    moment = datetime.fromisoformat(text)
    if moment.utcoffset() is None:
        raise ValueError("Time without a zone")
    return moment


def resource_path(value):
    """Defender resource text such as `file:_C:\\dir\\x.exe` -> `c:\\dir\\x.exe` (case-folded)."""
    text = str(value).strip()
    if ":_" in text:
        text = text.split(":_", 1)[1]
    return text.casefold()


class WindowsSystem:
    """Real Defender and process access inside the Windows guest."""

    def __init__(self):
        if os.name != "nt":
            raise ValueError("Detector checks run only in the Windows guest")
        import guest_scanners
        self.scanners = guest_scanners

    def defender_state(self):
        return self.scanners.defender_state()

    def threats(self):
        script = ("ConvertTo-Json -InputObject @(Get-MpThreatDetection | Select-Object ThreatID,Resources,"
                  "DetectionSourceTypeID,@{N='InitialDetectionTime';E={$_.InitialDetectionTime.ToUniversalTime()"
                  ".ToString('o')}}) -Depth 4 -Compress")
        value = self.scanners.powershell_json(script) or []
        return [value] if isinstance(value, dict) else value

    def events(self, since):
        # Structured fields from each event's EventData; the path is compared exactly on return.
        literal = "'" + parse_time(since).astimezone(timezone.utc).isoformat() + "'"
        script = ("$start=[datetime]::Parse(" + literal + ").ToLocalTime(); ConvertTo-Json -InputObject @("
                  "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';"
                  "Id=@(1116,1117);StartTime=$start} -ErrorAction SilentlyContinue | Select-Object -First 50 | "
                  "ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data)"
                  "{ $d[$n.Name]=[string]$n.'#text' }; [pscustomobject]@{id=$_.Id;record_id=$_.RecordId;"
                  "time=$_.TimeCreated.ToUniversalTime().ToString('o');path=$d['Path'];"
                  "source=$(if($d['Detection Source Name']){$d['Detection Source Name']}else{$d['Source Name']})} })"
                  " -Depth 3 -Compress")
        value = self.scanners.powershell_json(script) or []
        return [value] if isinstance(value, dict) else value

    def defender_program(self):
        return self.scanners.defender_program()

    def run(self, arguments, timeout):
        result = subprocess.run([str(a) for a in arguments], capture_output=True, text=True,
                                errors="replace", timeout=timeout)
        return {"exit_code": result.returncode, "stdout": result.stdout[:8192], "stderr": result.stderr[:8192]}

    def sleep(self, seconds):
        import time
        time.sleep(seconds)

    def now(self):
        return datetime.now(timezone.utc).isoformat()


def _state(system):
    try:
        value = system.defender_state()
        return {key: value.get(key) for key in DEFENDER_FIELDS}, None
    except Exception as exc:  # A failed read must never look like a valid state.
        return None, type(exc).__name__


def state_matches(state, expected):
    return (isinstance(state, dict) and state.get("AntivirusEnabled") is True
            and state.get("RealTimeProtectionEnabled") is STATE_REALTIME[expected])


def _state_after_f_startup(system):
    """Allow the Defender engine to initialize on a cold boot before checking state F."""
    state, error = _state(system)
    for _ in range(6):
        if (state is None or state.get("AntivirusEnabled") is not False
                or state.get("RealTimeProtectionEnabled") is not False
                or state.get("AMEngineVersion") != "0.0.0.0"
                or state.get("AntivirusSignatureVersion")):
            break
        system.sleep(5)
        state, error = _state(system)
    return state, error


def versions_stable(before, after):
    return (isinstance(before, dict) and isinstance(after, dict)
            and all(before.get(k) and before.get(k) == after.get(k) for k in VERSION_FIELDS))


def _lookup(system, path, since):
    """Detections of this exact path recorded at or after `since`.

    Threat-history resources and the Path field of events 1116/1117 must equal
    the file's path; an exact-path record without a readable time makes the
    lookup unknown rather than a detection or a negative.
    """
    text, start = str(path).casefold(), parse_time(since)
    try:
        threats, events, ambiguous = [], [], False
        for item in system.threats():
            if not any(resource_path(r) == text for r in (item.get("Resources") or [])):
                continue
            try:
                if parse_time(item.get("InitialDetectionTime")) >= start:
                    threats.append(item)
            except (TypeError, ValueError):
                ambiguous = True
        for item in system.events(since):
            paths = [resource_path(p) for p in str(item.get("path") or "").split(";") if p.strip()]
            if item.get("id") not in DETECTION_EVENTS or text not in paths:
                continue
            try:
                if parse_time(item.get("time")) >= start:
                    events.append(item)
            except (TypeError, ValueError):
                ambiguous = True
        if ambiguous and not (threats or events):
            return {"known": False, "threats": [], "events": [], "detected": False, "error": "UNDATED_RECORD"}
        return {"known": True, "threats": threats, "events": events, "detected": bool(threats or events),
                "sources": sorted({str(e.get("source")) for e in events if e.get("source")}
                                  | {"type-" + str(t.get("DetectionSourceTypeID")) for t in threats
                                     if t.get("DetectionSourceTypeID") is not None})}
    except Exception as exc:
        return {"known": False, "threats": [], "events": [], "detected": False, "error": type(exc).__name__}


def _split(lookup, moment):
    """(records dated before `moment`, records at or after it), each in lookup form."""
    cut = parse_time(moment)
    parts = []
    for before in (True, False):
        events = [e for e in lookup.get("events", []) if (parse_time(e.get("time")) < cut) is before]
        threats = [t for t in lookup.get("threats", [])
                   if (parse_time(t.get("InitialDetectionTime")) < cut) is before]
        parts.append({"known": lookup["known"], "threats": threats, "events": events,
                      "detected": bool(threats or events), **({"error": lookup["error"]} if "error" in lookup else {}),
                      "sources": sorted({str(e.get("source")) for e in events if e.get("source")}
                                        | {"type-" + str(t.get("DetectionSourceTypeID")) for t in threats
                                           if t.get("DetectionSourceTypeID") is not None})})
    return parts[0], parts[1]


def av_check(system, target, expected_sha256, *, wait_seconds, scan_timeout=60, run_id, sample_id):
    target = Path(target)
    started = system.now()
    before, state_error = _state(system)
    report = {"schema": 1, "kind": "av_check", "run_id": run_id, "scan_id": "av-" + uuid.uuid4().hex,
              "sample_id": sample_id, "sha256": expected_sha256, "expected_state": "A",
              "wait_seconds": wait_seconds, "started_at_utc": started, "defender_before": before,
              "access": None, "realtime": None, "custom_scan": None, "file_unchanged": None,
              "status": None, "detected_by": "", "reasons": []}

    def finish(status, *reasons, detected_by="", observed=None):
        after, error = observed if observed else _state(system)
        reasons = list(reasons)
        if error:
            reasons.append("STATE_READ_FAILED_AFTER:" + error)
        # A valid response needs the same tool versions and protection before and after.
        if status in VALID and not (versions_stable(before, after) and state_matches(after, "A")):
            reasons.append("TOOL_STATE_CHANGED_OR_UNKNOWN")
            status, detected_by = "INCONCLUSIVE", ""
        report.update(status=status, detected_by=detected_by, reasons=reasons, defender_after=after,
                      finished_at_utc=system.now())
        return report

    if not state_matches(before, "A"):
        return finish("ERROR", "STATE_MISMATCH" if before else "STATE_READ_FAILED:" + str(state_error))
    # Real-time protection here scans a file when it is opened, not when it is
    # written (laboratory EICAR control, 2026-11-28): the check opens the file
    # once, as a program using it would, and then waits the calibrated period.
    report["access"] = {"at_utc": system.now(), "error": _read_once(target)}
    system.sleep(wait_seconds)
    report["realtime"] = realtime = _lookup(system, target, started)
    if realtime["detected"]:
        verdict = source_check(realtime, "REALTIME")
        if verdict != "SUPPORTED":
            return finish("INCONCLUSIVE", "DETECTION_SOURCE_" + verdict)
        return finish("DETECTED", "REALTIME_DETECTION", detected_by="REALTIME")
    present = _same_bytes(target, expected_sha256) if target.is_file() else None
    if present is None:
        return finish("INCONCLUSIVE", "INPUT_MISSING_WITHOUT_DETECTION")
    if not present:
        return finish("INCONCLUSIVE", "INPUT_CHANGED_WITHOUT_DETECTION")
    scan_started = system.now()
    try:
        scan = system.run([system.defender_program(), "-Scan", "-ScanType", "3", "-File", target], scan_timeout)
    except subprocess.TimeoutExpired:
        report["custom_scan"] = {"timed_out": True}
        return finish("ERROR", "CUSTOM_SCAN_TIMEOUT")
    except OSError as exc:
        return finish("ERROR", "CUSTOM_SCAN_NOT_STARTED:" + type(exc).__name__)
    report["custom_scan"] = {"timed_out": False, "started_at_utc": scan_started, **scan,
                             "exit_code_use": "diagnostic only"}
    # One lookup from the check's start, split at the scan's start, so that a
    # real-time record written after the first lookup cannot fall between the
    # two windows and leave a negative.
    whole = _lookup(system, target, started)
    late, custom = _split(whole, scan_started)
    report["custom_scan"]["lookup"] = custom
    report["custom_scan"]["late_records"] = late
    if late["detected"]:
        return finish("INCONCLUSIVE", "DETECTION_RECORDED_AFTER_WAIT_BEFORE_SCAN")
    if custom["detected"]:
        if not realtime["known"]:
            # The earlier real-time lookup failed, so the flagging check cannot be named.
            return finish("INCONCLUSIVE", "DETECTION_SOURCE_UNKNOWN")
        verdict = source_check(custom, "CUSTOM_SCAN")
        if verdict != "SUPPORTED":
            return finish("INCONCLUSIVE", "DETECTION_SOURCE_" + verdict)
        return finish("DETECTED", "CUSTOM_SCAN_DETECTION", detected_by="CUSTOM_SCAN")
    observed = _state(system)
    unchanged = _same_bytes(target, expected_sha256) is True
    report["file_unchanged"] = unchanged
    failed = [name for name, ok in (
        ("CUSTOM_SCAN_NOT_COMPLETED", scan["exit_code"] == 0),
        ("FILE_CHANGED", unchanged),
        ("DETECTION_HISTORY_UNREADABLE", realtime["known"] and custom["known"]),
    ) if not ok]
    # The state that decided the outcome is the one reported.
    if failed:
        return finish("INCONCLUSIVE", *failed, observed=observed)
    return finish("NOT_DETECTED", "COMPLETE_NEGATIVE", observed=observed)


def _pinned(path, expected, label):
    path = Path(path)
    if not path.is_file() or sha256(path) != expected:
        raise ValueError(label + " does not match its pinned SHA-256")
    return path


def _yara_file(system, yara, rules, path, expected_sha256, timeout):
    """(status, matched rule names, reason) for one file; never a negative by default."""
    path = Path(path)
    if not path.is_file():
        return "NOT_RUN", [], "MISSING_INPUT"
    same = _same_bytes(path, expected_sha256)
    if same is None:
        return "ERROR", [], "INPUT_UNREADABLE"
    if not same:
        return "ERROR", [], "HASH_MISMATCH"
    try:
        result = system.run([yara, "-w", rules, path], timeout)
    except subprocess.TimeoutExpired:
        return "ERROR", [], "TIMEOUT"
    except OSError as exc:
        return "ERROR", [], "NOT_STARTED:" + type(exc).__name__
    if result["exit_code"] != 0:
        return "ERROR", [], "EXIT_" + str(result["exit_code"])
    names = []
    for line in result["stdout"].splitlines():
        if not line.strip():
            continue
        name, _, matched = line.partition(" ")
        if matched != str(path) or not name:
            return "ERROR", [], "UNEXPECTED_OUTPUT"
        names.append(name)
    if _same_bytes(path, expected_sha256) is not True:
        return "ERROR", [], "FILE_CHANGED_DURING_SCAN"
    return ("MATCHED" if names else "NOT_MATCHED"), sorted(names), None


def yara_check(system, files, *, yara, yara_sha256, ruleset, ruleset_sha256, timeout=30, run_id):
    """`files`: [(sample_id, path, sha256)]; the frozen rule set must match its freeze hash."""
    yara = _pinned(yara, yara_sha256, "YARA executable")
    ruleset = _pinned(ruleset, ruleset_sha256, "Frozen rule set")
    state, error = _state_after_f_startup(system)
    try:
        answer = system.run([yara, "--version"], 15)
        text = answer["stdout"].strip()
        # Only a successful query that prints a version counts.
        version = text if answer["exit_code"] == 0 and YARA_VERSION.fullmatch(text) else None
    except (subprocess.TimeoutExpired, OSError):
        version = None
    report = {"schema": 1, "kind": "yara_check", "run_id": run_id, "scan_id": "yara-" + uuid.uuid4().hex,
              "expected_state": "F", "defender_state": state, "yara_version": version,
              "yara_sha256": yara_sha256, "ruleset_sha256": ruleset_sha256,
              "started_at_utc": system.now(), "files": []}
    if state is None:
        blocked = "STATE_READ_FAILED:" + str(error)
    elif not state_matches(state, "F"):
        blocked = "STATE_MISMATCH"
    elif not version:
        blocked = "YARA_VERSION_UNKNOWN"
    else:
        blocked = None
    for sample_id, path, expected in files:
        if blocked:
            status, names, reason = "ERROR", [], blocked
        else:
            status, names, reason = _yara_file(system, yara, ruleset, path, expected, timeout)
        report["files"].append({"sample_id": sample_id, "sha256": expected, "status": status,
                                "rules": names, "reason": reason})
    report["finished_at_utc"] = system.now()
    return report


def candidate_check(system, rule_text, files, *, yara, yara_sha256, workdir, timeout=30):
    """The four-field results record for rule acceptance, plus its context."""
    yara = _pinned(yara, yara_sha256, "YARA executable")
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=False)
    rule_path, empty = workdir / "candidate.yar", workdir / "empty.bin"
    rule_path.write_bytes(rule_text.encode("utf-8"))
    empty.write_bytes(b"")
    state, _ = _state_after_f_startup(system)
    results = {"rule_sha256": hashlib.sha256(rule_text.encode("utf-8")).hexdigest(),
               "compiled": None, "compile_errors": [], "matches": {}}
    technical = None
    try:
        compiled = system.run([yara, "-w", rule_path, empty], timeout)
        errors = [line for line in compiled["stderr"].splitlines() if line.strip()]
        if compiled["exit_code"] == 0:
            results["compiled"] = True
        elif errors and all(COMPILE_ERROR.match(line) for line in errors):
            # Only diagnostics that point into the candidate file count as a compile failure.
            results["compiled"], results["compile_errors"] = False, errors[:20]
        else:
            technical = "EXIT_" + str(compiled["exit_code"])
    except (subprocess.TimeoutExpired, OSError) as exc:
        technical = type(exc).__name__
    if results["compiled"]:
        for sample_id, path, expected in files:
            status, _, _ = _yara_file(system, yara, rule_path, path, expected, timeout) \
                if state_matches(state, "F") else ("ERROR", [], "STATE_MISMATCH")
            results["matches"][sample_id] = {"status": "ERROR" if status == "NOT_RUN" else status,
                                             "sha256": expected}
    return {"schema": 1, "kind": "candidate_check", "expected_state": "F", "defender_state": state,
            "technical_error": technical, "finished_at_utc": system.now(), "results": results}


def write_new(path, value):
    path = Path(path)
    if path.exists():
        raise FileExistsError("Report already exists")
    temporary = path.with_name("writing-" + uuid.uuid4().hex + ".json")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.rename(temporary, path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, help="JSON request prepared on the host")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    request = json.loads(Path(args.request).read_text(encoding="utf-8"))
    system = WindowsSystem()
    root = Path(args.request).parent
    files = [(f["sample_id"], root / f["path"], f["sha256"]) for f in request["files"]]
    if request["kind"] == "av_check":
        if len(files) != 1:
            raise ValueError("An AV check covers exactly one file; restore the VM before the next")
        (sample_id, path, expected), = files
        value = av_check(system, path, expected, wait_seconds=request["wait_seconds"],
                         run_id=request["run_id"], sample_id=sample_id)
    elif request["kind"] == "yara_check":
        value = yara_check(system, files, yara=root / "yara64.exe", yara_sha256=request["yara_sha256"],
                           ruleset=root / "frozen.yar", ruleset_sha256=request["ruleset_sha256"],
                           run_id=request["run_id"])
    else:
        raise ValueError("Unknown check kind")
    value.update(platform=platform.system(), architecture=platform.machine(),
                 code_sha256=sha256(Path(__file__)))
    write_new(args.output, value)


if __name__ == "__main__":
    main()
