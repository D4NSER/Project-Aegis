"""Windows ARM lab preparation and a fixed, harmless managed-PE rehearsal.

No research object can be supplied to this module. EICAR is written for an AV
control only and is never executed. Protection and network settings are read,
not changed. Process Monitor's license must be accepted by the operator.
"""
import argparse
import base64
import csv
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import time
import uuid

from control_workspace import write_json
from guest_control import plain_path
from guest_scanners import (powershell_json, defender_state, defender_program,
                            defender_threats, interpret_defender)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def ps_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def signature(path):
    return powershell_json(
        "$s=Get-AuthenticodeSignature -LiteralPath " + ps_literal(path) +
        "; [pscustomobject]@{status=[string]$s.Status;subject=[string]$s.SignerCertificate.Subject;"
        "thumbprint=[string]$s.SignerCertificate.Thumbprint;version=(Get-Item -LiteralPath " +
        ps_literal(path) + ").VersionInfo.FileVersion}|ConvertTo-Json -Compress")


def accepted_procmon_license():
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Sysinternals\Process Monitor") as key:
            return winreg.QueryValueEx(key, 'EulaAccepted')[0] == 1
    except OSError:
        return False


def load_kit(root):
    if os.name != 'nt' or platform.machine().casefold() not in {'arm64', 'aarch64'}:
        raise ValueError('This rehearsal requires Windows ARM64')
    root = plain_path(root)
    manifest = json.loads((root / 'lab-kit.json').read_text(encoding='utf-8'))
    required = {'src/aegis.py', 'src/control_workspace.py', 'src/guest_control.py',
                'src/guest_scanners.py', 'src/guest_lab.py', 'rules/control-marker.yar',
                'yara64.exe', 'Procmon64a.exe', 'Eula.txt'}
    if set(manifest.get('files', {})) != required:
        raise ValueError('Unexpected lab kit contents')
    for name, expected in manifest['files'].items():
        path = plain_path(root.joinpath(*name.split('/')))
        if not path.is_file() or digest(path) != expected:
            raise ValueError('Lab kit identity mismatch: ' + name)
    return root, manifest


def inventory(root):
    root, manifest = load_kit(root)
    windows = Path(os.environ['WINDIR'])
    candidates = [windows / folder / 'v4.0.30319/csc.exe'
                  for folder in ('Microsoft.NET/Framework64', 'Microsoft.NET/Framework')]
    compilers = [{'path': str(p), 'sha256': digest(p), 'signature': signature(p)}
                 for p in candidates if p.is_file()]
    procmon = signature(root / 'Procmon64a.exe')
    if procmon['status'] != 'Valid' or 'microsoft' not in procmon['subject'].casefold():
        raise ValueError('Process Monitor does not have a valid Microsoft signature')
    raw = (root / 'Procmon64a.exe').read_bytes()
    offset = struct.unpack_from('<I', raw, 0x3c)[0]
    machine = struct.unpack_from('<H', raw, offset + 4)[0]
    if machine != 0xaa64:
        raise ValueError('Process Monitor is not ARM64')
    network = powershell_json(
        "[pscustomobject]@{active_adapters=@(Get-NetAdapter | Where-Object Status -eq 'Up' | "
        "Select-Object Name,InterfaceDescription);default_routes=@(Get-NetRoute | Where-Object "
        "{$_.DestinationPrefix -in @('0.0.0.0/0','::/0')}|Select-Object DestinationPrefix,InterfaceAlias)}"
        "|ConvertTo-Json -Depth 5 -Compress")
    preferences = powershell_json(
        'Get-MpPreference | Select-Object MAPSReporting,SubmitSamplesConsent,DisableRealtimeMonitoring,'
        'DisableIOAVProtection,DisableBehaviorMonitoring | ConvertTo-Json -Compress')
    return {'schema': 1, 'kind': 'arm_lab_inventory', 'experiment_results': False,
            'created_at_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.system(),
            'architecture': platform.machine(), 'code_sha256': digest(Path(__file__)),
            'kit_sha256': digest(root / 'lab-kit.json'), 'compilers': compilers,
            'procmon': {**procmon, 'sha256': digest(root / 'Procmon64a.exe'), 'machine': machine,
                        'operator_license_accepted': accepted_procmon_license()},
            'yara': {'version': bounded_process([root / 'yara64.exe', '--version'])['stdout'].strip(),
                     'sha256': digest(root / 'yara64.exe')},
            'defender': defender_state(), 'defender_preferences': preferences, 'network': network,
            'elevated': bool(ctypes.windll.shell32.IsUserAnAdmin()),
            'settings_changed': False, 'credentials_saved': False}


def atomic_report(path, value):
    path = plain_path(path)
    if path.exists():
        raise FileExistsError('Lab report already exists')
    temporary = path.with_name('writing-' + uuid.uuid4().hex + '.json')
    write_json(temporary, value)
    os.rename(temporary, path)


def fixture_source(label, run_parent):
    if label not in {'AEGIS_REHEARSAL_BASELINE', 'AEGIS_REHEARSAL_VARIANT'}:
        raise ValueError('Only the two fixed harmless fixtures can be compiled')
    directory = str(run_parent).replace('"', '""')
    return '''using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
class AegisHarmlessFixture {
 static int Main(string[] args) {
  if(args.Length!=2 || !Regex.IsMatch(args[1], "^[a-f0-9]{32}$")) return 2;
  string root=Path.GetFullPath(args[0]);
  if(Path.GetDirectoryName(root)!=@"DIRECTORY" ||
     (Path.GetFileName(root)!="baseline" && Path.GetFileName(root)!="variant")) return 3;
  if(!Directory.Exists(root)) return 4;
  File.WriteAllText(Path.Combine(root,"observed.txt"),"AEGIS_OK:"+args[1],new UTF8Encoding(false));
  Console.WriteLine("LABEL:"+args[1]);
  return 0;
 }
}
'''.replace('DIRECTORY', directory).replace('LABEL', label)


def bounded_process(arguments, timeout=30):
    result = subprocess.run([str(value) for value in arguments], capture_output=True,
                            text=True, errors='replace', timeout=timeout)
    return {'exit_code': result.returncode, 'stdout': result.stdout[:8192],
            'stderr': result.stderr[:8192]}


def inspect_pe(path):
    content = Path(path).read_bytes()
    if content[:2] != b'MZ' or len(content) < 256:
        raise ValueError('Compiled fixture is not a PE file')
    offset = struct.unpack_from('<I', content, 0x3c)[0]
    if content[offset:offset+4] != b'PE\0\0':
        raise ValueError('Compiled fixture has no PE header')
    machine = struct.unpack_from('<H', content, offset+4)[0]
    optional = offset+24
    magic = struct.unpack_from('<H', content, optional)[0]
    directory = optional + (96 if magic == 0x10b else 112)
    clr_rva, clr_size = struct.unpack_from('<II', content, directory + 14*8)
    if not clr_rva or not clr_size:
        raise ValueError('The rehearsal fixture must be a managed PE')
    return {'machine': machine, 'managed': True, 'execution_model': '.NET AnyCPU; not a native ARM64 fixture',
            'sha256': hashlib.sha256(content).hexdigest(), 'bytes': len(content)}


def run_fixture(executable, destination, token, label):
    started = datetime.now(timezone.utc).isoformat()
    process = subprocess.Popen([str(executable), str(destination), token],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='replace')
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=8)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
    observed = destination / 'observed.txt'
    expected = ('AEGIS_OK:' + token).encode('utf-8')
    contents = observed.read_bytes() if observed.is_file() else None
    passed = (not timed_out and process.returncode == 0 and contents == expected
              and stdout.strip() == label + ':' + token)
    return {'pid': process.pid, 'started_at_utc': started, 'exit_code': process.returncode,
            'timed_out': timed_out, 'stdout': stdout[:4096], 'stderr': stderr[:4096],
            'criterion': 'exit zero AND exact stdout challenge AND exact owned-file bytes within 8 seconds',
            'functionality': 'PASS' if passed else 'INCONCLUSIVE' if timed_out else 'FAIL',
            'observed_sha256': hashlib.sha256(contents).hexdigest() if contents is not None else None,
            'expected_sha256': hashlib.sha256(expected).hexdigest(), 'observed_path': str(observed)}


def monitor_evidence(csv_path, fixtures):
    output = {}
    prefix = csv_path.read_bytes()[:2]
    encoding = 'utf-16' if prefix in (b'\xff\xfe', b'\xfe\xff') else 'utf-8-sig'
    by_pid = {str(value['run']['pid']): key for key, value in fixtures.items()}
    for key in fixtures:
        output[key] = {'events': 0, 'operations': {}, 'owned_write_observed': False}
    with csv_path.open(encoding=encoding, errors='replace', newline='') as stream:
        reader = csv.DictReader(stream)
        if not {'PID', 'Operation', 'Path', 'Result'} <= set(reader.fieldnames or []):
            raise ValueError('Unrecognized Process Monitor CSV columns')
        for row in reader:
            key = by_pid.get(row['PID'].strip())
            if key is None:
                continue
            item = output[key]
            item['events'] += 1
            operation = row['Operation']
            item['operations'][operation] = item['operations'].get(operation, 0) + 1
            if (operation == 'WriteFile' and row['Result'] == 'SUCCESS'
                    and row['Path'].casefold() == fixtures[key]['run']['observed_path'].casefold()):
                item['owned_write_observed'] = True
    return output


def scan_negative(yara, rule, executable, before):
    original = digest(executable)
    y = bounded_process([yara, '-w', rule, executable])
    scan = bounded_process([defender_program(), '-Scan', '-ScanType', '3', '-File', executable], timeout=60)
    try:
        threats = defender_threats()
        threats = [threats] if isinstance(threats, dict) else threats
        relevant = [value for value in threats if any(str(executable).casefold() in str(r).casefold()
                                                     for r in value.get('Resources', []))]
        known = True
    except (OSError, ValueError, subprocess.SubprocessError):
        relevant, known = [], False
    after = defender_state()
    unchanged = executable.is_file() and digest(executable) == original
    av = interpret_defender(scan['exit_code'], unchanged, known, relevant,
        before.get('AntivirusEnabled') is True and after.get('AntivirusEnabled') is True,
        bool(before.get('AntivirusSignatureVersion')) and
        before.get('AntivirusSignatureVersion') == after.get('AntivirusSignatureVersion'))
    return {'av_status': av, 'av_raw': scan, 'threat_history_known': known,
            'relevant_threats': relevant, 'bytes_unchanged': unchanged,
            'yara_raw': y, 'yara_status': 'ERROR' if y['exit_code'] else 'MATCHED' if y['stdout'].strip() else 'NOT_MATCHED'}


def positive_control(work, started):
    # The official harmless EICAR test string is materialized only in Windows.
    # It is never supplied to a process execution call or copied to the host.
    content = base64.b64decode('WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=')
    if len(content) != 68:
        raise ValueError('Invalid official AV control length')
    target = work / 'eicar-control.txt'
    write_error = None
    try:
        with target.open('xb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        write_error = type(exc).__name__
    scan = None
    if target.is_file():
        scan = bounded_process([defender_program(), '-Scan', '-ScanType', '3', '-File', target], timeout=60)
    relevant, events = [], []
    for attempt in range(4):
        try:
            threats = defender_threats()
            threats = [threats] if isinstance(threats, dict) else threats
            relevant = [value for value in threats if any(str(target).casefold() in str(resource).casefold()
                                                         for resource in value.get('Resources', []))]
        except (OSError, ValueError, subprocess.SubprocessError):
            relevant = []
        if relevant:
            break
        time.sleep(1)
    try:
        script = ("$start=[datetime]::Parse(" + ps_literal(started) + "); $target=" + ps_literal(target) +
                  "; ConvertTo-Json -InputObject @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';"
                  "StartTime=$start;Id=@(1116,1117,1118,1119)} -ErrorAction SilentlyContinue | "
                  "Where-Object {$_.ToXml().IndexOf($target,[StringComparison]::OrdinalIgnoreCase) -ge 0} | "
                  "Select-Object -First 12 @{N='id';E={$_.Id}},@{N='record_id';E={$_.RecordId}},"
                  "@{N='xml';E={$_.ToXml()}}) -Depth 5 -Compress")
        events = powershell_json(script)
    except (OSError, ValueError, subprocess.SubprocessError):
        events = []
    detected = bool(relevant) or any(value.get('id') == 1116 for value in events)
    return {'type': 'official_EICAR; harmless AV control, never executed',
            'expected_sha256': hashlib.sha256(content).hexdigest(), 'bytes': len(content),
            'status': 'DETECTED' if detected else 'INCONCLUSIVE', 'write_error': write_error,
            'scan_raw': scan, 'exists_after': target.is_file(), 'threats': relevant, 'events': events,
            'scope': 'Real-time protection may detect before custom scan; not proof of custom-scan-only positive handling'}


def rehearsal(root):
    root, manifest = load_kit(root)
    initial = inventory(root)
    if not initial['elevated']:
        raise ValueError('Launch the reviewed desktop command and approve normal Windows UAC')
    if not initial['procmon']['operator_license_accepted']:
        raise ValueError('Review and accept the actual Process Monitor EULA yourself, then close its window')
    if initial['network']['active_adapters']:
        raise ValueError('Network must remain disconnected')
    compiler = next((Path(value['path']) for value in initial['compilers']
                     if value['signature']['status'] == 'Valid'), None)
    if compiler is None:
        raise ValueError('No Microsoft-signed built-in C# compiler was found')
    active = powershell_json("ConvertTo-Json -InputObject @(Get-Process -ErrorAction SilentlyContinue | "
                             "Where-Object {$_.ProcessName -match '^Procmon(64a|64)?$'} | Select-Object Id,ProcessName) -Compress")
    if active:
        raise ValueError('Close the previous Process Monitor window before starting the rehearsal')
    started = datetime.now(timezone.utc).isoformat()
    token = uuid.uuid4().hex
    work = root / ('work-' + token)
    work.mkdir()
    runs = work / 'runs'
    runs.mkdir()
    fixtures = {}
    for key, label in (('baseline', 'AEGIS_REHEARSAL_BASELINE'), ('variant', 'AEGIS_REHEARSAL_VARIANT')):
        source = work / (key + '.cs')
        source.write_text(fixture_source(label, runs), encoding='utf-8')
        executable = work / (key + '.exe')
        compile_result = bounded_process([compiler, '/nologo', '/target:exe', '/platform:anycpu',
                                          '/out:' + str(executable), source], timeout=45)
        if compile_result['exit_code'] != 0 or not executable.is_file():
            raise ValueError('Harmless fixture compilation failed: ' + compile_result['stdout'][:800])
        destination = runs / key
        destination.mkdir()
        fixtures[key] = {'source_sha256': digest(source), 'compile': compile_result,
                         'pe': inspect_pe(executable), 'label': label}
    trace = work / 'process-monitor.pml'
    csv_trace = work / 'process-monitor.csv'
    procmon = root / 'Procmon64a.exe'
    monitor = subprocess.Popen([str(procmon), '/Quiet', '/Minimized', '/BackingFile', str(trace)])
    stopped = None
    try:
        time.sleep(1.5)
        for key, value in fixtures.items():
            value['run'] = run_fixture(work / (key + '.exe'), runs / key, token, value['label'])
        # Procmon drains driver events asynchronously. Immediate termination
        # can truncate the final process's writes despite a successful exit.
        # The CSV evidence still decides whether the capture is sufficient.
        time.sleep(2)
    finally:
        stopped = bounded_process([procmon, '/Terminate', '/Quiet'], timeout=20)
        monitor.wait(timeout=15)
    if stopped['exit_code'] != 0 or not trace.is_file() or trace.stat().st_size > 128 * 1024 * 1024:
        raise ValueError('Process Monitor did not save a bounded trace')
    export = bounded_process([procmon, '/OpenLog', trace, '/SaveAs', csv_trace, '/Quiet'], timeout=45)
    if export['exit_code'] != 0 or not csv_trace.is_file() or csv_trace.stat().st_size > 128 * 1024 * 1024:
        raise ValueError('Process Monitor CSV export failed or exceeded the limit')
    monitoring = monitor_evidence(csv_trace, fixtures)
    rule = work / 'rehearsal.yar'
    rule.write_text('rule Aegis_Rehearsal_Variant { strings: $s="AEGIS_REHEARSAL_VARIANT" ascii wide condition: $s }\n')
    invalid = work / 'invalid-control.yar'
    invalid.write_text('rule Deliberately_Invalid { condition: }\n')
    yara = root / 'yara64.exe'
    invalid_result = bounded_process([yara, invalid, work / 'baseline.exe'])
    for key, value in fixtures.items():
        value['scan'] = scan_negative(yara, rule, work / (key + '.exe'), initial['defender'])
    eicar = positive_control(work, started)
    absent = work / 'deliberately-missing.exe'
    missing = {'input_exists': absent.exists(), 'status': 'NOT_RUN', 'reason': 'MISSING_INPUT',
               'never_classified_as_negative': True}
    observed = {'functionality_passed': all(v['run']['functionality'] == 'PASS' for v in fixtures.values()),
                'independent_file_writes_observed': all(v['owned_write_observed'] for v in monitoring.values()),
                'yara_positive_and_negative': fixtures['baseline']['scan']['yara_status'] == 'NOT_MATCHED'
                    and fixtures['variant']['scan']['yara_status'] == 'MATCHED',
                'yara_invalid_rule_rejected': invalid_result['exit_code'] != 0,
                'defender_negative_controls': all(v['scan']['av_status'] == 'NOT_DETECTED' for v in fixtures.values()),
                'defender_eicar_observed': eicar['status'] == 'DETECTED',
                'missing_input_not_negative': not missing['input_exists']}
    artifacts = []
    for path in sorted(work.rglob('*')):
        if path.is_file() and path.name != 'eicar-control.txt':
            artifacts.append({'path': path.relative_to(root).as_posix(), 'sha256': digest(path), 'bytes': path.stat().st_size})
    return {'schema': 1, 'mode': 'benign_pe_rehearsal', 'experiment_results': False,
            'created_at_utc': datetime.now(timezone.utc).isoformat(), 'started_at_utc': started,
            'platform': platform.system(), 'architecture': platform.machine(), 'run_id': 'rehearsal-' + token,
            'code_sha256': digest(Path(__file__)), 'kit_sha256': digest(root / 'lab-kit.json'),
            'environment': initial, 'fixtures': fixtures, 'monitoring': monitoring,
            'files': [{'id': key, 'bytes': value['pe']['bytes'], 'sha256': value['pe']['sha256'],
                       'hash_verified': value['scan']['bytes_unchanged'], 'av_status': value['scan']['av_status'],
                       'yara_status': value['scan']['yara_status'], 'functionality': value['run']['functionality']}
                      for key, value in fixtures.items()],
            'invalid_rule_control': invalid_result, 'positive_av_control': eicar, 'missing_input_control': missing,
            'checks': observed, 'all_checks_passed': all(observed.values()), 'artifacts': artifacts,
            'defender_after': defender_state(), 'settings_changed': False,
            'vm_restore_verified': False, 'research_objects_executed': False,
            'scope': 'Two generated harmless managed PE fixtures; no proof of arbitrary native PE or malware compatibility'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kit', required=True)
    parser.add_argument('--action', choices=['inventory', 'operator_ready', 'rehearsal'], required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        value = inventory(args.kit) if args.action in {'inventory','operator_ready'} else rehearsal(args.kit)
        if args.action=='operator_ready' and value['procmon']['operator_license_accepted'] is not True:
            raise ValueError('The operator has not accepted the Process Monitor license')
        atomic_report(args.output, value)
    except Exception as exc:
        failure = Path(args.output).with_name('failure-' + Path(args.output).name)
        if not failure.exists():
            atomic_report(failure, {'kind': 'lab_failure', 'error_type': type(exc).__name__,
                                   'message': str(exc)[:2000], 'experiment_results': False})
        raise


if __name__ == '__main__':
    main()
