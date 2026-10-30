"""Deploy the pinned ARM lab kit; retrieve evidence before a cold restore."""
import base64
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import uuid

from control_workspace import write_json
from vm_run_manager import windows_arguments


class LabPreparation:
    def __init__(self, manager):
        self.manager = manager
        self.folder = manager.workspace / 'lab-preparation'
        if self.folder.is_symlink():
            raise ValueError('Unexpected lab preparation link')
        self.folder.mkdir(parents=True, exist_ok=True)
        self.pending = None
        self.notified_baseline=False
        for path in self.folder.glob('preparation-*/pending.json'):
            if path.with_name('resolved.json').exists() or path.with_name('deferred.json').exists():
                continue
            if self.pending:
                raise ValueError('Multiple lab preparation jobs need review')
            value = self.read(path)
            if value['vmx'] != str(manager.vmx.resolve()):
                continue
            if Path(value['host_root']) != path.parent or not re.fullmatch(r'preparation-[0-9a-f]{32}', path.parent.name):
                raise ValueError('Invalid lab preparation identity')
            self.pending = value

    @staticmethod
    def read(path):
        path = Path(path)
        if path.is_symlink() or path.stat().st_size > 1024 * 1024:
            raise ValueError('Invalid lab preparation record')
        return json.loads(path.read_text(encoding='utf-8'))

    def prepare(self, vendor):
        m = self.manager
        if self.pending or m.pending_scan or m.scanner_cleanup:
            raise ValueError('Finish the existing job and restore first')
        if not m.session or m.session.state not in {'baseline_ready', 'restored'}:
            raise ValueError('Prepare the cold baseline first')
        if not m.environment or not m.environment.get('personal_accounts_separated'):
            raise ValueError('Dedicated-account separation is required')
        probe = m.probe()
        if probe.get('network_config') != 'disconnected' or probe.get('sharing_config') != 'disabled':
            raise ValueError('Network and sharing must be disconnected')
        vendor = Path(vendor)
        provenance = self.read(vendor / 'provenance.json')
        for name in ('Procmon64a.exe', 'Eula.txt'):
            if hashlib.sha256((vendor / name).read_bytes()).hexdigest() != provenance['files'][name]['sha256']:
                raise ValueError('Prepared vendor file changed')
        yara = Path(m.scanner['yara_executable'])
        if hashlib.sha256(yara.read_bytes()).hexdigest() != m.scanner['yara_sha256']:
            raise ValueError('Prepared YARA file changed')
        token = uuid.uuid4().hex
        host = self.folder / ('preparation-' + token)
        host.mkdir()
        cleanup = {'id': token, 'vmx': str(m.vmx.resolve()), 'previous_cycle': str(m.session.cycle_root),
                   'kind': 'arm_lab_preparation', 'experiment_results': False}
        checks = m.workspace / 'scanner-checks'
        checks.mkdir(exist_ok=True)
        write_json(checks / ('cleanup-required-' + token + '.json'), cleanup)
        m.scanner_cleanup = cleanup
        appdata = PureWindowsPath(m.connection.environment('LOCALAPPDATA'))
        kit = appdata / ('AegisLabKit-' + token)
        source = Path(__file__).parent
        sources = {('src/' + name): source / name for name in
                   ('aegis.py', 'control_workspace.py', 'guest_control.py', 'guest_scanners.py', 'guest_lab.py')}
        sources.update({'rules/control-marker.yar': source.parent / 'rules/control-marker.yar',
                        'yara64.exe': yara, 'Procmon64a.exe': vendor / 'Procmon64a.exe', 'Eula.txt': vendor / 'Eula.txt'})
        hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sources.items()}
        manifest = host / 'lab-kit.json'
        write_json(manifest, {'schema': 1, 'files': hashes, 'experiment_results': False})
        pending = {'vmx': str(m.vmx.resolve()), 'host_root': str(host), 'guest_root': str(kit),
                   'guest_output': str(kit / 'rehearsal.json'), 'files': hashes,
                   'kit_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
                   'awaiting_operator': True, 'experiment_results': False}
        write_json(host / 'pending.json', pending)
        self.pending = pending
        for directory in (kit, kit / 'src', kit / 'rules'):
            m.connection.mkdir(str(directory))
        for name, path in sources.items():
            m.connection.copy_to(path, str(kit / PureWindowsPath(name)))
        m.connection.copy_to(manifest, str(kit / 'lab-kit.json'))
        output = kit / 'inventory.json'
        code = m.connection.run(m.python, windows_arguments(kit / 'src/guest_lab.py', '--kit', kit,
            '--action', 'inventory', '--output', output), timeout=120)
        if code != 0:
            self.retrieve_failure('inventory.json')
            raise ValueError('Windows lab inventory failed; see the saved failure record')
        path = host / 'inventory.json'
        m.connection.copy_from(str(output), path)
        value = self.read(path)
        if (value.get('code_sha256') != hashes['src/guest_lab.py'] or value.get('kit_sha256') != pending['kit_sha256']
                or value.get('platform') != 'Windows' or value.get('architecture', '').casefold() not in {'arm64', 'aarch64'}
                or value.get('settings_changed') is not False):
            raise ValueError('Windows inventory identity mismatch')
        if not value['compilers']:
            raise ValueError('The built-in C# compiler is absent; choose a supported compiler before rehearsal')
        # No automatic license acceptance. The operator opens this launcher and
        # approves ordinary elevation, then reviews Procmon's actual EULA dialog.
        proc = str(kit / 'Procmon64a.exe').replace("'", "''")
        args = windows_arguments(kit / 'src/guest_lab.py', '--kit', kit, '--action', 'operator_ready', '--output', kit / 'operator-ready.json')
        script = ("$ErrorActionPreference='Stop'; Start-Process -FilePath '" + proc +
                  "' -Verb RunAs -ArgumentList '/NoConnect' -Wait; & '" +
                  m.python.replace("'", "''") + "' " + args)
        encoded = base64.b64encode(script.encode('utf-16le')).decode('ascii')
        launcher = host / 'Prepare-ARM-Tools.cmd'
        launcher.write_bytes(('@echo off\r\npowershell.exe -NoLogo -NoProfile -EncodedCommand ' + encoded + '\r\n').encode('ascii'))
        desktop_root = PureWindowsPath(m.connection.environment('USERPROFILE')) / 'Desktop'
        desktop = desktop_root / ('Aegis-Prepare-ARM-' + token[:8] + '.cmd')
        m.connection.copy_to(launcher, str(desktop))
        run_args=windows_arguments(kit/'src/guest_lab.py','--kit',kit,'--action','rehearsal','--output',kit/'rehearsal.json')
        run_script="Start-Process -FilePath '"+m.python.replace("'","''")+"' -Verb RunAs -ArgumentList '"+run_args.replace("'","''")+"' -Wait"
        encoded=base64.b64encode(run_script.encode('utf-16le')).decode('ascii')
        run_launcher=host/'Run-PE-Rehearsal.cmd'
        run_launcher.write_bytes(('@echo off\r\npowershell.exe -NoLogo -NoProfile -EncodedCommand '+encoded+'\r\n').encode('ascii'))
        m.connection.copy_to(run_launcher,str(desktop_root/('Aegis-PE-Rehearsal-'+token[:8]+'.cmd')))
        if value.get('procmon', {}).get('operator_license_accepted') is True:
            # Read the already approved state; never accept or alter the EULA.
            code = m.connection.run(m.python, windows_arguments(kit/'src/guest_lab.py', '--kit', kit,
                '--action', 'operator_ready', '--output', kit/'operator-ready.json'), timeout=120)
            if code != 0:
                self.retrieve_failure('operator-ready.json')
                raise ValueError('Previously approved tool state could not be verified')
        return {'inventory': value, 'host_root': str(host), 'launcher': str(desktop), 'awaiting_operator': True}

    def retrieve_failure(self, name):
        if not self.pending:
            return None
        source = PureWindowsPath(self.pending['guest_root']) / ('failure-' + name)
        target = Path(self.pending['host_root']) / ('failure-' + name)
        if self.manager.connection.exists(str(source)):
            if not target.exists():
                self.manager.connection.copy_from(str(source), target)
            return self.read(target)

    def request_rehearsal(self):
        """Open the exact prepared launcher; Windows still shows ordinary UAC."""
        if not self.pending:
            raise ValueError('No prepared rehearsal is waiting')
        host = Path(self.pending['host_root'])
        if not (host/'baseline-ready.json').is_file():
            raise ValueError('Wait for the prepared baseline')
        stage = self.read(host/'baseline-ready.json')
        if stage['session_root'] != str(self.manager.session.root):
            raise ValueError('Prepared baseline identity changed')
        kit = PureWindowsPath(self.pending['guest_root'])
        if self.manager.connection.exists(str(kit/'rehearsal-interactive-requested.json')):
            raise ValueError('The rehearsal was already requested; inspect Windows or retrieve its result')
        launcher = host/'Run-PE-Rehearsal.cmd'
        # Require the same lab user to be present at the console. Ordinary
        # Tools logons create a background session where UAC cannot be shown.
        self.manager.connection.login(self.manager.username, self.manager.credential, interactive=True)
        requested = host/'rehearsal-interactive-requested.json'
        write_json(requested, {'launcher_sha256': hashlib.sha256(launcher.read_bytes()).hexdigest(),
                              'normal_windows_uac_required': True, 'experiment_results': False})
        self.manager.connection.copy_to(requested, str(kit/requested.name))
        # Execute only our pinned host launcher text in that existing session.
        # No saved administrator credentials or UAC bypass.
        line = launcher.read_text(encoding='ascii').splitlines()[1]
        if not line.startswith('powershell.exe -NoLogo -NoProfile -EncodedCommand '):
            raise ValueError('Unexpected prepared launcher')
        self.manager.connection.run(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                                    line.removeprefix('powershell.exe '), wait=False)

    def poll(self):
        if not self.pending:
            return None
        host=Path(self.pending['host_root']);kit=PureWindowsPath(self.pending['guest_root'])
        setup_failure = self.retrieve_failure('operator-ready.json')
        rehearsal_failure = self.retrieve_failure('rehearsal.json')
        # A repeated setup launcher cannot overwrite its first proof. Only this
        # exact duplicate is recoverable, after a validated prepared baseline.
        duplicate_setup = (setup_failure and setup_failure.get('error_type') == 'FileExistsError'
                           and setup_failure.get('message') == 'Lab report already exists'
                           and (host/'baseline-ready.json').is_file())
        if rehearsal_failure or (setup_failure and not duplicate_setup):
            failure = rehearsal_failure or setup_failure
            raise ValueError('Windows rehearsal failed: ' + failure['error_type'] + ': ' + failure['message'])
        if not (host/'operator-ready.json').exists():
            if not self.manager.connection.exists(str(kit/'operator-ready.json')):return None
            self.manager.connection.copy_from(str(kit/'operator-ready.json'),host/'operator-ready.json')
        ready=self.read(host/'operator-ready.json')
        if (ready.get('kit_sha256')!=self.pending['kit_sha256']
                or ready.get('code_sha256')!=self.pending['files']['src/guest_lab.py']
                or ready.get('procmon',{}).get('operator_license_accepted') is not True):
            raise ValueError('Operator preparation proof does not match this kit')
        if not (host/'baseline-started.json').exists():
            self.create_prepared_baseline(host)
        if self.manager.session.state in {'awaiting_baseline_boot','awaiting_restore_boot'}:
            return {'stage':'awaiting_boot','summary':self.manager.summary()}
        stage=self.read(host/'baseline-started.json')
        if stage['session_root']!=str(self.manager.session.root):
            raise ValueError('Prepared baseline operation needs recovery review')
        if duplicate_setup and not (host/'duplicate-setup-reviewed.json').exists():
            write_json(host/'duplicate-setup-reviewed.json', {
                'reason': 'Repeated setup preserved the original validated proof and baseline',
                'failure': setup_failure, 'experiment_results': False})
        if not (host/'baseline-ready.json').exists():
            if self.manager.session.state!='baseline_ready':raise ValueError('Prepared baseline is not ready')
            write_json(host/'baseline-ready.json',{'snapshot':self.manager.session.snapshot,'session_root':str(self.manager.session.root),
                       'tool_versions_pinned':True,'operator_license_persisted_in_baseline':True,'experiment_results':False})
        if not self.notified_baseline:
            self.notified_baseline=True
            return {'stage':'ready_for_rehearsal','launcher':'Aegis-PE-Rehearsal-'+host.name[-32:][:8]+'.cmd'}
        if not self.manager.connection.exists(self.pending['guest_output']):
            return None
        value = self.pending
        host = Path(value['host_root'])
        report_path = host / 'report.json'
        if not report_path.exists():
            self.manager.connection.copy_from(value['guest_output'], report_path)
        report = self.read(report_path)
        validate_report(report, value)
        artifacts = host / 'artifacts'
        artifacts.mkdir(exist_ok=True)
        for item in report['artifacts']:
            relative = Path(*item['path'].split('/'))
            target = artifacts / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and (target.stat().st_size != item['bytes']
                    or hashlib.sha256(target.read_bytes()).hexdigest() != item['sha256']):
                # Preserve an interrupted copy for review; never overwrite it.
                target.rename(target.with_name('interrupted-'+uuid.uuid4().hex+'-'+target.name))
            if not target.exists():
                self.manager.progress('Perkeliami PE įrodymai: '+relative.name+' ('+str(item['bytes']//1024)+' KiB)…')
                self.manager.connection.copy_from(str(PureWindowsPath(value['guest_root']) / PureWindowsPath(item['path'])), target,
                                                  timeout=180)
            if target.stat().st_size != item['bytes'] or hashlib.sha256(target.read_bytes()).hexdigest() != item['sha256']:
                raise ValueError('Rehearsal artifact transport mismatch')
        write_json(host / 'resolved.json', {'report_sha256': hashlib.sha256(report_path.read_bytes()).hexdigest(),
                   'artifacts_verified': True, 'all_checks_passed': report['all_checks_passed'],
                   'experiment_results': False, 'vm_restore_verified': False})
        self.pending = None
        return {'report': report, 'host_root': str(host)}

    def create_prepared_baseline(self,host):
        from vm_control_session import ManualControlSession
        m=self.manager
        m.collect_environment();m.status()
        previous=m.session
        session=ManualControlSession(m.connection,m.media,m.workspace,m.vmx,account_ready=True,
                                     probe=m.probe,windows_credentials_used=True)
        write_json(session.root/'deployment.json',{'guest_root':str(m.guest_root),'source_hashes':m.manifest['source_hashes'],
                   'windows_credentials_used':True,'credentials_saved':False,'experiment_results':False})
        write_json(host/'baseline-started.json',{'session_root':str(session.root),'previous_session_root':str(previous.root),
                   'reason':'Operator-approved ARM tools and license state; no rehearsal work or EICAR yet','experiment_results':False})
        m.session=session
        m.baseline()

    def record_restore(self):
        m = self.manager
        if not m.session or m.session.state != 'restored' or m.scanner_cleanup:
            return
        for host in self.folder.glob('preparation-*'):
            if not (host / 'resolved.json').is_file() or (host / 'restoration.json').exists():
                continue
            token = host.name.removeprefix('preparation-')
            record = m.workspace / 'scanner-checks' / ('cleanup-completed-' + token + '.json')
            if record.is_file():
                proof = self.read(record)
                write_json(host / 'restoration.json', proof)
        self.audit_restored_artifacts()

    def audit_restored_artifacts(self):
        """Read-only proof that the rehearsal files vanished but the kit survived."""
        m = self.manager
        if not m.session or m.session.state not in {'baseline_ready', 'restored'} or self.pending:
            return
        for host in self.folder.glob('preparation-*'):
            target=host/'restored-artifacts.json'
            if target.exists() or not (host/'restoration.json').is_file():
                continue
            pending=self.read(host/'pending.json');report=self.read(host/'report.json')
            kit=PureWindowsPath(pending['guest_root'])
            names=['rehearsal.json', *[item['path'] for item in report['artifacts']]]
            remaining=[name for name in names if m.connection.exists(str(kit/PureWindowsPath(name)))]
            if remaining:
                raise ValueError('Rehearsal artifacts remain after the cold restore')
            manifest=host/'restored-kit.json'
            if not manifest.exists():m.connection.copy_from(str(kit/'lab-kit.json'), manifest)
            if hashlib.sha256(manifest.read_bytes()).hexdigest()!=pending['kit_sha256']:
                raise ValueError('Prepared tools manifest changed after restore')
            write_json(target, {'checked_paths': names, 'all_rehearsal_files_absent': True,
                'prepared_kit_manifest_sha256': pending['kit_sha256'], 'prepared_kit_preserved': True,
                'experiment_results': False})

    def defer(self):
        if self.pending:
            write_json(Path(self.pending['host_root']) / 'deferred.json',
                       {'status': 'NOT_RUN', 'reason': 'Operator deferred preparation', 'experiment_results': False})
            self.pending = None


def validate_report(report, pending):
    if (type(report.get('schema')) is not int or report.get('schema') != 1 or report.get('mode') != 'benign_pe_rehearsal'
            or report.get('experiment_results') is not False or report.get('platform') != 'Windows'
            or report.get('architecture', '').casefold() not in {'arm64', 'aarch64'}
            or report.get('code_sha256') != pending['files']['src/guest_lab.py']
            or report.get('kit_sha256') != pending['kit_sha256']
            or report.get('settings_changed') is not False or report.get('research_objects_executed') is not False
            or report.get('vm_restore_verified') is not False
            or not re.fullmatch(r'rehearsal-[0-9a-f]{32}', report.get('run_id', ''))):
        raise ValueError('Rehearsal identity mismatch')
    fixtures = report.get('fixtures', {})
    if set(fixtures) != {'baseline', 'variant'}:
        raise ValueError('Only the fixed harmless PE pair is allowed')
    monitoring = report.get('monitoring', {})
    if set(monitoring) != set(fixtures):
        raise ValueError('Independent monitor observations are missing')
    for key, value in fixtures.items():
        if value.get('pe', {}).get('managed') is not True or value.get('compile', {}).get('exit_code') != 0:
            raise ValueError('The harmless managed PE identity is missing')
        run = value['run']
        if run['functionality'] == 'PASS' and (run['exit_code'] != 0 or run['timed_out']
                or run['observed_sha256'] != run['expected_sha256']):
            raise ValueError('A process launch alone cannot establish functionality')
        scan = value['scan']
        if scan['av_status'] == 'NOT_DETECTED' and (scan['av_raw']['exit_code'] != 0
                or scan['bytes_unchanged'] is not True or scan['threat_history_known'] is not True
                or scan['relevant_threats']):
            raise ValueError('Incomplete negative AV observation')
    expected_files=[{'id':key,'bytes':value['pe']['bytes'],'sha256':value['pe']['sha256'],
                     'hash_verified':value['scan']['bytes_unchanged'],'av_status':value['scan']['av_status'],
                     'yara_status':value['scan']['yara_status'],'functionality':value['run']['functionality']}
                    for key,value in fixtures.items()]
    if report.get('files')!=expected_files:raise ValueError('Rehearsal table does not match its original observations')
    positive = report['positive_av_control']
    if positive['status'] == 'DETECTED' and not (positive['threats'] or any(v.get('id') == 1116 for v in positive['events'])):
        raise ValueError('Positive AV control needs an actual event or threat record')
    calculated = {
        'functionality_passed': all(v['run']['functionality'] == 'PASS' for v in fixtures.values()),
        'independent_file_writes_observed': all(v['owned_write_observed'] is True for v in monitoring.values()),
        'yara_positive_and_negative': fixtures['baseline']['scan']['yara_status'] == 'NOT_MATCHED'
            and fixtures['variant']['scan']['yara_status'] == 'MATCHED',
        'yara_invalid_rule_rejected': report['invalid_rule_control']['exit_code'] != 0,
        'defender_negative_controls': all(v['scan']['av_status'] == 'NOT_DETECTED' for v in fixtures.values()),
        'defender_eicar_observed': positive['status'] == 'DETECTED',
        'missing_input_not_negative': report['missing_input_control']['input_exists'] is False
            and report['missing_input_control']['status'] == 'NOT_RUN'}
    if report.get('checks') != calculated or report.get('all_checks_passed') is not all(calculated.values()):
        raise ValueError('Rehearsal checklist does not match observations')
    token = report['run_id'].removeprefix('rehearsal-')
    allowed = {'baseline.cs', 'baseline.exe', 'variant.cs', 'variant.exe', 'process-monitor.pml',
               'process-monitor.csv', 'rehearsal.yar', 'invalid-control.yar',
               'runs/baseline/observed.txt', 'runs/variant/observed.txt'}
    seen = set()
    total = 0
    for item in report.get('artifacts', []):
        prefix = 'work-' + token + '/'
        name = item.get('path', '')
        if not name.startswith(prefix) or name[len(prefix):] not in allowed or name in seen:
            raise ValueError('Rehearsal artifact is outside the fixed control workspace')
        if type(item.get('bytes')) is not int or not 0 <= item['bytes'] <= 128 * 1024 * 1024:
            raise ValueError('Rehearsal artifact exceeds limit')
        if not re.fullmatch(r'[0-9a-f]{64}', item.get('sha256', '')):
            raise ValueError('Rehearsal artifact has no hash')
        seen.add(name)
        total += item['bytes']
    if total > 300 * 1024 * 1024 or {n[len('work-' + token + '/'): ] for n in seen} != allowed:
        raise ValueError('Rehearsal artifact inventory is incomplete or exceeds budget')
    return report


def validated_result(path,workspace):
    path=Path(path);pending=LabPreparation.read(path.with_name('pending.json'))
    if Path(pending['host_root'])!=path.parent:raise ValueError('Foreign lab preparation report')
    report=validate_report(LabPreparation.read(path),pending)
    resolved=LabPreparation.read(path.with_name('resolved.json'))
    if resolved.get('report_sha256')!=hashlib.sha256(path.read_bytes()).hexdigest() or resolved.get('artifacts_verified') is not True:
        raise ValueError('Rehearsal transport proof is missing or changed')
    restore=path.with_name('restoration.json')
    if restore.is_file():
        proof=LabPreparation.read(restore)
        from vm_results import validate_cycle
        _,completion,evidence=validate_cycle(Path(proof['cycle_root'])/'report.json',workspace)
        if not completion or evidence.get('vm_restore_verified') is not True:
            raise ValueError('Rehearsal cold restore is not verified')
    return report
