"""Simulated guest filesystem exercises the entire automatic control/restore path."""
import copy
import hashlib
import json
from pathlib import Path,PureWindowsPath
import shlex
import shutil
import tempfile
import unittest
from unittest.mock import patch
import uuid

from test_guest_media import load_media,stage_and_run
from guest_media import build_media
from control_channel import encode_message
from guest_environment import personal_accounts_separated
from vm_run_manager import VMRunManager
from fusion_control import ManualBootRequired
from vm_results import validate_cycle
import control_panel


class GuestFilesystem:
    def __init__(self,root):
        self.root=root/'guest';self.root.mkdir();(self.root/'Lab').mkdir();self.snapshot=root/'snapshot';self.calls=[]
        self.power=True;self.logged_in=False;self.challenge=None;self.permission=None;self.response=''
        self.network=False;self.personal=False
        self.manual_boot=False
    def path(self,value):return self.root.joinpath(*PureWindowsPath(value).parts[1:])
    def login(self,*args):self.logged_in=True
    def environment(self,name):return 'C:\\Lab'
    def exists(self,path):return True if path.endswith('python.exe') else self.path(path).exists()
    def mkdir(self,path):self.path(path).mkdir()
    def copy_to(self,source,destination):shutil.copyfile(source,self.path(destination))
    def copy_from(self,source,destination):
        destination=Path(destination)
        if not destination.is_absolute() or not destination.parent.is_dir() or destination.exists():
            raise ValueError('Expected a new external host result')
        shutil.copyfile(self.path(source),destination)
    def stop_old_control_ui(self):pass
    def set_challenge(self,value):self.challenge=value
    def allow_inert_run(self,value):self.permission=value
    def read_control(self):return self.response
    def shutdown(self):self.calls.append('shutdown');self.power=False;self.logged_in=False
    def create_cold_snapshot(self,name):
        if self.power:raise AssertionError('Must be cold')
        self.calls.append('snapshot');shutil.copytree(self.root,self.snapshot)
    def power_on(self):
        self.calls.append('power_on')
        if self.manual_boot:raise ManualBootRequired('fixture manual boot')
        self.power=True
    def reopen(self):self.logged_in=False;return {'powered_on':self.power}
    def wait_tools(self):pass
    def revert_cold_snapshot(self,name):
        if self.power:raise AssertionError('Must be cold')
        self.calls.append('restore');shutil.rmtree(self.root);shutil.copytree(self.snapshot,self.root);self.logged_in=False
    def close(self):pass
    def run(self,program,arguments,**kwargs):
        if not self.logged_in:raise AssertionError('Login is required')
        args=[s.strip('"') for s in shlex.split(arguments,posix=False)]
        module=self.path(args[0])
        if module.name=='guest_environment.py':
            value={'schema':1,'current_sid':'lab-sid','accounts':[{'Enabled':True,'Source':'Local','SID':'lab-sid'}],
                   'profiles':[{'Special':False,'SID':'lab-sid'}],'platform':'Windows','architecture':'ARM64',
                   'collector_sha256':hashlib.sha256(module.read_bytes()).hexdigest(),'experiment_results':False}
            if self.personal:value['profiles'].append({'Special':False,'SID':'other-sid'})
            self.path(args[2]).write_text(json.dumps(value));return 0
        media=self.path(args[2]);_,transfer,request,manifest=load_media(media)
        work=self.root/'work';run=work/request['run_id'];report=None
        if args[4]=='control':
            if self.permission!=self.challenge:raise AssertionError('No permission')
            with patch('platform.system',return_value='Windows'),patch('platform.machine',return_value='ARM64'):
                stage_and_run(transfer,request,work)
        if (run/'guest-report.json').exists():report=json.loads((run/'guest-report.json').read_text())
        self.response=encode_message({'schema':1,'phase':'complete' if report else 'ready','challenge':self.challenge,
            'run_id':request['run_id'],'nonce':request['nonce'],'message_id':uuid.uuid4().hex,'platform':'Windows',
            'architecture':'ARM64','app_sha256':manifest['source_hashes']['guest_control_app.py'],
            'run_root_exists':run.exists(),'mutation_exists':(run/'mutation.json').exists(),'network_up':self.network,'report':report})
        return 0


class VMRunManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        media=self.root/'media';build_media(media,['plain','marker','unicode'])
        self.connection=GuestFilesystem(self.root)
        self.manager=VMRunManager(self.connection,media,self.root/'host',self.root/'test.vmx',username='lab',credential='fixture-only',
            probe=lambda:{'network_config':'disconnected','sharing_config':'disabled'})
    def test_three_complete_cycles_preserve_host_reports_and_prove_real_revert_in_fake_vm(self):
        for i in range(3):
            result=self.manager.cycle();self.assertTrue(result['vm_restore_verified'])
        cycles=list(self.manager.session.root.glob('cycle-*'))
        self.assertEqual(3,len(cycles));self.assertEqual(3,self.connection.calls.count('restore'))
        for cycle in cycles:
            self.assertTrue(json.loads((cycle/'completion.json').read_text())['vm_restore_verified'])
            self.assertFalse(json.loads((cycle/'report.json').read_text())['work_cleanup_performed'])
        self.assertEqual(1,self.connection.calls.count('snapshot'))
    def test_personal_profile_or_live_network_prevents_cold_baseline(self):
        self.connection.personal=True;self.manager.deploy();self.manager.status()
        with self.assertRaises(ValueError):self.manager.baseline()
        self.assertEqual([],self.connection.calls)
    def test_unknown_or_foreign_account_inventory_is_not_personal_separation(self):
        for value in ({},{'current_sid':'lab','accounts':[],'profiles':[]},
                      {'current_sid':'lab','accounts':[{'Enabled':True,'SID':'lab','Source':'MicrosoftAccount'}],'profiles':[{'SID':'lab','Special':False}]}):
            self.assertFalse(personal_accounts_separated(value))

    def test_restart_resumes_baseline_and_completed_reports_without_new_snapshot(self):
        self.manager.cycle()
        reopened=VMRunManager(self.connection,self.manager.media,self.root/'host',self.root/'test.vmx',
            username='lab',credential='fixture-only',probe=self.manager.probe)
        reopened.deploy();self.assertEqual('restored',reopened.session.state)
        reopened.cycle();self.assertEqual(1,self.connection.calls.count('snapshot'))
        self.assertEqual(2,len(list(reopened.session.root.glob('cycle-*'))))

    def test_failed_scanner_deployment_survives_restart_and_requires_a_later_cold_restore(self):
        self.manager.cycle();old_cycle=self.manager.session.cycle_root
        vendor=self.root/'vendor.exe';vendor.write_bytes(b'inert fake vendor; never executed')
        self.manager.scanner={'yara_executable':str(vendor),'yara_sha256':hashlib.sha256(vendor.read_bytes()).hexdigest()}
        with patch.object(self.connection,'run',return_value=1):
            with self.assertRaises(ValueError):self.manager.scan_controls()
        self.assertIsNotNone(self.manager.scanner_cleanup)
        self.assertFalse(self.manager.summary()['vm_restore_verified'])
        reopened=VMRunManager(self.connection,self.manager.media,self.root/'host',self.root/'test.vmx',
            username='lab',credential='fixture-only',probe=self.manager.probe)
        reopened.deploy();self.assertIsNotNone(reopened.scanner_cleanup)
        self.assertFalse(reopened.summary()['vm_restore_verified'])
        result=reopened.cycle();self.assertTrue(result['vm_restore_verified'])
        self.assertNotEqual(old_cycle,reopened.session.cycle_root)
        self.assertIsNone(reopened.scanner_cleanup)
        self.assertEqual(1,len(list((self.root/'host/scanner-checks').glob('cleanup-completed-*.json'))))

    def test_scanner_report_is_saved_on_host_before_the_new_cold_restore(self):
        from test_guest_scanners import ScannerControlTests
        self.manager.cycle()
        vendor=self.root/'vendor.exe';vendor.write_bytes(b'inert vendor fixture; never executed')
        digest=hashlib.sha256(vendor.read_bytes()).hexdigest()
        self.manager.scanner={'yara_executable':str(vendor),'yara_sha256':digest}
        original=self.connection.run
        def run(program,arguments,**kwargs):
            args=[s.strip('"') for s in shlex.split(arguments,posix=False)]
            module=self.connection.path(args[0])
            if module.name!='guest_scanners.py':return original(program,arguments,**kwargs)
            report=ScannerControlTests().fixture();report['elevated']=True
            report['code_sha256']=hashlib.sha256(module.read_bytes()).hexdigest()
            report['yara_executable_sha256']=digest
            for row in report['files']:
                row.update(av_status='NOT_DETECTED',av_reason='CUSTOM_SCAN_WITH_THREAT_HISTORY',av_exit_code=0)
            self.connection.path(args[args.index('--output')+1]).write_text(json.dumps(report))
            return 0
        with patch.object(self.connection,'run',side_effect=run):result=self.manager.scan_controls()
        path=Path(result['report_path'])
        self.assertEqual(self.root/'host/scanner-checks',path.parent)
        self.assertTrue(path.is_file());self.assertFalse(result['pending_elevation'])
        self.assertFalse(self.manager.summary()['vm_restore_verified'])
        self.manager.cycle();self.assertIsNone(self.manager.scanner_cleanup)
        self.assertTrue(path.is_file());self.assertTrue(self.manager.summary()['vm_restore_verified'])

    def test_manual_boot_phase_survives_restart_and_cannot_claim_restore_early(self):
        self.connection.manual_boot=True
        result=self.manager.cycle();self.assertEqual('awaiting_baseline_boot',result['state'])
        self.assertFalse(result['vm_restore_verified'])
        self.connection.power=True;self.manager.continue_after_boot()
        result=self.manager.cycle();self.assertEqual('awaiting_restore_boot',result['state'])
        self.assertFalse((self.manager.session.cycle_root/'completion.json').exists())
        self.connection.power=True
        reopened=VMRunManager(self.connection,self.manager.media,self.root/'host',self.root/'test.vmx',
            username='lab',credential='fixture-only',probe=self.manager.probe)
        reopened.deploy();self.assertEqual('restored',reopened.session.state)
        self.assertTrue((reopened.session.cycle_root/'completion.json').exists())

    def test_vm_results_export_has_original_report_and_independent_restore_evidence(self):
        self.manager.cycle();path=self.manager.session.cycle_root/'report.json'
        report,completion,evidence=validate_cycle(path,self.root/'host')
        self.assertIsNotNone(completion);self.assertFalse(report['vm_restore_verified'])
        self.assertTrue(evidence['vm_restore_verified']);self.assertIn(path,control_panel.result_paths(self.root/'host'))
        exported=control_panel.export_result(path,self.root/'host',self.root/'result.zip')
        import zipfile
        with zipfile.ZipFile(exported) as archive:
            hashes=json.loads(archive.read('sha256.json'))
            for name,digest in hashes.items():self.assertEqual(digest,hashlib.sha256(archive.read(name)).hexdigest())
            self.assertIn('completion.json',archive.namelist())
            self.assertNotIn(str(self.root).encode(),b''.join(archive.read(name) for name in archive.namelist()))
        completion['fresh_guest_proof']['mutation_exists']=True
        path.with_name('completion.json').write_text(json.dumps(completion))
        with self.assertRaises(ValueError):validate_cycle(path,self.root/'host')


if __name__=='__main__':unittest.main()
