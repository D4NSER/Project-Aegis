"""Simulated tool setup proves license-state baseline and deferred-job recovery."""
import hashlib
import json
from pathlib import Path, PureWindowsPath
import shlex
import shutil
import tempfile
import unittest
from unittest.mock import patch

from guest_media import build_media
from test_vm_run_manager import GuestFilesystem
from vm_run_manager import VMRunManager


class LabGuest(GuestFilesystem):
    def __init__(self, root):
        super().__init__(root)
        (self.root/'Lab/Desktop').mkdir()

    def login(self, *args, **kwargs):
        return super().login(*args)

    def copy_from(self, source, destination, **kwargs):
        return super().copy_from(source, destination)

    def create_cold_snapshot(self, name):
        if self.snapshot.exists():
            shutil.rmtree(self.snapshot)  # disposable test-only guest snapshot
        super().create_cold_snapshot(name)

    def lab_inventory(self, kit, accepted=False):
        return {'platform':'Windows','architecture':'ARM64','settings_changed':False,
                'code_sha256':hashlib.sha256((kit/'src/guest_lab.py').read_bytes()).hexdigest(),
                'kit_sha256':hashlib.sha256((kit/'lab-kit.json').read_bytes()).hexdigest(),
                'compilers':[{'signature':{'status':'Valid'}}],
                'procmon':{'operator_license_accepted':accepted},'defender':{}}

    def run(self, program, arguments, **kwargs):
        args=[v.strip('"') for v in shlex.split(arguments,posix=False)]
        if PureWindowsPath(args[0]).name!='guest_lab.py':
            return super().run(program,arguments,**kwargs)
        kit=self.path(args[args.index('--kit')+1])
        output=self.path(args[args.index('--output')+1])
        output.write_text(json.dumps(self.lab_inventory(kit)))
        return 0


class LabPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        media=self.root/'media';build_media(media,['plain','marker','unicode'])
        self.guest=LabGuest(self.root)
        self.manager=VMRunManager(self.guest,media,self.root/'host',self.root/'vm.vmx',
            username='lab',credential='fixture-only',probe=lambda:{'network_config':'disconnected','sharing_config':'disabled'})
        self.manager.cycle();self.manager.environment['personal_accounts_separated']=True
        self.vendor=self.root/'vendor';self.vendor.mkdir()
        files={}
        for name in ('Procmon64a.exe','Eula.txt'):
            path=self.vendor/name;path.write_bytes(b'inert vendor fixture; never executed')
            files[name]={'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        (self.vendor/'provenance.json').write_text(json.dumps({'files':files}))
        yara=self.root/'yara.exe';yara.write_bytes(b'inert YARA fixture; never executed')
        self.manager.scanner={'yara_executable':str(yara),'yara_sha256':hashlib.sha256(yara.read_bytes()).hexdigest()}

    def test_pending_setup_survives_restart_and_blocks_a_restore_before_operator_review(self):
        self.manager.lab.prepare(self.vendor)
        with self.assertRaises(ValueError):self.manager.cycle()
        reopened=VMRunManager(self.guest,self.manager.media,self.root/'host',self.root/'vm.vmx',
            username='lab',credential='fixture-only',probe=self.manager.probe)
        reopened.deploy()
        self.assertIsNotNone(reopened.lab.pending)
        self.assertIsNone(reopened.lab.poll())
        self.assertFalse(reopened.summary()['vm_restore_verified'])

    def test_operator_approved_kit_is_in_new_baseline_but_later_work_is_removed_on_restore(self):
        previous=self.manager.session.root
        self.manager.lab.prepare(self.vendor)
        pending=self.manager.lab.pending
        kit=self.guest.path(pending['guest_root'])
        (kit/'operator-ready.json').write_text(json.dumps(self.guest.lab_inventory(kit,accepted=True)))
        result=self.manager.lab.poll()
        self.assertEqual('ready_for_rehearsal',result['stage'])
        self.assertNotEqual(previous,self.manager.session.root)
        self.assertTrue((self.manager.session.root/'baseline.json').is_file())
        self.assertTrue((self.guest.snapshot/kit.relative_to(self.guest.root)/'operator-ready.json').is_file())
        later=kit/'rehearsal-work.txt';later.write_text('test-only post-baseline work')
        self.manager.lab.defer();result=self.manager.cycle()
        self.assertTrue(result['vm_restore_verified'])
        self.assertFalse(later.exists())
        self.assertTrue((kit/'operator-ready.json').is_file())
        self.assertTrue((Path(pending['host_root'])/'deferred.json').is_file())

    def test_repeated_setup_does_not_block_verified_baseline_or_hide_rehearsal_failure(self):
        self.manager.lab.prepare(self.vendor)
        pending=self.manager.lab.pending;kit=self.guest.path(pending['guest_root'])
        (kit/'operator-ready.json').write_text(json.dumps(self.guest.lab_inventory(kit,accepted=True)))
        self.manager.lab.poll()
        duplicate={'error_type':'FileExistsError','message':'Lab report already exists'}
        (kit/'failure-operator-ready.json').write_text(json.dumps(duplicate))
        self.assertIsNone(self.manager.lab.poll())
        self.assertTrue((Path(pending['host_root'])/'duplicate-setup-reviewed.json').exists())
        (kit/'failure-rehearsal.json').write_text(json.dumps({'error_type':'ValueError','message':'control failed'}))
        with self.assertRaisesRegex(ValueError,'control failed'):self.manager.lab.poll()

    def test_start_request_needs_prepared_baseline_and_cannot_spawn_duplicate_launchers(self):
        self.manager.lab.prepare(self.vendor)
        with self.assertRaisesRegex(ValueError,'baseline'):self.manager.lab.request_rehearsal()
        kit=self.guest.path(self.manager.lab.pending['guest_root'])
        (kit/'operator-ready.json').write_text(json.dumps(self.guest.lab_inventory(kit,accepted=True)))
        self.manager.lab.poll()
        with patch.object(self.guest,'run',return_value=0) as launch:
            self.manager.lab.request_rehearsal()
            with self.assertRaisesRegex(ValueError,'already requested'):self.manager.lab.request_rehearsal()
            self.assertEqual(1,launch.call_count)
        self.assertTrue((kit/'rehearsal-interactive-requested.json').is_file())

    def test_interrupted_evidence_is_preserved_and_complete_report_precedes_restore(self):
        from test_guest_lab import report_fixture
        self.manager.lab.prepare(self.vendor)
        pending=self.manager.lab.pending;kit=self.guest.path(pending['guest_root'])
        host=Path(pending['host_root'])
        (kit/'operator-ready.json').write_text(json.dumps(self.guest.lab_inventory(kit,accepted=True)))
        self.manager.lab.poll()
        report,_=report_fixture();report['code_sha256']=pending['files']['src/guest_lab.py']
        report['kit_sha256']=pending['kit_sha256']
        for item in report['artifacts']:
            path=kit/item['path'];path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixture')
            item.update(bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        (kit/'rehearsal.json').write_text(json.dumps(report))
        damaged=host/'artifacts'/report['artifacts'][0]['path']
        damaged.parent.mkdir(parents=True);damaged.write_bytes(b'partial')
        value=self.manager.lab.poll()
        self.assertTrue(value['report']['all_checks_passed'])
        self.assertTrue((host/'resolved.json').is_file())
        self.assertFalse((host/'restoration.json').exists())
        self.assertEqual(b'partial',next(damaged.parent.glob('interrupted-*')).read_bytes())
        self.manager.cycle()
        audit=json.loads((host/'restored-artifacts.json').read_text())
        self.assertTrue(audit['all_rehearsal_files_absent'])
        self.assertTrue(audit['prepared_kit_preserved'])


if __name__=='__main__':unittest.main()
