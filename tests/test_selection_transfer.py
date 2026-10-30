"""Selected-byte transport and cold-restore checks in a disposable fake guest."""
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import shlex
import tempfile
import unittest
from unittest.mock import patch

import control_panel as panel
from guest_media import build_media
from guest_selection import verify_transfer
from vm_run_manager import VMRunManager
from vm_selection_transfer import execute, validated_result
from test_vm_run_manager import GuestFilesystem


class SelectionGuest(GuestFilesystem):
    def run(self,program,arguments,**kwargs):
        args=[v.strip('"') for v in shlex.split(arguments,posix=False)]
        if PureWindowsPath(args[0]).name!='guest_selection.py':return super().run(program,arguments,**kwargs)
        root=self.path(args[args.index('--root')+1])
        with patch('platform.system',return_value='Windows'),patch('platform.machine',return_value='ARM64'),patch.dict(os.environ,{'LOCALAPPDATA':str(root.parent)}):
            report=verify_transfer(root)
        (root/'report.json').write_text(json.dumps(report));return 0


class SelectionTransferTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();media=self.root/'media'
        build_media(media,['plain','marker','unicode']);self.guest=SelectionGuest(self.root)
        self.manager=VMRunManager(self.guest,media,self.root/'host',self.root/'vm.vmx',username='lab',credential='fixture-only',
            probe=lambda:{'network_config':'disconnected','sharing_config':'disabled','vm_free_bytes':4*1024**3})
        self.manager.cycle();self.catalog=panel.demo_catalog(self.root/'host')
        self.plan,_=panel.save_selection_plan(self.root/'host',self.catalog,['marker'],'one inert selected text')

    def test_only_selected_object_is_copied_and_report_survives_fake_disk_revert(self):
        original={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (Path(self.catalog['root'])/'controls').iterdir()}
        value=execute(self.manager,self.plan,self.catalog['root']);host=Path(value['host_root'])
        manifest=json.loads((host/'manifest.json').read_text())
        self.assertEqual(['marker'],[row['id'] for row in manifest['files']])
        kit=self.guest.path(json.loads((host/'pending.json').read_text())['guest_root'])
        self.assertEqual(1,len(list(kit.glob('object-*.bin'))))
        self.assertTrue(value['report']['all_verified']);self.assertFalse(value['report']['guest_execution'])
        self.assertFalse((host/'restoration.json').exists())
        self.manager.cycle()
        self.assertFalse(kit.exists());self.assertTrue((host/'restoration.json').exists())
        validated_result(host/'report.json',self.root/'host')
        self.assertEqual(original,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (Path(self.catalog['root'])/'controls').iterdir()})

    def test_changed_source_is_rejected_before_any_guest_copy(self):
        source=Path(self.catalog['root'])/'controls/marker.txt';source.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'bytes changed'):execute(self.manager,self.plan,self.catalog['root'])
        self.assertIsNone(self.manager.scanner_cleanup)
        self.assertFalse((self.root/'host/selection-transfers').exists())

    def test_missing_transferred_file_is_not_a_negative_scan_result(self):
        original=self.guest.copy_to
        def copy_to(source,destination):
            if destination.endswith('.bin'):return
            return original(source,destination)
        with patch.object(self.guest,'copy_to',side_effect=copy_to):value=execute(self.manager,self.plan,self.catalog['root'])
        self.assertFalse(value['report']['all_verified'])
        self.assertEqual('MISSING_INPUT',value['report']['files'][0]['status'])
        self.assertFalse(value['report']['av_run']);self.manager.cycle()


if __name__=='__main__':unittest.main()
