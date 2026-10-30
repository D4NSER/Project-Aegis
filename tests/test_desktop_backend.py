"""Native bridge guards and reuse of validated catalogue/result operations."""
from pathlib import Path
from types import SimpleNamespace
import json
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from html.parser import HTMLParser

from desktop_backend import DesktopBackend,NativeSession


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.base=Path(self.temp.name)
        self.status=self.base/'lab.json';self.status.write_text('{}')
        self.bridge=DesktopBackend(self.base/'panel',self.status)
    def tearDown(self):self.temp.cleanup()

    def test_selected_file_plan_and_export_keep_identity_through_bridge(self):
        catalogue=self.bridge.dispatch('demo',{})
        self.assertEqual(3,len(catalogue['objects']))
        result=self.bridge.dispatch('plan',{'selected':['marker'],'title':'Native UI fixture'})
        self.assertEqual(['marker'],[r['object_id'] for r in result['report']['files']])
        self.assertFalse(result['report']['guest_execution'])
        row=next(r for r in result['results'] if r['id']==result['report']['run_id'])
        loaded=self.bridge.dispatch('result',{'key':row['key']})
        self.assertEqual(result['report'],loaded['report'])
        destination=self.base/'export.zip'
        self.bridge.dispatch('export',{'key':row['key'],'path':str(destination)})
        with zipfile.ZipFile(destination) as archive:
            self.assertTrue(any(name.endswith('.json') for name in archive.namelist()))
        with self.assertRaises(ValueError):self.bridge.dispatch('result',{'key':'../../lab.json'})
        with self.assertRaises(ValueError):self.bridge.dispatch('open_result',{'key':str(self.status)})

    def test_unknown_actions_and_unselected_files_are_rejected(self):
        with self.assertRaises(ValueError):self.bridge.dispatch('run_arbitrary_program',{})
        with self.assertRaises(ValueError):self.bridge.dispatch('lab_action',{'action':'cycle'})
        self.bridge.dispatch('demo',{})
        with self.assertRaises(ValueError):self.bridge.dispatch('catalog_check',{'selected':[]})
        with self.assertRaises(ValueError):self.bridge.dispatch('catalog_check',{'selected':['not-in-catalogue']})

    @patch.object(NativeSession,'worker',lambda self:None)
    def test_native_session_preserves_restore_lock_and_environment_gates(self):
        session=NativeSession(self.base/'panel',{'yara_executable':'configured','procmon_vendor_root':'configured'})
        session.submit('connect',('fixture-vm-credential','fixture-lab-credential'))
        self.assertTrue(session.snapshot()['busy'])
        session.actions.get_nowait()
        env={'architecture':'ARM64','python_version':'fixture','network_up':False,'personal_accounts_separated':True}
        session.manager=SimpleNamespace(environment=env,session=SimpleNamespace(state='restored'),
            connection=SimpleNamespace(pending=False),pending_scan=None,scanner_cleanup=None,lab=SimpleNamespace(pending=None))
        session.events.put(('connected',env));session.tick()
        snapshot=session.snapshot()
        self.assertIn('cycle',snapshot['allowed'])
        self.assertNotIn('credential',json.dumps(snapshot))
        session.submit('cycle')
        with self.assertRaises(ValueError):session.submit('cycle')
        session.events.put(('transfer_restoring',{}));session.tick()
        self.assertTrue(session.snapshot()['busy'])
        self.assertEqual([],session.snapshot()['allowed'])
        session.events.put(('done',{'state':'restored','vm_restore_verified':True}));session.tick()
        self.assertFalse(session.snapshot()['busy'])
        env['network_up']=True
        with self.assertRaises(ValueError):session.submit('cycle')
        self.assertNotIn('scan',session.snapshot()['allowed'])
        session.disconnect()

    def test_local_document_assets_satisfy_its_no_network_policy(self):
        class Document(HTMLParser):
            def __init__(self):super().__init__();self.resources=[];self.policy=None;self.inline=[]
            def handle_starttag(self,tag,attrs):
                fields=dict(attrs)
                if tag=='meta' and fields.get('http-equiv')=='Content-Security-Policy':self.policy=fields['content']
                if tag=='script':self.resources.append(fields.get('src'))
                if tag=='link':self.resources.append(fields.get('href'))
                self.inline.extend(k for k,v in attrs if k=='style' or k.startswith('on'))
        folder=Path(__file__).resolve().parents[1]/'src/desktop_ui'
        document=Document();document.feed((folder/'index.html').read_text())
        self.assertEqual(['app.css','app.js'],document.resources)
        self.assertIn("connect-src 'none'",document.policy)
        self.assertIn("frame-src 'none'",document.policy)
        self.assertNotIn('unsafe-inline',document.policy)
        self.assertEqual([],document.inline)
        for name in document.resources:self.assertTrue((folder/name).is_file())


if __name__=='__main__':unittest.main()
