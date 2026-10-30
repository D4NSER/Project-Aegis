"""Scanner interpretation never equates Defender exit zero with a negative."""
from pathlib import Path
import subprocess
import sys
import unittest
import copy,hashlib,json,tempfile,zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from guest_scanners import interpret_defender,yara_status,validate_report,RULE
from control_workspace import CONTROLS,MARKER
import control_panel


class ScannerControlTests(unittest.TestCase):
    def fixture(self):
        state={'AMEngineVersion':'1.0','AMProductVersion':'1.0','AntivirusEnabled':True,'RealTimeProtectionEnabled':True,
               'IsTamperProtected':True,'AntivirusSignatureVersion':'1.0'}
        return {'schema':1,'mode':'scanner_inert_control','experiment_results':False,'run_id':'scan-'+'a'*32,
            'created_at_utc':'2026-10-29T00:00:00+00:00','platform':'Windows','architecture':'ARM64','code_sha256':'c'*64,
            'yara_version':'4.6.0','yara_executable_sha256':'d'*64,'yara_machine':0x8664,'rule_sha256':hashlib.sha256(RULE).hexdigest(),
            'defender_before':state,'defender_after':copy.deepcopy(state),'elevated':False,'vm_restore_verified':False,
            'work_cleanup_performed':False,'files':[{'id':key,'bytes':len(content),'sha256':hashlib.sha256(content).hexdigest(),
              'yara_status':'MATCHED' if MARKER in content else 'NOT_MATCHED','yara_expected_match':MARKER in content,
              'av_status':'NOT_RUN','av_reason':'ELEVATION_REQUIRED','av_exit_code':None} for key,(_,content) in CONTROLS.items()]}

    def test_defender_needs_threat_history_unchanged_content_and_a_stable_enabled_engine(self):
        self.assertEqual('NOT_DETECTED',interpret_defender(0,True,True,[],True,True))
        cases=[(0,False,True,[],True,True),(0,True,False,[],True,True),(0,True,True,[],False,True),
               (0,True,True,[],True,False),(2,True,True,[],True,True)]
        for args in cases:
            with self.subTest(args=args):self.assertEqual('INCONCLUSIVE',interpret_defender(*args))
        self.assertEqual('DETECTED',interpret_defender(0,False,True,[{'ThreatID':1}],True,True))
    def test_yara_rejects_unknown_rule_output_and_process_failure(self):
        target=Path('inert-marker.txt')
        def result(code,stdout):return subprocess.CompletedProcess([],code,stdout,'')
        self.assertEqual('MATCHED',yara_status(result(0,'Aegis_Control_Marker '+str(target)+'\n'),target))
        self.assertEqual('NOT_MATCHED',yara_status(result(0,''),target))
        for value in (result(1,''),result(0,'unknown '+str(target)),result(0,'Aegis_Control_Marker different.txt')):
            self.assertEqual('ERROR',yara_status(value,target))

    def test_scanner_metadata_rejects_foreign_code_false_restore_and_unperformed_av_claims(self):
        original=self.fixture();self.assertEqual(original,validate_report(original,'c'*64,'d'*64))
        for key,replacement in (('schema',True),('code_sha256','0'*64),('vm_restore_verified',True),('experiment_results',True)):
            value=copy.deepcopy(original);value[key]=replacement
            with self.subTest(key=key),self.assertRaises(ValueError):validate_report(value,'c'*64,'d'*64)
        value=copy.deepcopy(original);value['files'][0]['av_status']='NOT_DETECTED'
        with self.assertRaises(ValueError):validate_report(value,'c'*64,'d'*64)
        value=copy.deepcopy(original);value['unrecognized']='extra'
        with self.assertRaises(ValueError):validate_report(value,'c'*64,'d'*64)

    def test_scanner_export_preserves_unknown_av_and_yara_control_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();folder=root/'scanner-checks';folder.mkdir();path=folder/('scan-'+'b'*32+'.json')
            path.write_text(json.dumps(self.fixture()));path.with_name(path.stem+'.identity.json').write_text(json.dumps({'code_sha256':'c'*64,'yara_sha256':'d'*64}))
            self.assertEqual([path],control_panel.result_paths(root))
            item=control_panel.result_summary(path,root);self.assertIn('Defender nepatvirtintas',item['state'])
            target=control_panel.export_result(path,root,root/'scanner.zip')
            with zipfile.ZipFile(target) as archive:
                self.assertEqual('NOT_RUN',json.loads(archive.read('report.json'))['files'][0]['av_status'])
                self.assertIn('nekenkėjiškais',archive.read('SKAITYK.txt').decode())


if __name__=='__main__':unittest.main()
