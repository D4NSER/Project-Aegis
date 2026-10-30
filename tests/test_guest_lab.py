"""Harmless fixture and independent evidence checks; no Windows execution claim."""
import copy
import csv
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from guest_lab import fixture_source, monitor_evidence, run_fixture
from vm_lab_preparation import validate_report


def report_fixture():
    fixtures = {}
    for key in ('baseline', 'variant'):
        fixtures[key] = {'compile': {'exit_code': 0}, 'pe': {'managed': True, 'bytes': 20, 'sha256': 'a'*64},
            'run': {'functionality': 'PASS', 'exit_code': 0, 'timed_out': False,
                    'observed_sha256': 'b'*64, 'expected_sha256': 'b'*64},
            'scan': {'av_status': 'NOT_DETECTED', 'av_raw': {'exit_code': 0}, 'bytes_unchanged': True,
                     'threat_history_known': True, 'relevant_threats': [],
                     'yara_status': 'MATCHED' if key == 'variant' else 'NOT_MATCHED'}}
    names = ['baseline.cs','baseline.exe','variant.cs','variant.exe','process-monitor.pml','process-monitor.csv',
             'rehearsal.yar','invalid-control.yar','runs/baseline/observed.txt','runs/variant/observed.txt']
    report = {'schema': 1, 'mode': 'benign_pe_rehearsal', 'platform': 'Windows', 'architecture': 'ARM64',
        'run_id': 'rehearsal-'+'c'*32, 'code_sha256': 'd'*64, 'kit_sha256': 'e'*64,
        'experiment_results': False, 'settings_changed': False, 'research_objects_executed': False,
        'vm_restore_verified': False, 'fixtures': fixtures,
        'monitoring': {key: {'owned_write_observed': True} for key in fixtures},
        'files': [{'id':key,'bytes':value['pe']['bytes'],'sha256':value['pe']['sha256'],
                   'hash_verified':True,'av_status':'NOT_DETECTED','yara_status':value['scan']['yara_status'],
                   'functionality':'PASS'} for key,value in fixtures.items()],
        'positive_av_control': {'status':'DETECTED','threats':[{'ThreatID':1}],'events':[]},
        'invalid_rule_control': {'exit_code':1}, 'missing_input_control': {'input_exists':False,'status':'NOT_RUN'},
        'artifacts':[{'path':'work-'+'c'*32+'/'+name,'sha256':'f'*64,'bytes':1} for name in names],
        'checks': {key:True for key in ('functionality_passed','independent_file_writes_observed',
            'yara_positive_and_negative','yara_invalid_rule_rejected','defender_negative_controls',
            'defender_eicar_observed','missing_input_not_negative')}, 'all_checks_passed':True}
    return report, {'files':{'src/guest_lab.py':'d'*64},'kit_sha256':'e'*64}


class GuestLabTests(unittest.TestCase):
    def test_fixture_generation_has_two_fixed_labels_and_an_owned_write_guard(self):
        source=fixture_source('AEGIS_REHEARSAL_BASELINE',Path('owned-runs'))
        self.assertIn('File.WriteAllText',source);self.assertIn('Path.GetDirectoryName(root)',source)
        self.assertNotIn('Process.Start',source)
        with self.assertRaises(ValueError):fixture_source('arbitrary input',Path('owned-runs'))

    def test_successful_process_without_the_required_effect_is_not_functionality(self):
        token='a'*32
        with tempfile.TemporaryDirectory() as temporary:
            destination=Path(temporary)
            process=Mock();process.pid=123;process.returncode=0
            process.communicate.return_value=('AEGIS_REHEARSAL_BASELINE:'+token+'\n','')
            with patch('guest_lab.subprocess.Popen',return_value=process):
                value=run_fixture('owned.exe',destination,token,'AEGIS_REHEARSAL_BASELINE')
                self.assertEqual('FAIL',value['functionality'])
                (destination/'observed.txt').write_bytes(('AEGIS_OK:'+token).encode())
                value=run_fixture('owned.exe',destination,token,'AEGIS_REHEARSAL_BASELINE')
                self.assertEqual('PASS',value['functionality'])
            process.communicate.side_effect=[subprocess.TimeoutExpired('fixture',8),('','')]
            with patch('guest_lab.subprocess.Popen',return_value=process):
                value=run_fixture('owned.exe',destination,token,'AEGIS_REHEARSAL_BASELINE')
                self.assertEqual('INCONCLUSIVE',value['functionality']);process.kill.assert_called_once()

    def test_procmon_write_needs_matching_pid_path_operation_and_success(self):
        fixtures={'baseline':{'run':{'pid':11,'observed_path':'owned/baseline.txt'}},
                  'variant':{'run':{'pid':22,'observed_path':'owned/variant.txt'}}}
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'trace.csv'
            with path.open('w',newline='') as stream:
                writer=csv.writer(stream);writer.writerow(['PID','Operation','Path','Result'])
                writer.writerows([[99,'WriteFile','owned/baseline.txt','SUCCESS'],
                    [11,'WriteFile','foreign.txt','SUCCESS'],[11,'WriteFile','owned/baseline.txt','ACCESS DENIED'],
                    [22,'WriteFile','OWNED/VARIANT.TXT','SUCCESS']])
            result=monitor_evidence(path,fixtures)
            self.assertFalse(result['baseline']['owned_write_observed'])
            self.assertTrue(result['variant']['owned_write_observed'])

    def test_host_rejects_invented_success_positive_without_evidence_and_export_of_extra_files(self):
        report,pending=report_fixture();validate_report(report,pending)
        changes=[lambda v:v.update(vm_restore_verified=True),
                 lambda v:v['positive_av_control'].update(threats=[]),
                 lambda v:v['fixtures']['baseline']['run'].update(observed_sha256='0'*64),
                 lambda v:v['monitoring']['baseline'].update(owned_write_observed=False),
                 lambda v:v['artifacts'][0].update(path='../outside.txt'),
                 lambda v:v['missing_input_control'].update(status='NOT_DETECTED')]
        for change in changes:
            value=copy.deepcopy(report);change(value)
            with self.assertRaises(ValueError):validate_report(value,pending)


if __name__=='__main__':unittest.main()
