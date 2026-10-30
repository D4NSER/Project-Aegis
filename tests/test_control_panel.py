"""Behaviour checks for host catalogue, exports and honest VM observations."""
import csv
import hashlib
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import control_panel as panel
from control_workspace import ControlWorkspace


class PanelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.workspace = self.base / 'panel'
        self.controls = ControlWorkspace(self.workspace)
        self.collection = self.base / 'collection'
        (self.collection / 'catalog').mkdir(parents=True)
        (self.collection / 'controls').mkdir()
        self.sources = [dict(zip(panel.SOURCE_FIELDS, ['s1', 'Synthetic controls', 'https://example.org',
                         '1', '2026-10-28', 'Test fixture', 'DOCUMENTED']))]
        self.objects, self.selection = [], []
        for i, content in enumerate([b'inert original text', b'inert modified text', b'other project'], 1):
            name = 'controls/control{}.txt'.format(i)
            (self.collection / name).write_bytes(content)
            self.objects.append(dict(zip(panel.OBJECT_FIELDS, ['c' + str(i), 's1', name,
                                hashlib.sha256(content).hexdigest(), str(len(content)), 'text', 'none',
                                'p1' if i < 3 else 'p2', 'f1' if i < 3 else '', 'c1' if i == 2 else '',
                                'control', 'Synthetic inert fixture', 'REVIEWED'])))
            self.selection.append(dict(zip(panel.SELECTION_FIELDS,
                                  ['c' + str(i), 'evaluation', 'Synthetic fixture', 'test-v1'])))
        self.write_tables()

    def tearDown(self):
        self.temp.cleanup()

    def write_tables(self):
        for name, fields, rows in [('sources', panel.SOURCE_FIELDS, self.sources),
                                   ('objects', panel.OBJECT_FIELDS, self.objects),
                                   ('selection', panel.SELECTION_FIELDS, self.selection)]:
            with (self.collection / 'catalog' / (name + '.csv')).open('w', encoding='utf-8', newline='') as stream:
                writer = csv.DictWriter(stream, fields)
                writer.writeheader()
                writer.writerows(rows)

    def catalog(self):
        return panel.load_catalog(self.collection, self.workspace)

    def test_only_selected_objects_hashed_and_catalog_unchanged(self):
        catalog = self.catalog()
        before = {p: p.read_bytes() for p in self.collection.rglob('*') if p.is_file()}
        # Unselected missing content must not be read after metadata load.
        (self.collection / self.objects[2]['relative_path']).unlink()
        path, report = panel.save_catalog_check(self.workspace, catalog, ['c1'])
        self.assertTrue(report['all_verified'])
        self.assertEqual(['c1'], [r['object_id'] for r in report['files']])
        self.assertFalse(report['experiment_results'])
        self.assertTrue(path.is_file())
        for source, content in before.items():
            if source.exists():
                self.assertEqual(content, source.read_bytes())

    def test_changed_selected_file_is_recorded_and_plan_refused(self):
        catalog = self.catalog()
        (self.collection / self.objects[0]['relative_path']).write_bytes(b'changed')
        _, report = panel.save_catalog_check(self.workspace, catalog, ['c1'])
        self.assertFalse(report['all_verified'])
        with self.assertRaisesRegex(ValueError, 'nesutampa'):
            panel.save_selection_plan(self.workspace, catalog, ['c1'], 'plan')
        self.assertFalse((self.workspace / 'plans').exists())

    def test_plan_preserves_lineage_and_reports_no_execution(self):
        path, plan = panel.save_selection_plan(self.workspace, self.catalog(), ['c1', 'c2'], 'Pirmas planas')
        self.assertEqual('PLAN_ONLY', plan['status'])
        self.assertFalse(plan['guest_execution'])
        self.assertFalse(plan['experiment_results'])
        self.assertFalse(plan['vm_restore_verified'])
        self.assertEqual(['c1', 'c2'], [r['object_id'] for r in plan['files']])
        self.assertEqual('Tik planas', panel.result_summary(path, self.workspace)['state'])
        with self.assertRaisesRegex(ValueError, 'originalą'):
            panel.save_selection_plan(self.workspace, self.catalog(), ['c2'], 'bad')

    def test_cross_split_projects_and_missing_source_rejected(self):
        self.selection[1]['split'] = 'calibration'
        self.write_tables()
        with self.assertRaisesRegex(ValueError, 'abi'):
            self.catalog()
        self.selection[1]['split'] = 'evaluation'
        self.objects[0]['source_id'] = 'missing'
        self.write_tables()
        with self.assertRaises(ValueError):
            self.catalog()

    def test_traversal_and_symlink_objects_refused(self):
        for name in ('../outside.txt', '/tmp/outside', 'C:\\outside', 'controls/../bad', 'controls//bad'):
            self.objects[0]['relative_path'] = name
            self.write_tables()
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.catalog()
        self.objects[0]['relative_path'] = 'controls/control1.txt'
        self.write_tables()
        target = self.collection / self.objects[0]['relative_path']
        target.unlink()
        target.symlink_to(self.collection / self.objects[1]['relative_path'])
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            self.catalog()

    def test_windows_drive_path_refused_even_when_it_exists_on_posix(self):
        (self.collection / 'C:').mkdir()
        (self.collection / 'C:/outside.txt').write_bytes(b'inert original text')
        self.objects[0]['relative_path'] = 'C:/outside.txt'
        self.write_tables()
        with self.assertRaisesRegex(ValueError, 'relative'):
            self.catalog()

    def test_changed_registry_stops_plan_and_mixed_protocols_refused(self):
        catalog = self.catalog()
        self.selection[0]['selection_reason'] = 'changed'
        self.write_tables()
        with self.assertRaisesRegex(ValueError, 'pasikeitė'):
            panel.save_selection_plan(self.workspace, catalog, ['c1'], 'plan')
        with self.assertRaisesRegex(ValueError, 'pasikeitė'):
            panel.save_catalog_check(self.workspace, catalog, ['c1'])
        self.selection[1]['protocol_version'] = 'other'
        self.write_tables()
        with self.assertRaisesRegex(ValueError, 'protokolo'):
            panel.save_selection_plan(self.workspace, self.catalog(), ['c1', 'c2'], 'plan')

    def test_export_contains_original_results_and_verifiable_hashes(self):
        folder, report = self.controls.run(['plain', 'marker'], 'GUI patikra')
        destination = self.base / 'export.zip'
        panel.export_result(folder / 'report.json', self.workspace, destination)
        with zipfile.ZipFile(destination) as archive:
            self.assertEqual(report, json.loads(archive.read('report.json')))
            self.assertEqual(True, json.loads(archive.read('completion.json'))['work_cleanup_verified'])
            for name, sha in json.loads(archive.read('sha256.json')).items():
                self.assertEqual(sha, hashlib.sha256(archive.read(name)).hexdigest())
            self.assertIn(b'NOT_RUN', archive.read('files.csv'))
        with self.assertRaises(ValueError):
            panel.export_result(folder / 'report.json', self.workspace, destination)
        self.assertTrue(destination.is_file())

    def test_csv_formula_identifiers_remain_text_in_export(self):
        self.objects[0]['object_id'] = '=1+1'
        self.objects[1]['parent_id'] = '=1+1'
        self.selection[0]['object_id'] = '=1+1'
        self.write_tables()
        path, _ = panel.save_catalog_check(self.workspace, self.catalog(), ['=1+1'])
        target = self.base / 'formula.zip'
        panel.export_result(path, self.workspace, target)
        with zipfile.ZipFile(target) as archive:
            rows = list(csv.DictReader(archive.read('files.csv').decode('utf-8-sig').splitlines()))
        self.assertEqual("'=1+1", rows[0]['id'])

    def test_export_never_writes_into_selected_collection(self):
        folder, _ = self.controls.run(['plain'])
        target = self.collection / 'export.zip'
        with self.assertRaisesRegex(ValueError, 'kolekciją'):
            panel.export_result(folder / 'report.json', self.workspace, target, [self.collection])
        self.assertFalse(target.exists())

    def test_budget_reserves_image_once_even_for_relative_workspace(self):
        runtime = self.base / 'runtime'
        workspace = runtime / 'panel'
        workspace.mkdir(parents=True)
        image = runtime / 'Storage.sparsebundle'
        image.mkdir()
        (image / 'Info.plist').write_bytes(plistlib.dumps({'size': 39000000000}))
        (image / 'band').write_bytes(b'x' * 1024 * 1024)
        fusion = self.base / 'Fusion.app' / 'Contents' / 'Library'
        fusion.mkdir(parents=True)
        (fusion / 'tool').write_bytes(b'tool')
        installer = self.base / 'installer.iso'
        installer.write_bytes(b'installer')
        config = {'disk_image': str(image), 'installer_path': str(installer), 'mac_lab_budget_bytes': 50000000000}
        import os
        with patch.object(panel, 'FUSION', fusion):
            absolute = panel.budget_snapshot(workspace, config)
            relative = panel.budget_snapshot(os.path.relpath(workspace), config)
        self.assertEqual(absolute, relative)
        self.assertLess(absolute['reserved_bytes'], 39000000000 + 1024 * 1024)

    def test_bad_result_and_symlink_export_inputs_rejected(self):
        folder, _ = self.controls.run(['plain'])
        (folder / 'completion.json').write_text('{broken')
        self.assertFalse(panel.cleanup_confirmed(folder / 'report.json'))
        self.assertEqual('Reikia patikros', panel.result_summary(folder / 'report.json', self.workspace)['state'])
        (folder / 'report.json').unlink()
        other = self.base / 'other.json'
        other.write_text('{}')
        (folder / 'report.json').symlink_to(other)
        with self.assertRaises(ValueError):
            panel.export_result(folder / 'report.json', self.workspace, self.base / 'bad.zip')

    def test_result_output_symlink_and_overlapping_collection_refused(self):
        (self.workspace / 'catalog-checks').symlink_to(self.collection, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'nuoroda'):
            panel.save_catalog_check(self.workspace, self.catalog(), ['c1'])
        with self.assertRaisesRegex(ValueError, 'atskiri'):
            panel.load_catalog(self.base, self.workspace)

    def test_settings_roundtrip_and_secret_fields_refused(self):
        value = {'vm_bundle': '/Volumes/Lab/Control.vmwarevm', 'collection_root': ''}
        panel.save_settings(self.workspace, value)
        self.assertEqual(value, panel.load_settings(self.workspace))
        with self.assertRaises(ValueError):
            panel.save_settings(self.workspace, {'password': 'not-a-real-credential'})
        self.assertEqual(value, panel.load_settings(self.workspace))

    def test_demo_catalog_works_without_hdd_and_does_not_overwrite_changes(self):
        first = panel.demo_catalog(self.workspace)
        second = panel.demo_catalog(self.workspace)
        self.assertEqual(first['catalog_sha256'], second['catalog_sha256'])
        self.assertTrue(all(r['verified'] for r in panel.verify_selected(first, ['plain', 'marker'])))
        target = Path(first['root']) / 'controls/plain.txt'
        target.write_text('changed')
        with self.assertRaisesRegex(ValueError, 'pakeistas'):
            panel.demo_catalog(self.workspace)
        self.assertEqual('changed', target.read_text())

    def test_corrupt_result_identity_or_rows_are_rejected(self):
        folder, value = self.controls.run(['plain'])
        path = folder / 'report.json'
        value['files'] = ['not an object']
        path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            panel.validated_result(path, self.workspace)
        value['files'] = []
        value['run_id'] = '../other'
        path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            panel.validated_result(path, self.workspace)
    def vm_config(self):
        bundle = self.base / 'Control.vmwarevm'
        bundle.mkdir()
        (bundle / 'Control.vmx').write_text('memsize = "6144"\nethernet0.present = "TRUE"\n'
                                          'ethernet0.connectionType = "nat"\n'
                                          'isolation.tools.copy.disable = "TRUE"\n'
                                          'isolation.tools.paste.disable = "TRUE"\n'
                                          'isolation.tools.dnd.disable = "TRUE"\n')
        return {'vm_bundle': str(bundle)}, bundle

    def test_probe_runtime_is_independent_of_old_preparation_record(self):
        config, bundle = self.vm_config()
        config['power_state'] = 'stopped'
        def command(args, timeout=8):
            return subprocess.CompletedProcess(args, 0, 'Total running VMs: 1\n' + str(bundle / 'Control.vmx') + '\n', '')
        with patch.object(panel.sys, 'platform', 'darwin'):
            state = panel.probe_vm(config, command)
        self.assertEqual('running', state['state'])
        self.assertEqual('connected_or_unspecified', state['network_config'])
        self.assertEqual('disabled', state['sharing_config'])
        self.assertEqual(6 * 1024**3, state['memory_bytes'])
        self.assertGreater(state['vm_free_bytes'], 0)

    def test_probe_failure_is_unknown_and_other_vm_does_not_count(self):
        config, _ = self.vm_config()
        with patch.object(panel.sys, 'platform', 'darwin'):
            failed = panel.probe_vm(config, lambda args: subprocess.CompletedProcess(args, 1, '', 'failure'))
            other = panel.probe_vm(config, lambda args: subprocess.CompletedProcess(args, 0, 'Total running VMs: 1\n/other.vmx\n', ''))
        self.assertEqual('unknown', failed['state'])
        self.assertEqual('stopped', other['state'])

    def test_unattached_image_does_not_report_host_space_as_vm_space(self):
        config, bundle = self.vm_config()
        image = self.base / 'Storage.sparsebundle'
        image.mkdir()
        (image / 'Info.plist').write_bytes(plistlib.dumps({'size': 39000000000}))
        config['disk_image'] = str(image)
        def command(args, timeout=8):
            return subprocess.CompletedProcess(args, 0, plistlib.dumps({'images': []}).decode()
                                               if args[0] == 'hdiutil' else 'Total running VMs: 0\n', '')
        with patch.object(panel.sys, 'platform', 'darwin'):
            state = panel.probe_vm(config, command)
        self.assertFalse(state['image_attached'])
        self.assertIsNone(state['vm_free_bytes'])
        self.assertEqual(39000000000, state['image_limit_bytes'])


if __name__ == '__main__':
    unittest.main()
