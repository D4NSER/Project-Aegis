"""Host panel services. Read-only collection access; no sample execution."""
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlparse
import uuid
import zipfile

from aegis import digest, external_path, local_file, read_csv, SHA256
from control_workspace import CONTROLS, write_json

FUSION = Path('/Applications/VMware Fusion.app/Contents/Library')
SOURCE_FIELDS = ('source_id', 'title', 'url', 'version', 'retrieved_at', 'usage_terms', 'status')
OBJECT_FIELDS = ('object_id', 'source_id', 'relative_path', 'sha256', 'bytes', 'format',
                 'architecture', 'project_id', 'family_id', 'parent_id', 'label',
                 'label_basis', 'eligibility_status')
SELECTION_FIELDS = ('object_id', 'split', 'selection_reason', 'protocol_version')


def now():
    return datetime.now(timezone.utc).isoformat()


def read_json(path, limit=1024 * 1024):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > limit:
        raise ValueError('Netinkamas arba per didelis JSON failas: ' + path.name)
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict):
        raise ValueError('Tikėtasi JSON objekto: ' + path.name)
    return value


def save_settings(workspace, value):
    root = external_path(workspace)
    root.mkdir(parents=True, exist_ok=True)
    target = root / 'panel-settings.json'
    if target.is_symlink():
        raise ValueError('Nustatymų failas negali būti nuoroda.')
    allowed = {'collection_root', 'vm_bundle', 'disk_image'}
    if set(value) - allowed or any(not isinstance(v, str) for v in value.values()):
        raise ValueError('Netinkami programos nustatymai.')
    fd, temporary = tempfile.mkstemp(prefix='.settings-', dir=root)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_settings(workspace):
    path = Path(workspace) / 'panel-settings.json'
    return read_json(path) if path.exists() else {}


def run_command(args, timeout=8):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=timeout, check=False)


def probe_vm(config, command=run_command):
    """Runtime membership comes from vmrun; VMX flags remain configuration only."""
    result = {'checked_at': now(), 'state': 'unconfigured', 'error': None,
              'bundle_exists': False, 'vm_free_bytes': None, 'host_free_bytes': None,
              'memory_bytes': None, 'network_config': 'unknown', 'sharing_config': 'unknown',
              'image_attached': False, 'image_limit_bytes': None}
    if sys.platform != 'darwin':
        result['error'] = 'Fusion valdymas prieinamas tik Mac.'
        return result
    bundle = Path(config.get('vm_bundle', ''))
    if not config.get('vm_bundle') or bundle.suffix != '.vmwarevm':
        return result
    result['host_free_bytes'] = shutil.disk_usage(Path.home()).free
    image_name = config.get('disk_image', '')
    if image_name:
        image = Path(image_name)
        if image.is_dir() and not image.is_symlink():
            try:
                result['image_limit_bytes'] = plistlib.loads((image / 'Info.plist').read_bytes()).get('size')
                info = command(['hdiutil', 'info', '-plist'])
                if info.returncode == 0:
                    for item in plistlib.loads(info.stdout.encode()).get('images', []):
                        if Path(item.get('image-path', '')) == image:
                            for entity in item.get('system-entities', []):
                                mount = entity.get('mount-point')
                                if mount and bundle.parent == Path(mount):
                                    result['image_attached'] = True
            except (OSError, ValueError, plistlib.InvalidFileException, subprocess.TimeoutExpired):
                result['error'] = 'Nepavyko patikrinti VM atvaizdo prijungimo.'
    result['bundle_exists'] = bundle.is_dir() and not bundle.is_symlink()
    if not result['bundle_exists']:
        result['state'] = 'storage_unavailable'
        return result
    if result['image_attached'] or not image_name:
        result['vm_free_bytes'] = shutil.disk_usage(bundle).free
    vmx_files = list(bundle.glob('*.vmx'))
    if len(vmx_files) != 1 or vmx_files[0].is_symlink():
        result.update(state='unknown', error='VM pakete turi būti vienas VMX failas.')
        return result
    vmx = vmx_files[0]
    flags = {}
    for line in vmx.read_text(encoding='utf-8').splitlines():
        match = re.fullmatch(r'([\w.]+)\s*=\s*"([^"\n]*)"', line.strip())
        if match:
            key, value = match.groups()
            if key == 'memsize' or key.startswith(('ethernet', 'isolation.tools.', 'sharedFolder')):
                flags[key] = value
    try:
        result['memory_bytes'] = int(flags.get('memsize', '0')) * 1024 * 1024 or None
    except ValueError:
        pass
    present = {k: v for k, v in flags.items() if re.fullmatch(r'ethernet\d+\.present', k)}
    adapters = {k.split('.')[0] for k in present if present[k].upper() == 'TRUE'}
    if present:
        result['network_config'] = ('disconnected' if not adapters or all(
            flags.get(a + '.startConnected', '').upper() == 'FALSE' for a in adapters) else 'connected_or_unspecified')
    shared = any(k.startswith('sharedFolder') and k.endswith('.enabled') and v.upper() == 'TRUE'
                 for k, v in flags.items())
    result['sharing_config'] = ('disabled' if not shared and all(
        flags.get('isolation.tools.' + k + '.disable', '').upper() == 'TRUE'
        for k in ('copy', 'paste', 'dnd')) else 'not_confirmed')
    try:
        listing = command([FUSION / 'vmrun', '-T', 'fusion', 'list'])
        if listing.returncode != 0 or not re.match(r'Total running VMs: \d+', listing.stdout):
            result.update(state='unknown', error='Fusion negrąžino patikimo veikiančių VM sąrašo.')
        else:
            running = {str(Path(p).resolve()) for p in listing.stdout.splitlines()[1:] if p.strip()}
            result['state'] = ('running' if str(vmx.resolve()) in running else
                               'suspended' if list(bundle.glob('*.vmss')) else 'stopped')
    except (OSError, subprocess.TimeoutExpired):
        result.update(state='unknown', error='Fusion būsenos patikra nepasiekiama.')
    return result


def mount_vm_storage(config, command=run_command):
    if sys.platform != 'darwin':
        raise ValueError('VM saugyklos prijungimas skirtas Mac.')
    path = external_path(config.get('disk_image', ''))
    if path.suffix != '.sparsebundle' or path.is_symlink() or not (path / 'Info.plist').is_file():
        raise ValueError('Pasirinktas VM atvaizdas nerastas arba netinkamas.')
    state = probe_vm(config, command)
    if state['image_attached']:
        return state
    response = command(['diskutil', 'image', 'attach', '--nobrowse', '--plist', path], timeout=30)
    if response.returncode:
        raise ValueError('Nepavyko prijungti VM saugyklos. Patikrink ją per Disk Utility.')
    state = probe_vm(config, command)
    if not state['image_attached']:
        raise ValueError('Atvaizdas prijungtas, bet numatytas VM kelias nepatvirtintas.')
    return state


def open_path(path):
    path = external_path(path)
    if not path.exists():
        raise ValueError('Failas arba aplankas nerastas.')
    if sys.platform == 'darwin':
        subprocess.run(['open', str(path)], check=True, timeout=8)
    elif sys.platform == 'win32':
        os.startfile(str(path))
    else:
        subprocess.run(['xdg-open', str(path)], check=True, timeout=8)


def budget_snapshot(workspace, config):
    """Allocated files plus reserved image capacity; no unrelated disk inventory."""
    image = Path(config.get('disk_image', '')).resolve()
    installer = Path(config.get('installer_path', ''))
    runtime = Path(workspace).resolve().parent
    fusion = FUSION.parent.parent
    if (not config.get('disk_image') or not config.get('installer_path')
            or not installer.is_file() or not fusion.is_dir() or not image.is_dir()):
        return None
    def allocated(root, skip=None):
        total = 0
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if not (Path(directory) / d).is_symlink()
                       and Path(directory) / d != skip]
            for name in files:
                info = (Path(directory) / name).lstat()
                total += getattr(info, 'st_blocks', (info.st_size + 511) // 512) * 512
        return total
    limit = plistlib.loads((image / 'Info.plist').read_bytes())['size']
    other = allocated(runtime, image) + allocated(fusion) + installer.stat().st_size
    return {'reserved_bytes': limit + other, 'current_bytes': allocated(image) + other,
            'budget_bytes': config.get('mac_lab_budget_bytes', 0)}


def owned_directory(workspace, name):
    root = external_path(workspace)
    folder = root / name
    if folder.is_symlink():
        raise ValueError('Programos aplankas negali būti nuoroda: ' + name)
    folder.mkdir(exist_ok=True)
    return folder


def load_catalog(root, workspace):
    root, workspace = external_path(root), external_path(workspace)
    if root == workspace or root in workspace.parents or workspace in root.parents:
        raise ValueError('HDD kolekcija ir programos darbo aplankas turi būti atskiri.')
    tables, identities = {}, {}
    for name, fields in [('sources', SOURCE_FIELDS), ('objects', OBJECT_FIELDS), ('selection', SELECTION_FIELDS)]:
        path = local_file(root, 'catalog/' + name + '.csv')
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError('Katalogo CSV per didelis: ' + name)
        before = digest(path)
        tables[name] = read_csv(path, fields)
        if before != digest(path):
            raise ValueError('Katalogas pasikeitė skaitant; įkelk iš naujo.')
        identities[name] = before
    sources, objects, selections = {}, {}, {}
    hashes = set()
    for row in tables['sources']:
        key = row['source_id']
        local_controls = row['url'] == 'aegis://controls/v1' and row['status'] == 'SYNTHETIC_CONTROLS'
        if not key or key in sources or not row['title'] or (not local_controls and urlparse(row['url']).scheme not in {'http', 'https'}):
            raise ValueError('Netinkamas arba pasikartojantis šaltinis: ' + key)
        if any(not row[k].strip() for k in ('version', 'retrieved_at', 'usage_terms', 'status')):
            raise ValueError('Trūksta šaltinio kilmės ar naudojimo sąlygų: ' + key)
        sources[key] = row
    for row in tables['objects']:
        key = row['object_id']
        if not key or key in objects or row['source_id'] not in sources:
            raise ValueError('Netinkamas objektas arba jo šaltinis: ' + key)
        if not SHA256.fullmatch(row['sha256']) or row['sha256'] in hashes:
            raise ValueError('Netinkama arba pasikartojanti maiša: ' + key)
        if not row['bytes'].isdigit() or any(not row[k].strip() for k in (
                'format', 'architecture', 'project_id', 'label', 'label_basis', 'eligibility_status')):
            raise ValueError('Trūksta objekto metaduomenų: ' + key)
        # Validate containment/existence now; only selected objects are read for hashing.
        local_file(root, row['relative_path'])
        objects[key] = row
        hashes.add(row['sha256'])
    for row in objects.values():
        if row['parent_id']:
            parent = objects.get(row['parent_id'])
            if not parent or parent['object_id'] == row['object_id'] or parent['parent_id'] or any(
                    parent[k] != row[k] for k in ('project_id', 'family_id')):
                raise ValueError('Netinkamas originalo ryšys: ' + row['object_id'])
    groups = {}
    for row in tables['selection']:
        key = row['object_id']
        if key not in objects or key in selections or row['split'] not in {'', 'calibration', 'evaluation'}:
            raise ValueError('Netinkama atrankos eilutė: ' + key)
        if row['split']:
            if not row['selection_reason'].strip() or not row['protocol_version'].strip():
                raise ValueError('Atrankai reikia pagrindo ir protokolo versijos: ' + key)
            project = objects[key]['project_id']
            if project in groups and groups[project] != row['split']:
                raise ValueError('Susijęs projektas pateko į abi tyrimo dalis: ' + project)
            groups[project] = row['split']
        selections[key] = row
    for key, row in objects.items():
        if row['parent_id'] and selections.get(key, {}).get('split') != selections.get(row['parent_id'], {}).get('split'):
            raise ValueError('Originalas ir variantas turi priklausyti tai pačiai daliai: ' + key)
    return {'root': str(root), 'loaded_at': now(), 'catalog_sha256': identities,
            'sources': sources, 'objects': objects, 'selection': selections}


def demo_catalog(workspace):
    workspace = external_path(workspace)
    root = workspace.with_name(workspace.name + '-demo-collection')
    if root.is_symlink():
        raise ValueError('Mokomasis katalogas negali būti nuoroda.')
    if root.exists():
        if read_json(root / 'aegis-demo.json').get('type') != 'inert_controls_v1':
            raise ValueError('Esamas aplankas nepriklauso mokomajam katalogui.')
        catalog = load_catalog(root, workspace)
        if set(catalog['objects']) != set(CONTROLS) or any(
                (root / 'controls' / (key + '.txt')).read_bytes() != content
                for key, (_, content) in CONTROLS.items()):
            raise ValueError('Mokomojo katalogo turinys pakeistas; esamų failų neperrašome.')
        return catalog
    root.mkdir()
    write_json(root / 'aegis-demo.json', {'type': 'inert_controls_v1', 'experiment_results': False})
    (root / 'catalog').mkdir()
    (root / 'controls').mkdir()
    source = dict(zip(SOURCE_FIELDS, ['builtin', 'Project Aegis inert text controls',
                      'aegis://controls/v1', '1', now(), 'Generated locally for demonstration', 'SYNTHETIC_CONTROLS']))
    objects, selection = [], []
    for key, (_, content) in CONTROLS.items():
        relative = 'controls/' + key + '.txt'
        (root / relative).write_bytes(content)
        objects.append(dict(zip(OBJECT_FIELDS, [key, 'builtin', relative, hashlib.sha256(content).hexdigest(),
                             str(len(content)), 'UTF-8 text', 'none', 'demo-' + key, '', '', 'control',
                             'Fixed inert text generated by this application', 'DEMO_ONLY'])))
        selection.append(dict(zip(SELECTION_FIELDS, [key, 'evaluation', 'Inert UI demonstration only', 'demo-v1'])))
    for name, fields, rows in [('sources', SOURCE_FIELDS, [source]), ('objects', OBJECT_FIELDS, objects),
                               ('selection', SELECTION_FIELDS, selection)]:
        with (root / 'catalog' / (name + '.csv')).open('x', encoding='utf-8', newline='') as stream:
            writer = csv.DictWriter(stream, fields)
            writer.writeheader()
            writer.writerows(rows)
    return load_catalog(root, workspace)


def verify_selected(catalog, selected):
    if not selected or len(set(selected)) != len(selected) or any(k not in catalog['objects'] for k in selected):
        raise ValueError('Pasirink bent vieną katalogo objektą.')
    results = []
    for key in selected:
        row = catalog['objects'][key]
        path = local_file(Path(catalog['root']), row['relative_path'])
        before = path.stat()
        actual = digest(path)
        after = path.stat()
        stable = (before.st_size, before.st_mtime_ns, before.st_ino) == (after.st_size, after.st_mtime_ns, after.st_ino)
        results.append({'object_id': key, 'relative_path': row['relative_path'], 'sha256': actual,
                        'bytes': after.st_size,
                        'verified': stable and actual == row['sha256'] and after.st_size == int(row['bytes'])})
    return results


def save_catalog_check(workspace, catalog, selected):
    def check_registry():
        for name, sha in catalog['catalog_sha256'].items():
            if digest(local_file(Path(catalog['root']), 'catalog/' + name + '.csv')) != sha:
                raise ValueError('Katalogas pasikeitė; įkelk jį iš naujo.')
    check_registry()
    rows = verify_selected(catalog, selected)
    check_registry()
    folder = owned_directory(workspace, 'catalog-checks')
    report = {'run_id': 'catalog-' + uuid.uuid4().hex, 'created_at_utc': now(),
              'mode': 'catalog_hash_check', 'experiment_results': False,
              'catalog_sha256': catalog['catalog_sha256'], 'files': rows,
              'all_verified': all(r['verified'] for r in rows)}
    path = folder / (report['run_id'] + '.json')
    write_json(path, report)
    return path, report


def save_selection_plan(workspace, catalog, selected, title):
    title = title.strip()
    if not title or len(title) > 100 or any(ord(c) < 32 for c in title):
        raise ValueError('Plano pavadinimas: nuo 1 iki 100 simbolių.')
    current = load_catalog(catalog['root'], workspace)
    if current['catalog_sha256'] != catalog['catalog_sha256']:
        raise ValueError('Katalogas pasikeitė; prieš planuodamas įkelk jį iš naujo.')
    rows = verify_selected(current, selected)
    if not all(r['verified'] for r in rows):
        raise ValueError('Pasirinktų failų maišos arba dydžiai nesutampa.')
    splits, protocols = set(), set()
    for key in selected:
        item = current['selection'].get(key, {})
        splits.add(item.get('split', ''))
        protocols.add(item.get('protocol_version', ''))
        parent = current['objects'][key]['parent_id']
        if parent and parent not in selected:
            raise ValueError('Kartu pasirink varianto originalą: ' + parent)
    if len(splits) != 1 or '' in splits or len(protocols) != 1 or '' in protocols:
        raise ValueError('Planui reikia vienos tyrimo dalies ir vienos protokolo versijos.')
    plan = {'run_id': 'plan-' + uuid.uuid4().hex, 'created_at_utc': now(),
            'title': title, 'mode': 'selection_plan', 'status': 'PLAN_ONLY',
            'experiment_results': False, 'guest_execution': False, 'vm_restore_verified': False,
            'split': splits.pop(), 'protocol_version': protocols.pop(),
            'catalog_sha256': current['catalog_sha256'],
            'sources': {current['objects'][key]['source_id']: current['sources'][current['objects'][key]['source_id']]
                        for key in selected},
            'files': [{**r, 'metadata': current['objects'][r['object_id']]} for r in rows]}
    folder = owned_directory(workspace, 'plans')
    path = folder / (plan['run_id'] + '.json')
    write_json(path, plan)
    return path, plan


def result_paths(workspace):
    root = Path(workspace)
    entries = []
    for name, pattern in [('runs', 'control-*/report.json'), ('catalog-checks', 'catalog-*.json'), ('plans', 'plan-*.json'),
                          ('vm-controls', 'session-*/cycle-*/report.json'),
                          ('lab-preparation','preparation-*/report.json'),
                          ('selection-transfers','transfer-*/report.json'),
                          ('scanner-checks','scan-'+'?'*32+'.json')]:
        folder = root / name
        if folder.is_symlink():
            continue
        for path in folder.glob(pattern):
            try:
                if not path.is_symlink() and not path.parent.is_symlink():
                    entries.append((path.stat().st_mtime, path))
            except OSError:
                continue
    return [p for _, p in sorted(entries, key=lambda entry: entry[0], reverse=True)]


def validated_result(path, workspace):
    root = external_path(workspace)
    path = Path(path)
    if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != root and root in p.parents):
        raise ValueError('Rezultatas negali būti simbolinė nuoroda.')
    path = path.resolve()
    if path not in [p.resolve() for p in result_paths(root)]:
        raise ValueError('Rezultatas nepriklauso šiai programai.')
    value = read_json(path)
    if value.get('mode')=='selection_transfer_control':
        from vm_selection_transfer import validated_result as validate_transfer_result
        return validate_transfer_result(path,workspace)
    if value.get('mode')=='benign_pe_rehearsal':
        from vm_lab_preparation import validated_result as validate_lab_result
        return validate_lab_result(path,workspace)
    if value.get('mode') == 'guest_inert_transfer_control':
        from vm_results import validate_cycle
        return validate_cycle(path, workspace)[0]
    if value.get('mode') == 'scanner_inert_control':
        from guest_scanners import validate_report
        identity=read_json(path.with_name(path.stem+'.identity.json'))
        return validate_report(value,identity['code_sha256'],identity['yara_sha256'])
    if value.get('mode') not in {'inert_text_control', 'catalog_hash_check', 'selection_plan'} or value.get('experiment_results') is not False:
        raise ValueError('Neatpažintas rezultato formatas.')
    if not isinstance(value.get('files'), list) or not value.get('created_at_utc') or not value.get('run_id'):
        raise ValueError('Trūksta rezultato laukų.')
    prefix = {'inert_text_control': 'control', 'catalog_hash_check': 'catalog', 'selection_plan': 'plan'}[value['mode']]
    if not isinstance(value['run_id'], str) or not re.fullmatch(prefix + '-[0-9a-f]{32}', value['run_id']):
        raise ValueError('Netinkamas rezultato identifikatorius.')
    if (path.parent.name if prefix == 'control' else path.stem) != value['run_id']:
        raise ValueError('Rezultato identifikatorius neatitinka jo vietos.')
    if any(not isinstance(row, dict) for row in value['files']):
        raise ValueError('Netinkamos rezultato eilutės.')
    return value


def cleanup_confirmed(path):
    try:
        return (not (path.parent / 'work').exists()
                and read_json(path.with_name('completion.json')).get('work_cleanup_verified') is True)
    except (OSError, ValueError):
        return False


def result_summary(path, workspace):
    value = validated_result(path, workspace)
    mode = value['mode']
    if mode=='selection_transfer_control':
        state=('Maišos sutampa' if value['all_verified'] else 'Perdavimo neatitikimas')+(' · VM atkurta' if path.with_name('restoration.json').is_file() else ' · atkūrimas laukia')
        title='Pasirinkto poaibio perdavimas į VM'
    elif mode=='benign_pe_rehearsal':
        state=('Kontrolės praėjo' if value['all_checks_passed'] else 'Reikia patikros')+(' · VM atkurta' if path.with_name('restoration.json').is_file() else ' · atkūrimas laukia')
        title='Nekenkėjiška PE repeticija'
    elif mode == 'scanner_inert_control':
        yara_ok=all(row['yara_status'] in {'MATCHED','NOT_MATCHED'} and (row['yara_status']=='MATCHED')==row['yara_expected_match'] for row in value['files'])
        av_done=all(row['av_status'] in {'NOT_DETECTED','DETECTED'} for row in value['files'])
        state=('YARA patikrinta' if yara_ok else 'YARA reikia patikros')+(' · Defender patikrintas' if av_done else ' · Defender nepatvirtintas')
        title='Skenerių kontrolė su tekstais'
    elif mode == 'guest_inert_transfer_control':
        from vm_results import restore_confirmed
        state = 'VM atkūrimas patvirtintas' if restore_confirmed(path, workspace) else 'Rezultatas išsaugotas; atkūrimas laukia'
        title = 'Windows VM kontrolė'
    elif mode == 'inert_text_control':
        state = 'Baigta' if cleanup_confirmed(path) else 'Reikia patikros'
        title = value.get('title') or 'Vietinė kontrolinė patikra'
    elif mode == 'catalog_hash_check':
        state = 'Maišos sutampa' if value.get('all_verified') else 'Rastas neatitikimas'
        title = 'Katalogo failų patikra'
    else:
        state, title = 'Tik planas', value.get('title', 'Pasirinkimo planas')
    return {'path': path, 'id': value['run_id'], 'date': value['created_at_utc'],
            'title': title, 'state': state, 'count': len(value['files']), 'mode': mode}


def export_result(path, workspace, destination, protected_roots=()):
    value = validated_result(path, workspace)
    destination = external_path(destination)
    for source in protected_roots:
        source = external_path(source)
        if destination == source or source in destination.parents:
            raise ValueError('Eksporto negalima rašyti į tik skaitomą kolekciją. Pasirink Mac rezultatų aplanką.')
    if destination.exists():
        raise ValueError('Eksportui pasirink naują failo vardą; esamų failų neperrašome.')
    table = io.StringIO(newline='')
    writer = csv.writer(table)
    writer.writerow(['id', 'bytes', 'sha256', 'verified', 'literal_marker_found', 'av_status', 'yara_status'])
    for row in value['files']:
        if not isinstance(row, dict):
            raise ValueError('Netinkama rezultato eilutė.')
        cells = [row.get('object_id', row.get('id', '')), row.get('bytes', ''), row.get('sha256', ''),
                 row.get('verified', row.get('hash_verified', False)), row.get('literal_marker_found', ''),
                 row.get('av_status', 'NOT_RUN'), row.get('yara_status', 'NOT_RUN')]
        writer.writerow(["'" + str(v) if str(v).lstrip().startswith(('=', '+', '-', '@')) else v for v in cells])
    content = Path(path).read_bytes()
    if len(content) > 1024 * 1024 or json.loads(content) != value:
        raise ValueError('Rezultatas pasikeitė eksporto metu; bandyk iš naujo.')
    files = {'report.json': content, 'files.csv': table.getvalue().encode('utf-8-sig'),
             'SKAITYK.txt': ('Project Aegis\nTai kontrolinė patikra arba planas, ne aptikimo eksperimentas.\n'
                              'AV ir YARA nepaleistos. VM atkūrimas nepatvirtintas.\n').encode('utf-8')}
    if value['mode'] == 'inert_text_control' and path.with_name('completion.json').is_file():
        files['completion.json'] = json.dumps(read_json(path.with_name('completion.json')), indent=2).encode()
    if value['mode'] == 'guest_inert_transfer_control':
        from vm_results import validate_cycle
        _, completion, evidence = validate_cycle(path, workspace)
        files['vm-evidence.json'] = json.dumps(evidence, indent=2).encode()
        if completion is not None:files['completion.json'] = path.with_name('completion.json').read_bytes()
        files['SKAITYK.txt'] = ('Project Aegis\nWindows VM kontrolė su inertiniais tekstais; ne aptikimo eksperimentas.\n'
                              'AV / YARA nepaleistos. VM atkūrimas: '+('patvirtintas' if completion else 'dar nepatvirtintas')+'\n').encode('utf-8')
    if value['mode'] == 'scanner_inert_control':
        files['scanner-evidence.json']=path.with_name(path.stem+'.identity.json').read_bytes()
        files['SKAITYK.txt']=('Project Aegis\nSkenerių kontrolė su trimis nekenkėjiškais tekstais.\n'
                            'YARA žymeklio sutapimas nėra kenkėjiškumo klasifikacija.\n'
                            'Defender NOT_RUN / INCONCLUSIVE nėra neigiamas atsakymas. Tai ne tyrimo eksperimentas.\n').encode('utf-8')
    if value['mode']=='benign_pe_rehearsal':
        files['lab-evidence.json']=path.with_name('resolved.json').read_bytes()
        if path.with_name('restoration.json').is_file():files['restoration.json']=path.with_name('restoration.json').read_bytes()
        if path.with_name('restored-artifacts.json').is_file():files['restored-artifacts.json']=path.with_name('restored-artifacts.json').read_bytes()
        for item in value['artifacts']:
            target=path.parent/'artifacts'/item['path']
            if target.is_symlink() or not target.is_file() or target.stat().st_size!=item['bytes']:
                raise ValueError('Repeticijos įrodymas pasikeitė')
            content=target.read_bytes()
            if hashlib.sha256(content).hexdigest()!=item['sha256']:raise ValueError('Repeticijos įrodymo maiša nesutampa')
            files['artifacts/'+item['path']]=content
        files['SKAITYK.txt']=('Project Aegis\nDvi savo sukurtos nekenkėjiškos .NET AnyCPU PE programos Windows ARM VM.\n'
                            'Process Monitor stebėjimas, YARA ir Defender kontrolės; EICAR niekada nevykdytas ir neeksportuojamas.\n'
                            'Tai pasirengimo repeticija, ne tyrimo eksperimentas ar visų native PE objektų suderinamumo įrodymas.\n').encode('utf-8')
    if value['mode']=='selection_transfer_control':
        files['transfer-manifest.json']=path.with_name('manifest.json').read_bytes()
        files['transfer-evidence.json']=path.with_name('resolved.json').read_bytes()
        if path.with_name('restoration.json').is_file():files['restoration.json']=path.with_name('restoration.json').read_bytes()
        files['SKAITYK.txt']=('Project Aegis\nPasirinkto poaibio baitų perdavimo patikra.\n'
            'Failai nevykdyti; AV ir YARA nepaleistos. Tai ne tyrimo eksperimentas.\n').encode('utf-8')
    files['sha256.json'] = json.dumps({k: hashlib.sha256(v).hexdigest() for k, v in files.items()}, indent=2).encode()
    try:
        with destination.open('xb') as stream:
            with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                for name, content in files.items():
                    archive.writestr(name, content)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        # Keep partial output reviewable; never replace a prior export.
        raise
    return destination
