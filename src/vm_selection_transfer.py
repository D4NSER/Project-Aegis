"""Transfer only a frozen selection; preserve its report before cold restoration."""
import hashlib
from pathlib import Path, PureWindowsPath
import re
import uuid

from aegis import local_file
from control_workspace import write_json
import control_panel as panel
from guest_selection import MAX_FILE, MAX_TOTAL
from vm_run_manager import windows_arguments


def execute(manager, plan_path, collection_root):
    m=manager
    if (not m.session or m.session.state not in {'baseline_ready','restored'}
            or m.scanner_cleanup or m.pending_scan or m.lab.pending):
        raise ValueError('Finish the current job and restore before transferring a selection')
    probe=m.probe()
    if probe.get('network_config')!='disconnected' or probe.get('sharing_config')!='disabled':
        raise ValueError('Network and sharing must be disconnected')
    m.collect_environment();proof=m.status()
    if not m.session.account_ready or not proof or proof.get('network_up') is not False:
        raise ValueError('Dedicated-account and fresh disconnected-guest proof are required')
    plan=panel.validated_result(Path(plan_path),m.workspace)
    if plan['mode']!='selection_plan':raise ValueError('Choose a saved selection plan')
    catalog=panel.load_catalog(collection_root,m.workspace)
    if catalog['catalog_sha256']!=plan['catalog_sha256']:
        raise ValueError('Collection registries changed since this plan was saved')
    selected=[item['object_id'] for item in plan['files']]
    if not 1 <= len(selected) <= 16 or len(set(selected))!=len(selected):
        raise ValueError('Transfer between one and sixteen selected objects')
    for saved in plan['files']:
        key=saved['object_id'];metadata=catalog['objects'][key];selection=catalog['selection'].get(key,{})
        if (saved.get('metadata')!=metadata or selection.get('split')!=plan.get('split')
                or selection.get('protocol_version')!=plan.get('protocol_version')
                or metadata['parent_id'] and metadata['parent_id'] not in selected):
            raise ValueError('Plan grouping or object metadata changed')
    rows=panel.verify_selected(catalog,selected)
    if not all(row['verified'] for row in rows):raise ValueError('Selected source bytes changed')
    if any(row['bytes']>MAX_FILE for row in rows) or sum(row['bytes'] for row in rows)>MAX_TOTAL:
        raise ValueError('Transfer limit: 16 MiB per file, 64 MiB total')
    if any(row['sha256']!=saved['sha256'] or row['bytes']!=saved['bytes'] for row,saved in zip(rows,plan['files'])):
        raise ValueError('Plan no longer identifies the selected source bytes')
    if probe.get('vm_free_bytes',0)<3*1024**3+sum(row['bytes'] for row in rows):
        raise ValueError('Insufficient VM headroom for this bounded transfer')
    token=uuid.uuid4().hex
    host=panel.owned_directory(m.workspace,'selection-transfers')/('transfer-'+token);host.mkdir()
    kit=PureWindowsPath(m.connection.environment('LOCALAPPDATA'))/('AegisTransfer-'+token)
    source=Path(__file__).with_name('guest_selection.py')
    manifest={'run_id':'transfer-'+token,'nonce':uuid.uuid4().hex+uuid.uuid4().hex,
              'collector_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
              'files':[{'id':row['object_id'],'name':'object-'+str(index).zfill(4)+'.bin',
                        'sha256':row['sha256'],'bytes':row['bytes']} for index,row in enumerate(rows)]}
    write_json(host/'manifest.json',manifest)
    write_json(host/'selection-plan.json',plan)
    cleanup={'id':token,'vmx':str(m.vmx.resolve()),'previous_cycle':str(m.session.cycle_root),
             'kind':'selection_transfer','experiment_results':False}
    checks=panel.owned_directory(m.workspace,'scanner-checks')
    write_json(checks/('cleanup-required-'+token+'.json'),cleanup);m.scanner_cleanup=cleanup
    write_json(host/'pending.json',{'vmx':str(m.vmx.resolve()),'guest_root':str(kit),
        'manifest_sha256':hashlib.sha256((host/'manifest.json').read_bytes()).hexdigest(),'experiment_results':False})
    m.connection.mkdir(str(kit));m.connection.copy_to(source,str(kit/'guest_selection.py'))
    m.connection.copy_to(host/'manifest.json',str(kit/'manifest.json'))
    for row,item in zip(rows,manifest['files']):
        m.progress('Perduodamas pasirinktas objektas: '+row['object_id'])
        m.connection.copy_to(local_file(Path(catalog['root']),row['relative_path']),str(kit/item['name']))
    # A second source read catches changes during transfer; nothing is written to the collection.
    if not all(row['verified'] for row in panel.verify_selected(catalog,selected)):
        raise ValueError('Selected source bytes changed during transfer; restore required')
    code=m.connection.run(m.python,windows_arguments(kit/'guest_selection.py','--root',kit),timeout=90)
    if code!=0:raise ValueError('Windows selected-byte verification failed; restore required')
    m.connection.copy_from(str(kit/'report.json'),host/'report.json')
    report=validate_report(panel.read_json(host/'report.json'),manifest)
    write_json(host/'resolved.json',{'report_sha256':hashlib.sha256((host/'report.json').read_bytes()).hexdigest(),
               'experiment_results':False,'all_verified':report['all_verified']})
    return {'report':report,'host_root':str(host)}


def validate_report(report,manifest):
    if (report.get('mode')!='selection_transfer_control' or report.get('run_id')!=manifest['run_id']
            or report.get('nonce')!=manifest['nonce'] or report.get('collector_sha256')!=manifest['collector_sha256']
            or report.get('platform')!='Windows' or report.get('architecture','').casefold() not in {'arm64','aarch64'}
            or any(report.get(k) is not False for k in ['experiment_results','guest_execution','av_run','yara_run','vm_restore_verified'])
            or len(report.get('files',[]))!=len(manifest['files'])):
        raise ValueError('Selection transfer identity mismatch')
    for row,expected in zip(report['files'],manifest['files']):
        if any(row.get(k)!=v for k,v in expected.items()):raise ValueError('Selection transfer row changed')
        if row.get('status') not in {'VERIFIED','MISMATCH','MISSING_INPUT'}:raise ValueError('Unknown transfer result')
        passed=row.get('status')=='VERIFIED' and row.get('actual_sha256')==expected['sha256']
        if row.get('hash_verified') is not passed:raise ValueError('Selection byte verification is inconsistent')
    if report.get('all_verified') is not all(row['hash_verified'] for row in report['files']):
        raise ValueError('Selection verification summary is inconsistent')
    return report


def record_restore(manager):
    m=manager
    if not m.session or m.session.state!='restored':return
    for host in (m.workspace/'selection-transfers').glob('transfer-*'):
        if not re.fullmatch(r'transfer-[0-9a-f]{32}',host.name) or (host/'restoration.json').exists():continue
        token=host.name.removeprefix('transfer-')
        cleanup=m.workspace/'scanner-checks'/('cleanup-completed-'+token+'.json')
        if not cleanup.is_file():continue
        pending=panel.read_json(host/'pending.json');kit=PureWindowsPath(pending['guest_root'])
        manifest=panel.read_json(host/'manifest.json')
        names=['report.json','manifest.json','guest_selection.py',*[row['name'] for row in manifest['files']]]
        if any(m.connection.exists(str(kit/name)) for name in names):
            raise ValueError('Selected-byte files remain after cold restoration')
        write_json(host/'restoration.json',{**panel.read_json(cleanup),'checked_paths':names,
                   'selected_files_absent':True,'experiment_results':False})


def validated_result(path,workspace):
    path=Path(path);report=validate_report(panel.read_json(path),panel.read_json(path.with_name('manifest.json')))
    if path.parent.name!=report['run_id']:raise ValueError('Transfer result belongs to another job')
    pending=panel.read_json(path.with_name('pending.json'))
    if report.get('manifest_sha256')!=pending['manifest_sha256']:raise ValueError('Transfer manifest changed')
    resolved=panel.read_json(path.with_name('resolved.json'))
    if resolved.get('report_sha256')!=hashlib.sha256(path.read_bytes()).hexdigest():raise ValueError('Transfer report changed')
    proof=path.with_name('restoration.json')
    if proof.is_file():
        from vm_results import validate_cycle
        value=panel.read_json(proof);_,completion,evidence=validate_cycle(Path(value['cycle_root'])/'report.json',workspace)
        if not completion or not evidence['vm_restore_verified'] or value.get('selected_files_absent') is not True:
            raise ValueError('Selection transfer restoration proof is incomplete')
    return report
