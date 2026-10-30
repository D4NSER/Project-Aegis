"""Validate host VM-control evidence without trusting a guest restore claim."""
import hashlib
import json
from pathlib import Path
import re

from aegis import external_path
from control_channel import decode_message,encode_message
from guest_control import plain_path


def read_record(path,limit=65536):
    path=plain_path(path)
    if not path.is_file() or path.stat().st_size>limit:raise ValueError('Invalid VM evidence file')
    return json.loads(path.read_text(encoding='utf-8'))


def validate_cycle(path,workspace):
    root=external_path(workspace);path=plain_path(path)
    if (path.name!='report.json' or path.parent.parent.parent!=root/'vm-controls'
            or not re.fullmatch(r'cycle-[0-9a-f]{32}',path.parent.name)
            or not re.fullmatch(r'session-[0-9a-f]{32}',path.parent.parent.name)):
        raise ValueError('VM result is outside its owned session')
    session=read_record(path.parent.parent/'session.json')
    baseline=read_record(path.parent.parent/'baseline.json')
    transport=read_record(path.with_name('transport.json'))
    report=read_record(path,16000)
    hashes=session['source_hashes'];request=session['request'];message=transport['metadata_message']
    verified=decode_message(encode_message(message),request=request,challenge=message['challenge'],source_hashes=hashes)
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    if (verified['phase']!='complete' or verified['report']!=report or digest!=transport['report_sha256']
            or baseline.get('cold_snapshot') is not True or baseline['source_hashes']!=hashes
            or not re.fullmatch(r'Aegis-Inert-[0-9a-f]{16}',baseline['snapshot'])):
        raise ValueError('VM result identity or cold baseline mismatch')
    completion_path=path.with_name('completion.json');completion=None
    if completion_path.exists():
        completion=read_record(completion_path)
        fresh=completion['fresh_guest_proof']
        decoded=decode_message(encode_message(fresh),request=request,challenge=fresh['challenge'],source_hashes=hashes)
        if (completion.get('vm_restore_verified') is not True or completion.get('experiment_results') is not False
                or completion.get('report_sha256')!=digest or completion.get('snapshot')!=baseline['snapshot']
                or decoded['phase']!='ready' or decoded['challenge']==verified['challenge']
                or decoded['run_root_exists'] or decoded['mutation_exists'] or decoded['network_up'] is not False):
            raise ValueError('VM restore lacks a matching fresh absence proof')
    return report,completion,{'request':request,'source_hashes':hashes,'snapshot':baseline['snapshot'],
                              'cold_snapshot':True,'vm_restore_verified':completion is not None,'experiment_results':False}


def restore_confirmed(path,workspace):
    return validate_cycle(path,workspace)[1] is not None
