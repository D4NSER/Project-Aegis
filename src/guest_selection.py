"""Verify a bounded selected byte set in Windows; never execute its contents."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat

MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024


def digest(path):
    value = hashlib.sha256();total=0
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            total+=len(block)
            if total>MAX_FILE:raise ValueError('Transfer input grew beyond its size limit')
            value.update(block)
    return value.hexdigest()


def regular(path):
    info = path.lstat()
    if path.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise ValueError('Links and reparse points are not transfer inputs')
    return stat.S_ISREG(info.st_mode)


def verify_transfer(root):
    root = Path(root)
    if platform.system() != 'Windows' or platform.machine().casefold() not in {'arm64','aarch64'}:
        raise ValueError('The prepared transfer check requires Windows ARM64')
    if (root.is_symlink() or getattr(root.lstat(),'st_file_attributes',0)&0x400
            or not re.fullmatch(r'AegisTransfer-[0-9a-f]{32}', root.name)
            or root.parent.resolve() != Path(os.environ['LOCALAPPDATA']).resolve()):
        raise ValueError('Transfer directory is outside the dedicated lab workspace')
    manifest_path = root/'manifest.json'
    if not regular(manifest_path) or manifest_path.stat().st_size > 1024 * 1024:
        raise ValueError('Invalid transfer manifest')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if (manifest['run_id'] != 'transfer-'+root.name.removeprefix('AegisTransfer-')
            or not re.fullmatch(r'[0-9a-f]{64}', manifest['nonce'])
            or manifest['collector_sha256'] != digest(Path(__file__))
            or not 1 <= len(manifest['files']) <= 16):
        raise ValueError('Transfer identity mismatch')
    rows = []; total = 0; ids = set()
    for index, item in enumerate(manifest['files']):
        if (item['name'] != 'object-'+str(index).zfill(4)+'.bin'
                or item['id'] in ids or type(item['bytes']) is not int
                or not 0 <= item['bytes'] <= MAX_FILE
                or not re.fullmatch(r'[0-9a-f]{64}', item['sha256'])):
            raise ValueError('Invalid selected object identity or size')
        total += item['bytes']; ids.add(item['id'])
        if total > MAX_TOTAL:raise ValueError('Selected objects exceed transfer budget')
        path = root/item['name']
        if not path.exists():
            rows.append({**item,'hash_verified':False,'status':'MISSING_INPUT','actual_sha256':None})
            continue
        if not regular(path) or path.stat().st_size > MAX_FILE:
            raise ValueError('Unexpected transfer input type or size')
        actual = digest(path)
        passed = actual == item['sha256'] and path.stat().st_size == item['bytes']
        rows.append({**item,'hash_verified':passed,'status':'VERIFIED' if passed else 'MISMATCH','actual_sha256':actual})
    return {'schema':1,'mode':'selection_transfer_control','run_id':manifest['run_id'],
            'created_at_utc':datetime.now(timezone.utc).isoformat(),'nonce':manifest['nonce'],
            'collector_sha256':digest(Path(__file__)),'manifest_sha256':digest(manifest_path),
            'files':rows,'all_verified':all(row['hash_verified'] for row in rows),
            'platform':platform.system(),'architecture':platform.machine(),
            'experiment_results':False,'guest_execution':False,'av_run':False,'yara_run':False,
            'vm_restore_verified':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',required=True)
    args=parser.parse_args();root=Path(args.root);report=verify_transfer(root)
    with (root/'report.json').open('x',encoding='utf-8') as stream:
        json.dump(report,stream,indent=2);stream.flush();os.fsync(stream.fileno())


if __name__=='__main__':main()
