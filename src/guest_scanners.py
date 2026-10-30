"""Windows scanner readiness controls on three fixed inert texts only.

A YARA marker match is a plumbing control, never a malware classification.
Defender's exit code alone is not interpreted as a negative detection result.
"""
import argparse
import base64
import ctypes
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import uuid

from control_workspace import CONTROLS,MARKER,write_json
from guest_control import plain_path

RULE = (Path(__file__).resolve().parents[1]/'rules/control-marker.yar').read_bytes()


def validate_report(value,code_sha256,yara_sha256):
    fields={'schema','mode','experiment_results','run_id','created_at_utc','platform','architecture','code_sha256',
            'yara_version','yara_executable_sha256','yara_machine','rule_sha256','defender_before','defender_after',
            'elevated','files','vm_restore_verified','work_cleanup_performed'}
    if (not isinstance(value,dict) or set(value)!=fields or type(value.get('schema')) is not int or value.get('schema')!=1 or value.get('mode')!='scanner_inert_control'
            or value.get('experiment_results') is not False or value.get('platform')!='Windows'
            or value.get('architecture','').casefold() not in {'arm64','aarch64'}
            or value.get('code_sha256')!=code_sha256 or value.get('yara_executable_sha256')!=yara_sha256
            or value.get('rule_sha256')!=hashlib.sha256(RULE).hexdigest()
            or type(value.get('elevated')) is not bool or not isinstance(value.get('files'),list)
            or len(value['files'])!=len(CONTROLS) or value.get('vm_restore_verified') is not False
            or value.get('work_cleanup_performed') is not False
            or not isinstance(value.get('run_id'),str) or not re.fullmatch(r'scan-[0-9a-f]{32}',value['run_id'])
            or not isinstance(value.get('yara_version'),str) or not re.fullmatch(r'\d+\.\d+\.\d+',value['yara_version'])):
        raise ValueError('Scanner control identity mismatch')
    try:
        if datetime.fromisoformat(value['created_at_utc']).utcoffset() is None:raise ValueError('Missing timestamp offset')
    except (TypeError,ValueError) as exc:raise ValueError('Invalid scanner timestamp') from exc
    state_fields={'AMEngineVersion','AMProductVersion','AntivirusEnabled','RealTimeProtectionEnabled','IsTamperProtected','AntivirusSignatureVersion'}
    if type(value.get('yara_machine')) is not int or value['yara_machine'] not in {0x8664,0xaa64}:
        raise ValueError('Unexpected YARA executable architecture')
    for key in ('defender_before','defender_after'):
        if not isinstance(value[key],dict) or set(value[key])!=state_fields:raise ValueError('Unexpected Defender state fields')
    for (key,(_,content)),row in zip(CONTROLS.items(),value['files']):
        row_fields={'id','bytes','sha256','yara_status','yara_expected_match','av_status','av_reason','av_exit_code'}
        if (not isinstance(row,dict) or set(row)!=row_fields or row.get('id')!=key or type(row.get('bytes')) is not int or row.get('bytes')!=len(content) or row.get('sha256')!=hashlib.sha256(content).hexdigest()
                or row.get('yara_expected_match') is not (MARKER in content)
                or row.get('yara_status') not in {'MATCHED','NOT_MATCHED','ERROR'}
                or row.get('av_status') not in {'NOT_RUN','INCONCLUSIVE','NOT_DETECTED','DETECTED'}
                or row.get('av_reason') not in {'ELEVATION_REQUIRED','CUSTOM_SCAN_WITH_THREAT_HISTORY','THREAT_HISTORY_UNKNOWN'}
                or (row.get('av_exit_code') is not None and type(row['av_exit_code']) is not int)):
            raise ValueError('Scanner control content/status mismatch')
        if value['elevated'] is False and row['av_status']!='NOT_RUN':
            raise ValueError('Unelevated scanner cannot claim a Defender result')
        if row['av_status']=='NOT_DETECTED':
            before,after=value['defender_before'],value['defender_after']
            if (row.get('av_exit_code')!=0 or row.get('av_reason')!='CUSTOM_SCAN_WITH_THREAT_HISTORY'
                    or before.get('AntivirusEnabled') is not True or after.get('AntivirusEnabled') is not True
                    or not isinstance(before.get('AntivirusSignatureVersion'),str) or not before['AntivirusSignatureVersion']
                    or before.get('AntivirusSignatureVersion')!=after.get('AntivirusSignatureVersion')):
                raise ValueError('A Defender negative needs complete stable observations')
    return value


def powershell_json(script,timeout=30):
    prefix='[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $ErrorActionPreference="Stop"; '
    encoded=base64.b64encode((prefix+script).encode('utf-16le')).decode('ascii')
    value=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',encoded],
                          capture_output=True,encoding='utf-8',timeout=timeout,check=True)
    if len(value.stdout)>65536:raise ValueError('Scanner observation exceeds limit')
    return json.loads(value.stdout.lstrip('\ufeff'))


def defender_state():
    return powershell_json('Get-MpComputerStatus | Select-Object AMEngineVersion,AMProductVersion,AntivirusEnabled,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureVersion | ConvertTo-Json -Compress')


def defender_threats():
    return powershell_json('ConvertTo-Json -InputObject @(Get-MpThreatDetection | Select-Object ThreatID,InitialDetectionTime,Resources,ActionSuccess) -Depth 5 -Compress') or []


def defender_program():
    root=Path(os.environ['ProgramData'])/'Microsoft/Windows Defender/Platform'
    candidates=[]
    if root.is_dir():
        for directory in root.iterdir():
            path=directory/'MpCmdRun.exe'
            if path.is_file():candidates.append(path)
    candidates.sort(key=lambda p:tuple(int(x) if x.isdigit() else 0 for x in p.parent.name.replace('-','.').split('.')),reverse=True)
    fallback=Path(os.environ['ProgramFiles'])/'Windows Defender/MpCmdRun.exe'
    if fallback.is_file():candidates.append(fallback)
    if not candidates:raise ValueError('Microsoft Defender command is absent')
    return plain_path(candidates[0])


def interpret_defender(exit_code,unchanged,threats_known,relevant_threats,protection_enabled,signatures_stable):
    if relevant_threats:return 'DETECTED'
    if exit_code==0 and unchanged and threats_known and protection_enabled and signatures_stable:return 'NOT_DETECTED'
    return 'INCONCLUSIVE'


def yara_status(result,target):
    if result.returncode!=0:return 'ERROR'
    lines=[line for line in result.stdout.splitlines() if line.strip()]
    if not lines:return 'NOT_MATCHED'
    expected='Aegis_Control_Marker '+str(target)
    return 'MATCHED' if lines==[expected] else 'ERROR'


def run_control(yara,expected_sha256,output):
    if os.name!='nt':raise ValueError('Scanner controls run only in Windows')
    yara=plain_path(yara)
    if not yara.is_file() or hashlib.sha256(yara.read_bytes()).hexdigest()!=expected_sha256:
        raise ValueError('YARA executable does not match the approved vendor hash')
    version=subprocess.run([str(yara),'--version'],capture_output=True,text=True,timeout=15,check=True).stdout.strip()
    work=plain_path(Path(os.environ['LOCALAPPDATA'])/'ProjectAegis'/'scanner-controls'/('scan-'+uuid.uuid4().hex));work.mkdir(parents=True)
    rule=work/'control-marker.yar';rule.write_bytes(RULE)
    before=defender_state();elevated=bool(ctypes.windll.shell32.IsUserAnAdmin())
    scanner=defender_program();rows=[]
    for key,(_,content) in CONTROLS.items():
        target=work/(key+'.txt');target.write_bytes(content)
        result=subprocess.run([str(yara),'-w',str(rule),str(target)],capture_output=True,text=True,timeout=30)
        row={'id':key,'bytes':len(content),'sha256':hashlib.sha256(content).hexdigest(),
             'yara_status':yara_status(result,target),'yara_expected_match':MARKER in content,
             'av_status':'NOT_RUN','av_reason':'ELEVATION_REQUIRED','av_exit_code':None}
        if elevated:
            scan=subprocess.run([str(scanner),'-Scan','-ScanType','3','-File',str(target)],capture_output=True,text=True,errors='replace',timeout=60)
            try:
                threats=defender_threats();threats=[threats] if isinstance(threats,dict) else threats
                relevant=[t for t in threats if any(str(target).casefold() in str(r).casefold() for r in t.get('Resources',[]))]
                known=True
            except (ValueError,OSError,subprocess.SubprocessError):relevant=[];known=False
            after=defender_state();unchanged=target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest()==row['sha256']
            row.update(av_status=interpret_defender(scan.returncode,unchanged,known,relevant,
                before.get('AntivirusEnabled') is True and after.get('AntivirusEnabled') is True,
                bool(before.get('AntivirusSignatureVersion')) and before.get('AntivirusSignatureVersion')==after.get('AntivirusSignatureVersion')),
                av_reason='CUSTOM_SCAN_WITH_THREAT_HISTORY' if known else 'THREAT_HISTORY_UNKNOWN',av_exit_code=scan.returncode)
        rows.append(row)
    raw=yara.read_bytes();offset=struct.unpack_from('<I',raw,0x3c)[0];machine=struct.unpack_from('<H',raw,offset+4)[0]
    report={'schema':1,'mode':'scanner_inert_control','experiment_results':False,'run_id':work.name,
        'created_at_utc':datetime.now(timezone.utc).isoformat(),'platform':platform.system(),'architecture':platform.machine(),
        'code_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'yara_version':version,
        'yara_executable_sha256':expected_sha256,'yara_machine':machine,'rule_sha256':hashlib.sha256(RULE).hexdigest(),
        'defender_before':before,'defender_after':defender_state(),'elevated':elevated,'files':rows,
        'vm_restore_verified':False,'work_cleanup_performed':False}
    output=plain_path(output)
    if output.exists():raise FileExistsError('Scanner result already exists')
    temporary=output.with_name('scanner-writing-'+uuid.uuid4().hex+'.json')
    write_json(temporary,report)
    os.rename(temporary,output)  # Windows refuses to replace an existing destination.
    return report


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--yara',required=True);parser.add_argument('--yara-sha256',required=True);parser.add_argument('--output',required=True);args=parser.parse_args(argv)
    run_control(args.yara,args.yara_sha256,args.output)


if __name__=='__main__':main()
