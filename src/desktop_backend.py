"""Private-pipe desktop bridge. Reuses validated controls; no HTTP listener."""
import argparse
import json
from pathlib import Path
import queue
import sys
import threading
import time

import control_panel as service
from control_workspace import CONTROLS, ControlWorkspace
from vm_control_ui import VMControlWindow


class ViewValue:
    def __init__(self,value=''):self.value=value;self.state='disabled'
    def set(self,value):self.value=value
    def configure(self,**options):self.state=options.get('state',self.state)
    def pack(self,*args,**kwargs):pass
    def pack_forget(self):pass
    def stop(self):pass
    def start(self,*args):pass
    def after(self,*args):pass


class Transcript(ViewValue):
    def insert(self,index,text):self.value=(self.value+text)[-16000:]
    def see(self,*args):pass


class NativeSession(VMControlWindow):
    """Adapt the existing serialized VM worker and gates without creating Tk UI."""
    BUTTONS={'status':'check_button','cycle':'cycle_button','restore':'restore_button',
        'continue_boot':'boot_button','scan':'scan_button','scanner_poll':'scan_finish',
        'scanner_defer':'scan_defer','lab_prepare':'lab_prepare','lab_poll':'lab_finish',
        'lab_defer':'lab_defer','lab_start':'lab_start','transfer':'transfer_button'}

    def __init__(self,workspace,config):
        self.workspace=Path(workspace);self.config=config
        self.events=queue.Queue();self.actions=queue.Queue()
        self.connected=self.busy=self.awaiting_connect=self.pending_cycle=self.closed=False
        self.cleanup_resume_attempted=self.lab_poll_paused=False
        self.manager=None;self.advanced_open=False
        for name in (*self.BUTTONS.values(),'vm_entry','lab_entry','connect_button',
            'credentials','tasks','advanced_toggle','advanced','activity','window'):
            setattr(self,name,ViewValue())
        self.status=ViewValue('Įvesk laboratorijos slaptažodžius.')
        self.environment_text=ViewValue();self.output=Transcript()
        self.thread=threading.Thread(target=self.worker,daemon=True);self.thread.start()
        self._next_auto=0

    def toggle_advanced(self,force=None):self.advanced_open=True if force is None else force

    def submit(self,action,payload=None):
        if self.busy:raise ValueError('Palauk, kol baigsis dabartinis VM veiksmas.')
        if action=='connect':
            if self.manager:raise ValueError('Laboratorijos sesija jau atverta.')
            if not isinstance(payload,(tuple,list)) or len(payload)!=2 or not all(isinstance(v,str) and 0<len(v)<=1024 and '\0' not in v for v in payload):
                raise ValueError('Užpildyk abu esamų slaptažodžių laukus.')
        elif action=='check_boot':
            if not (self.awaiting_connect or (self.manager and self.manager.session and self.manager.session.state in {'awaiting_baseline_boot','awaiting_restore_boot'})):
                raise ValueError('Nėra laukiančio VM paleidimo.')
        else:
            self.render_buttons()
            name=self.BUTTONS.get(action)
            if not name or getattr(self,name).state!='normal':raise ValueError('Šis veiksmas dabar neprieinamas. Patikrink laboratorijos būseną.')
        self.busy=True
        if action=='lab_poll':self.lab_poll_paused=False
        if action not in {'check_boot','scanner_poll','lab_poll'}:self.status.set('Vykdoma…')
        self.actions.put((action,payload))

    def tick(self):
        self.poll()
        if time.monotonic()>=self._next_auto:
            self._next_auto=time.monotonic()+3
            self.auto_boot()

    def snapshot(self):
        if not self.busy:self.render_buttons()
        return {'busy':self.busy,'connected':bool(self.manager and not self.awaiting_connect and self.manager.environment),
            'status':self.status.value,'environment':self.environment_text.value,'history':self.output.value,
            'allowed':[] if self.busy else [action for action,name in self.BUTTONS.items() if getattr(self,name).state=='normal'],
            'pending':bool(self.manager and (self.manager.pending_scan or self.manager.lab.pending or self.manager.scanner_cleanup))}

    def disconnect(self):
        if self.busy:raise ValueError('Pirmiausia palauk dabartinio VM veiksmo pabaigos.')
        self.closed=True;self.actions.put(('close',None));self.thread.join(timeout=20)
        if self.thread.is_alive():raise ValueError('Sesijos uždarymas dar nepatvirtintas.')


OPERATIONS={'refresh','demo','collection_load','catalog_check','plan','result','export',
    'open_results','open_result','mount','open_vm','settings','local_control','lab_connect',
    'lab_action','lab_close','close'}


class DesktopBackend:
    def __init__(self,workspace,lab_status):
        self.workspace=ControlWorkspace(workspace)
        self.lab_status=Path(lab_status)
        self.settings=service.load_settings(self.workspace.root)
        self.catalog=None;self.lab=None

    def config(self):
        record=service.read_json(self.lab_status)
        return {**record,**{k:v for k,v in self.settings.items() if v and k!='collection_root'}}

    def result_path(self,key):
        known={str(p.relative_to(self.workspace.root)):p for p in service.result_paths(self.workspace.root)}
        if not isinstance(key,str) or key not in known:raise ValueError('Pasirink šios programos rezultatą.')
        return known[key]

    def results(self):
        rows=[]
        for path in service.result_paths(self.workspace.root):
            key=str(path.relative_to(self.workspace.root))
            try:rows.append({**service.result_summary(path,self.workspace.root),'key':key})
            except (ValueError,OSError,KeyError,TypeError):
                rows.append({'key':key,'title':'Įrašą reikia patikrinti','state':'Nepavyko patvirtinti','mode':'invalid','count':0,'date':''})
        return rows

    def catalogue(self):
        if not self.catalog:return None
        return {'root':str(self.catalog['root']),'demo':self.catalog.get('demo_only',False),
            'objects':[{**row,'object_id':key,'split':self.catalog['selection'].get(key,{}).get('split','')} for key,row in self.catalog['objects'].items()]}

    def dispatch(self,op,args):
        if op not in OPERATIONS or not isinstance(args,dict):raise ValueError('Neatpažintas programos veiksmas.')
        if self.lab and self.lab.busy and op not in {'refresh','result','open_results','open_vm'}:
            raise ValueError('Palauk vykdomo laboratorijos veiksmo pabaigos.')
        if op=='refresh':
            config=self.config()
            return {'vm':service.probe_vm(config),'budget':service.budget_snapshot(self.workspace.root,config),
                    'results':self.results(),'catalog':self.catalogue(),'settings':{k:config.get(k,'') for k in ('vm_bundle','disk_image')},
                    'workspace':str(self.workspace.root),'lab':self.lab.snapshot() if self.lab else None,
                    'controls':[{'id':key,'title':v[0]} for key,v in CONTROLS.items()]}
        if op in {'demo','collection_load'}:
            if self.lab:raise ValueError('Prieš keisdamas kolekciją uždaryk laboratorijos sesiją.')
            self.catalog=service.demo_catalog(self.workspace.root) if op=='demo' else service.load_catalog(args.get('path',''),self.workspace.root)
            if op=='collection_load':
                self.settings['collection_root']=str(self.catalog['root']);service.save_settings(self.workspace.root,self.settings)
            return self.catalogue()
        if op in {'catalog_check','plan'}:
            if not self.catalog:raise ValueError('Pirmiausia pasirink kolekciją.')
            selected=args.get('selected')
            if not isinstance(selected,list) or not selected or any(not isinstance(v,str) for v in selected):raise ValueError('Pažymėk bent vieną failą.')
            if op=='catalog_check':_,report=service.save_catalog_check(self.workspace.root,self.catalog,selected)
            else:
                _,report=service.save_selection_plan(self.workspace.root,self.catalog,selected,str(args.get('title','Pasirinkimas'))[:100])
            return {'report':report,'results':self.results()}
        if op=='result':
            path=self.result_path(args.get('key'));report=service.validated_result(path,self.workspace.root)
            return {'report':report,'summary':service.result_summary(path,self.workspace.root)}
        if op=='export':
            protected=[self.catalog['root']] if self.catalog else []
            if self.settings.get('collection_root'):protected.append(self.settings['collection_root'])
            return {'path':str(service.export_result(self.result_path(args.get('key')),self.workspace.root,args.get('path',''),protected))}
        if op=='open_results':service.open_path(self.workspace.root);return {}
        if op=='open_result':
            path=self.result_path(args.get('key'));service.validated_result(path,self.workspace.root);service.open_path(path);return {}
        if op=='mount':return service.mount_vm_storage(self.config())
        if op=='open_vm':
            config=self.config();state=service.probe_vm(config)
            if not state['bundle_exists']:raise ValueError('VM nerasta. Prijunk jos saugyklą.')
            if state['state']!='running' and (state['vm_free_bytes'] is None or state['vm_free_bytes']<2*1024**3):raise ValueError('VM saugykloje reikia bent 2 GiB laisvos vietos.')
            service.open_path(config['vm_bundle']);return {}
        if op=='settings':
            if self.lab:raise ValueError('Prieš keisdamas kelius uždaryk laboratorijos sesiją.')
            value={**self.settings}
            for key,suffix in [('vm_bundle','.vmwarevm'),('disk_image','.sparsebundle')]:
                path=args.get(key)
                if not isinstance(path,str) or not Path(path).is_absolute() or Path(path).suffix!=suffix:raise ValueError('Pasirink tinkamą '+suffix+' vietą.')
                service.external_path(path);value[key]=path
            service.save_settings(self.workspace.root,value);self.settings=value;return {}
        if op=='local_control':
            _,report=self.workspace.run(args.get('selected',list(CONTROLS)),str(args.get('title','Mac kontrolė'))[:160])
            return {'report':report,'results':self.results()}
        if op=='lab_connect':
            if self.lab:raise ValueError('Sesija jau atverta. Pirmiausia ją uždaryk.')
            config=self.config()
            if self.catalog:config['collection_root']=self.catalog['root']
            self.lab=NativeSession(self.workspace.root,config)
            try:self.lab.submit('connect',(args.pop('vm_credential',''),args.pop('lab_credential','')))
            except Exception:
                self.lab.disconnect();self.lab=None;raise
            return self.lab.snapshot()
        if op=='lab_action':
            if not self.lab:raise ValueError('Prisijunk prie laboratorijos.')
            action=args.get('action')
            if action not in NativeSession.BUTTONS:raise ValueError('Neatpažintas laboratorijos veiksmas.')
            self.lab.submit(action,args.get('path') if action=='transfer' else None);return self.lab.snapshot()
        if op in {'lab_close','close'}:
            if self.lab:self.lab.disconnect();self.lab=None
            return {'closed':True}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--workspace',required=True);parser.add_argument('--lab-status',required=True)
    options=parser.parse_args();backend=DesktopBackend(options.workspace,options.lab_status)
    requests=queue.Queue()
    def receive():
        for line in sys.stdin:
            if len(line)>65536:requests.put(None);break
            try:requests.put(json.loads(line))
            except (ValueError,TypeError):requests.put({})
        requests.put(None)
    threading.Thread(target=receive,daemon=True).start()
    def emit(value):
        sys.stdout.write(json.dumps(value,ensure_ascii=False,default=str)+'\n');sys.stdout.flush()
    previous=None
    while True:
        try:request=requests.get(timeout=.1)
        except queue.Empty:request=False
        if request is None:break
        if request is not False:
            identifier=request.get('id') if isinstance(request,dict) else None
            try:
                if not isinstance(identifier,int):raise ValueError('Netinkamas užklausos numeris.')
                value=backend.dispatch(request.get('op'),request.get('args',{}))
                emit({'id':identifier,'ok':True,'data':value})
            except Exception as exc:
                message=str(exc) if isinstance(exc,(ValueError,OSError)) else 'Veiksmo klaida: '+type(exc).__name__
                emit({'id':identifier,'ok':False,'error':message})
            finally:request=None
        if backend.lab:
            backend.lab.tick();snapshot=backend.lab.snapshot()
        else:snapshot=None
        if snapshot!=previous:
            emit({'event':'lab','data':snapshot});previous=snapshot


if __name__=='__main__':main()
