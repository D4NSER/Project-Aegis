"""Native VM control window inside the preparation panel; no saved credentials."""
import argparse
import json
from pathlib import Path
import queue
import threading
import uuid
import tkinter as tk
import ui_design as design
from tkinter import ttk, filedialog

from fusion_guest_ops import FusionGuestOps
from fusion_control import ManualBootRequired
from fusion_vix import VixError
from vm_run_manager import VMRunManager
import control_panel as service
from control_workspace import write_json


class VMControlWindow:
    def __init__(self, parent, workspace, config, *, on_close=None):
        self.window = tk.Toplevel(parent)
        self.window.title('Project Aegis – Windows valdymas')
        self.window._aegis_motion=getattr(parent,'_aegis_motion',True)
        self.window.geometry('840x760');self.window.minsize(780,680)
        self.workspace, self.config, self.on_close = Path(workspace), config, on_close
        self.events, self.actions = queue.Queue(), queue.Queue()
        self.connected, self.busy, self.manager = False, False, None
        self.awaiting_connect, self.pending_cycle, self.closed = False, False, False
        self.cleanup_resume_attempted=False
        self.lab_poll_paused=False
        self.window.configure(background=design.BG)
        bottom=ttk.Frame(self.window,padding=(24,12));bottom.pack(side='bottom',fill='x')
        design.Button(bottom,text='Rezultatų aplankas',command=self.open_results).pack(side='left')
        design.Button(bottom,text='Uždaryti sesiją',command=self.close).pack(side='right')
        outer=ttk.Frame(self.window,padding=(24,20,16,0));outer.pack(fill='both',expand=True)
        canvas=tk.Canvas(outer,background=design.BG,highlightthickness=0)
        scrollbar=ttk.Scrollbar(outer,orient='vertical',command=canvas.yview)
        scrollbar.pack(side='right',fill='y');canvas.pack(side='left',fill='both',expand=True)
        canvas.configure(yscrollcommand=scrollbar.set)
        frame=ttk.Frame(canvas,padding=(0,0,8,10));content=canvas.create_window(0,0,anchor='nw',window=frame)
        def layout(event=None):
            canvas.itemconfigure(content,width=canvas.winfo_width())
            canvas.configure(scrollregion=canvas.bbox('all'))
        frame.bind('<Configure>',layout);canvas.bind('<Configure>',layout)
        def wheel(event):
            if event.widget.winfo_class()!='Text':canvas.yview_scroll(-event.delta,'units');return 'break'
        self.window.bind('<MouseWheel>',wheel)
        ttk.Label(frame,text='Tavo Windows laboratorija',font=(design.FONT,24,'bold')).pack(anchor='w')
        ttk.Label(frame,text='Prisijunk vieną kartą. Tada pasirink paruoštą veiksmą.',foreground=design.MUTED).pack(anchor='w',pady=(6,20))
        self.credentials=design.Surface(frame,padding=22)
        self.credentials.pack(fill='x')
        ttk.Label(self.credentials,text='Prisijungimas',style='Heading.TLabel').pack(anchor='w',pady=(0,14))
        fields=ttk.Frame(self.credentials,style='Card.TFrame');fields.pack(fill='x')
        fields.columnconfigure(0,weight=1);fields.columnconfigure(1,weight=1)
        ttk.Label(fields,text='Fusion VM slaptažodis',style='Card.TLabel').grid(row=0,column=0,sticky='w',pady=(0,6))
        ttk.Label(fields,text=config.get('guest_username','AegisLab')+' slaptažodis',style='Card.TLabel').grid(row=0,column=1,sticky='w',padx=(14,0),pady=(0,6))
        self.vm_entry=ttk.Entry(fields,show='•');self.vm_entry.grid(row=1,column=0,sticky='ew')
        self.lab_entry=ttk.Entry(fields,show='•');self.lab_entry.grid(row=1,column=1,sticky='ew',padx=(14,0))
        for entry in (self.vm_entry,self.lab_entry):entry.bind('<Return>',lambda e:self.connect())
        ttk.Label(self.credentials,text='Tik šios sesijos atmintyje · Microsoft paskyros nereikia',
            style='Card.TLabel',foreground=design.MUTED).pack(anchor='w',pady=(12,14))
        ttk.Label(self.credentials,text='Patvirtinamas VM ryšys. Windows darbalaukyje kol kas prisijunk Fusion lange.',
            style='Card.TLabel',foreground=design.MUTED,wraplength=690).pack(anchor='w',pady=(0,14))
        self.connect_button=design.Button(self.credentials,text='Paleisti ir prisijungti  →',style='Primary.TButton',command=self.connect)
        self.connect_button.pack(anchor='w')
        state=design.Surface(frame,padding=22);state.pack(fill='x',pady=(14,0))
        self.status=tk.StringVar(value='Įvesk esamus laboratorijos slaptažodžius.')
        ttk.Label(state,textvariable=self.status,style='Card.TLabel',wraplength=690,justify='left').pack(anchor='w')
        self.activity=ttk.Progressbar(state,mode='indeterminate')
        self.environment_text=tk.StringVar(value='Windows būsena dar nepatikrinta.')
        ttk.Label(state,textvariable=self.environment_text,style='Card.TLabel',foreground=design.MUTED,wraplength=690,justify='left').pack(anchor='w',pady=(10,0))
        self.check_button=design.Button(state,text='Atnaujinti būseną',command=lambda:self.submit('status'),state='disabled')
        self.check_button.pack(anchor='w',pady=(12,0))
        design.Button(state,text='Atverti Windows darbalaukį ↗',command=lambda:service.open_path(self.config['vm_bundle'])).pack(anchor='w',pady=(8,0))
        self.tasks=ttk.Frame(frame);self.tasks.pack(fill='x',pady=(20,0))
        ttk.Label(self.tasks,text='Pasirink veiksmą',font=(design.FONT,15,'bold')).pack(anchor='w',pady=(0,12))
        def task(title,detail,action):
            card=design.Surface(self.tasks,padding=16);card.pack(fill='x',pady=(0,8))
            button=design.Button(card,text=title,command=action,state='disabled',width=31)
            button.pack(side='left',padx=(0,16))
            ttk.Label(card,text=detail,style='Card.TLabel',foreground=design.MUTED,wraplength=370).pack(side='left',fill='x',expand=True)
            return button
        self.cycle_button=task('Patikrinti eigą ir atkūrimą','Trys tekstai → ataskaita → švari VM.',lambda:self.submit('cycle'))
        self.scan_button=task('Patikrinti YARA ir Defender','Kontroliniai tekstai. Gali reikėti Windows patvirtinimo.',lambda:self.submit('scan'))
        self.transfer_button=task('Perduoti pasirinktus failus','Pasirinkimo plano baitų patikra. Failai nevykdomi.',self.choose_transfer)
        self.transfer_hint=ttk.Label(self.tasks,text='Failų perdavimui pirmiausia pasirink kolekciją pagrindiniame lange.',
            foreground=design.MUTED,wraplength=690)
        if not config.get('collection_root'):self.transfer_hint.pack(anchor='w',pady=(0,6))
        self.tasks.pack_forget()
        self.advanced_toggle=design.Button(frame,text='›  Išplėstiniai veiksmai ir eiga',command=self.toggle_advanced)
        self.advanced_toggle.pack(anchor='w',pady=(12,8))
        self.advanced=design.Surface(frame,padding=16)
        self.advanced_open=False
        def extra(text,action):
            button=design.Button(self.advanced,text=text,command=lambda:self.submit(action),state='disabled')
            button.pack(anchor='w',fill='x',pady=3)
            return button
        self.restore_button=extra('Užbaigti VM atkūrimą','restore')
        self.boot_button=extra('Tęsti po paleidimo Fusion','continue_boot')
        self.scan_finish=extra('Gauti skenerių rezultatą','scanner_poll')
        self.scan_defer=extra('Atidėti Defender patikrą ir atkurti VM','scanner_defer')
        self.lab_prepare=extra('Paruošti ARM įrankius','lab_prepare')
        self.lab_start=extra('Paleisti paruoštą PE repeticiją','lab_start')
        self.lab_finish=extra('Gauti PE repeticijos rezultatą','lab_poll')
        self.lab_defer=extra('Atidėti repeticiją ir atkurti VM','lab_defer')
        ttk.Label(self.advanced,text='Veiksmų istorija',style='Heading.TLabel').pack(anchor='w',pady=(16,6))
        self.output=tk.Text(self.advanced,height=7,wrap='word',relief='flat',background='white',font=(design.FONT,11),state='disabled')
        self.output.pack(fill='both',expand=True)
        self.window.protocol('WM_DELETE_WINDOW',self.close)
        threading.Thread(target=self.worker,daemon=True).start()
        self.window.after(100,self.poll);self.window.after(100,self.vm_entry.focus_set);self.window.after(3000,self.auto_boot)

    def toggle_advanced(self, force=None):
        self.advanced_open=not self.advanced_open if force is None else force
        if self.advanced_open:self.advanced.pack(fill='x')
        else:self.advanced.pack_forget()
        self.advanced_toggle.configure(text=('⌄' if self.advanced_open else '›')+'  Išplėstiniai veiksmai ir eiga')

    def connect(self):
        if self.busy:return
        values=self.vm_entry.get(),self.lab_entry.get()
        if not all(values):self.status.set('Užpildyk abu esamų slaptažodžių laukus.');return
        self.vm_entry.delete(0,'end');self.lab_entry.delete(0,'end')
        self.submit('connect',values)

    def choose_transfer(self):
        if self.busy:return
        path=filedialog.askopenfilename(parent=self.window,title='Pasirink išsaugotą kolekcijos planą',
            initialdir=self.workspace/'plans',filetypes=[('Pasirinkimo planas','*.json')])
        if path:self.submit('transfer',path)

    def submit(self, action, payload=None):
        if self.busy:return
        self.busy=True
        self.activity.pack(fill='x',pady=(10,0));self.activity.start(12)
        for widget in (self.connect_button,self.check_button,self.cycle_button,self.restore_button,self.boot_button,self.vm_entry,self.lab_entry,self.scan_button,self.scan_finish,self.scan_defer,self.lab_prepare,self.lab_finish,self.lab_defer,self.lab_start,self.transfer_button):widget.configure(state='disabled')
        if action=='lab_poll':self.lab_poll_paused=False
        if action not in {'check_boot','scanner_poll','lab_poll'}:self.status.set('Vykdoma…')
        self.actions.put((action,payload))

    def worker(self):
        connection=None
        while True:
            action,payload=self.actions.get()
            try:
                if action=='close':
                    if self.manager:self.manager.close()
                    elif connection:connection.close()
                    return
                if action=='connect':
                    vm_credential,lab_credential=payload;payload=None
                    bundle=Path(self.config['vm_bundle']);vmx=bundle/(bundle.stem+'.vmx')
                    if not vmx.is_file():service.mount_vm_storage(self.config)
                    connection=FusionGuestOps(timeout=20);power=connection.open(vmx,vm_credential);vm_credential=None
                    self.manager=VMRunManager(connection,self.config['guest_media_root'],self.workspace,vmx,
                        username=self.config.get('guest_username','AegisLab'),credential=lab_credential,
                        probe=lambda:service.probe_vm(self.config),progress=lambda value:self.events.put(('progress',value)),
                        scanner={k:self.config.get(k) for k in ('yara_executable','yara_sha256')})
                    lab_credential=None
                    if power['powered_off']:connection.power_on()
                    connection.wait_tools()
                    environment=self.manager.deploy();self.manager.status()
                    if self.manager.scanner_cleanup and self.manager.scanner_cleanup.get('kind')=='selection_transfer':
                        self.cleanup_resume_attempted=True
                    self.events.put(('connected',environment))
                elif action=='cycle':
                    self.pending_cycle=True
                    self.events.put(('done',self.manager.cycle()))
                elif action=='restore':self.events.put(('done',self.manager.restore()))
                elif action in {'continue_boot','check_boot'}:
                    if action=='check_boot' and service.probe_vm(self.config).get('state')!='running':
                        self.events.put(('boot_waiting',None));continue
                    if self.awaiting_connect:
                        if not connection.reopen()['powered_on']:raise ManualBootRequired('Start the VM in Fusion')
                        connection.wait_tools();environment=self.manager.deploy();self.manager.status()
                        self.awaiting_connect=False;self.events.put(('connected',environment))
                    else:
                        result=self.manager.continue_after_boot()
                        if self.pending_cycle and result['state']=='baseline_ready':result=self.manager.cycle()
                        self.events.put(('done',result))
                elif action=='status':
                    environment=self.manager.collect_environment();self.manager.status()
                    self.events.put(('connected',environment))
                elif action=='scan':
                    value=self.manager.scan_controls()
                    if not value.get('pending_elevation'):
                        self.events.put(('scanner_restoring',value));self.pending_cycle=True
                        self.events.put(('done',self.manager.cycle()))
                    else:self.events.put(('scanner',value))
                elif action=='scanner_poll':
                    value=self.manager.finish_scanner()
                    if value:
                        self.events.put(('scanner_restoring',value));self.pending_cycle=True
                        self.events.put(('progress','Skenerių rezultatai jau Mac. Dabar atkuriama VM…'))
                        self.events.put(('done',self.manager.cycle()))
                    else:self.events.put(('boot_waiting',None))
                elif action=='scanner_defer':
                    self.manager.defer_scanner();self.events.put(('scanner_deferred_restoring',None));self.pending_cycle=True
                    self.events.put(('done',self.manager.cycle()))
                elif action=='lab_prepare':
                    self.events.put(('lab_waiting',self.manager.lab.prepare(self.config['procmon_vendor_root'])))
                elif action=='lab_start':
                    self.manager.lab.request_rehearsal()
                    self.events.put(('lab_requested',None))
                elif action=='transfer':
                    from vm_selection_transfer import execute
                    value=execute(self.manager,payload,self.config['collection_root'])
                    self.events.put(('transfer_restoring',value));self.pending_cycle=True
                    self.events.put(('done',self.manager.cycle()))
                elif action=='lab_poll':
                    value=self.manager.lab.poll()
                    if value:
                        if value.get('stage')=='awaiting_boot':self.events.put(('done',value['summary']))
                        elif value.get('stage')=='ready_for_rehearsal':self.events.put(('lab_ready',value))
                        else:
                            self.events.put(('lab_restoring',value));self.pending_cycle=True
                            self.events.put(('progress','PE repeticijos įrodymai jau Mac. Atkuriama VM…'))
                            self.events.put(('done',self.manager.cycle()))
                    else:self.events.put(('boot_waiting',None))
                elif action=='lab_defer':
                    self.manager.lab.defer();self.pending_cycle=True
                    self.events.put(('progress','Laboratorijos repeticija atidėta. Atkuriama VM…'))
                    self.events.put(('done',self.manager.cycle()))
            except ManualBootRequired:
                if action=='connect':self.awaiting_connect=True
                self.events.put(('awaiting_connect',None))
            except Exception as exc:
                code=(' / '+str(exc.code)) if isinstance(exc,VixError) else ''
                message=str(exc) if isinstance(exc,ValueError) else type(exc).__name__+code
                # Keep a bounded, credential-free failure record even when a later
                # successful cleanup replaces the current status line.
                folder=self.workspace/'vm-controls';folder.mkdir(exist_ok=True)
                write_json(folder/('failure-'+uuid.uuid4().hex+'.json'),
                           {'action':action,'error_type':type(exc).__name__,'message':message,
                            'experiment_results':False})
                if action in {'scan','transfer'}:self.cleanup_resume_attempted=True
                if action in {'lab_prepare','lab_poll'}:
                    self.lab_poll_paused=True;self.cleanup_resume_attempted=True
                self.events.put(('error',message))
                if action=='connect':
                    if connection:connection.close()
                    connection=None;self.manager=None
            finally:payload=vm_credential=lab_credential=None

    def render_buttons(self):
        for widget in (self.check_button,self.cycle_button,self.restore_button,self.boot_button,
                       self.scan_button,self.scan_finish,self.scan_defer,self.lab_prepare,
                       self.lab_finish,self.lab_defer,self.lab_start,self.transfer_button):
            widget.configure(state='disabled')
        self.connected=self.manager is not None
        if not self.connected:
            for widget in (self.vm_entry,self.lab_entry,self.connect_button):widget.configure(state='normal')
            return
        self.check_button.configure(state='normal')
        if self.awaiting_connect:
            self.check_button.configure(state='disabled');self.boot_button.configure(state='normal');return
        session=self.manager.session
        state=session.state if session else ''
        if (self.manager.pending_scan or self.manager.lab.pending or state in {'result_saved','awaiting_baseline_boot','awaiting_restore_boot'}) and hasattr(self,'advanced'):
            self.toggle_advanced(True)
        clean=bool(self.manager.environment and self.manager.environment.get('personal_accounts_separated')
                   and self.manager.environment.get('network_up') is False and not self.manager.connection.pending)
        self.cycle_button.configure(state='normal' if clean and state in {'ready','baseline_ready','restored'} else 'disabled')
        if self.manager.pending_scan or self.manager.lab.pending:self.cycle_button.configure(state='disabled')
        self.restore_button.configure(state='normal' if state=='result_saved' else 'disabled')
        self.boot_button.configure(state='normal' if state in {'awaiting_baseline_boot','awaiting_restore_boot'} else 'disabled')
        self.scan_button.configure(state='normal' if clean and self.config.get('yara_executable') and state in {'baseline_ready','restored'} and not self.manager.pending_scan and not self.manager.scanner_cleanup and not self.manager.lab.pending else 'disabled')
        self.scan_finish.configure(state='normal' if self.manager.pending_scan else 'disabled')
        self.scan_defer.configure(state='normal' if self.manager.pending_scan else 'disabled')
        self.lab_prepare.configure(state='normal' if clean and self.config.get('procmon_vendor_root') and state in {'baseline_ready','restored'} and not self.manager.pending_scan and not self.manager.scanner_cleanup and not self.manager.lab.pending else 'disabled')
        self.lab_finish.configure(state='normal' if self.manager.lab.pending else 'disabled')
        self.lab_defer.configure(state='normal' if self.manager.lab.pending else 'disabled')
        self.lab_start.configure(state='normal' if self.manager.lab.pending and state in {'baseline_ready','restored'} else 'disabled')
        self.transfer_button.configure(state='normal' if clean and self.config.get('collection_root')
            and state in {'baseline_ready','restored'} and not self.manager.pending_scan
            and not self.manager.scanner_cleanup and not self.manager.lab.pending else 'disabled')

    def poll(self):
        try:
            while True:
                kind,value=self.events.get_nowait()
                if kind=='progress':self.status.set(value);continue
                intermediate=kind in {'scanner_restoring','scanner_deferred_restoring','lab_restoring','transfer_restoring'}
                if not intermediate:
                    self.busy=False
                    if hasattr(self,'activity'):self.activity.stop();self.activity.pack_forget()
                if kind=='boot_waiting':self.render_buttons();continue
                if kind in {'lab_ready','lab_waiting','scanner','lab_requested'} and hasattr(self,'advanced'):
                    self.toggle_advanced(True)
                if kind=='awaiting_connect':
                    self.status.set('Atveriama Windows. Programa pati tęs prisijungimą. Jei Fusion nepaleidžia VM, pasirink „Virtual Machine → Start Up“.')
                    service.open_path(self.config['vm_bundle'])
                elif kind=='connected':
                    self.credentials.pack_forget()
                    self.tasks.pack(fill='x',pady=(20,0),before=self.advanced_toggle)
                    defender=value.get('defender') or {}
                    self.environment_text.set('Windows '+str(value.get('architecture'))+' · Python '+str(value.get('python_version'))+
                        '\nAsmeninės paskyros: '+('atskirtos' if value.get('personal_accounts_separated') else 'reikia patikros')+
                        ' · Tinklas: '+('atjungtas' if value.get('network_up') is False else 'atjungimas nepatvirtintas')+
                        '\nDefender: '+('įjungtas' if defender.get('AntivirusEnabled') else 'nepatvirtintas')+' · Apsauga realiu laiku: '+('įjungta' if defender.get('RealTimeProtectionEnabled') else 'nepatvirtinta'))
                    self.status.set('VM ryšys paruoštas. Pasirink veiksmą. Darbalaukio prisijungimui atverk Windows.')
                elif kind=='done':
                    if value.get('state') in {'awaiting_baseline_boot','awaiting_restore_boot'}:
                        self.status.set('Šaltas VM etapas išsaugotas. Fusion lange pasirink „Virtual Machine → Start Up“, tada čia „Tęsti po paleidimo Fusion“. Šifruotos VM automatinio paleidimo šis Fusion ryšys neatliko.')
                        service.open_path(self.config['vm_bundle'])
                    else:
                        if value.get('vm_restore_verified'):self.pending_cycle=False
                        self.status.set('VM atkūrimas patvirtintas nauju Windows atsakymu. Mac rezultatai išsaugoti.' if value.get('vm_restore_verified') else 'Windows būsena patikrinta: '+value.get('state','nežinoma'))
                    phase={'restored':'Atkūrimas patvirtintas','baseline_ready':'Pradinė kopija paruošta',
                           'ready':'Windows paruošta pradinei kopijai','awaiting_baseline_boot':'Laukiama pradinės VM paleidimo',
                           'awaiting_restore_boot':'VM grąžinta į kopiją; laukiama paleidimo','result_saved':'Rezultatas išsaugotas Mac'}.get(value.get('state'),'Reikia patikros')
                    text=phase+'\n'
                    if value.get('cycle_root'):text+='Kontrolės rezultatas saugomas Mac rezultatų aplanke.\n'
                    text+='Tai trijų kontrolinių tekstų patikra, ne tyrimo eksperimentas.\n\n'
                    self.output.configure(state='normal');self.output.insert('end',text);self.output.see('end');self.output.configure(state='disabled')
                elif kind in {'scanner','scanner_restoring'}:
                    report=value['report'];yara_ok=all((row['yara_status']=='MATCHED')==row['yara_expected_match'] and row['yara_status']!='ERROR' for row in report['files'])
                    av_done=all(row['av_status']!='NOT_RUN' for row in report['files'])
                    message='YARA '+report['yara_version']+': '+('kontroliniai atsakymai sutampa.' if yara_ok else 'reikia patikros.')
                    message+=' Defender: '+('kontroliniai atsakymai išsaugoti.' if av_done else 'laukia patvirtinimo Windows.')
                    if value.get('pending_elevation'):
                        message+=' Windows darbalaukyje paleisk '+Path(value['launcher'].replace('\\','/')).name+' ir patvirtink įprastą UAC „Yes“. Atsakymą programa pasiims automatiškai.'
                    self.status.set(message)
                    self.output.configure(state='normal');self.output.insert('end',message+'\nTai skenerių patikra su nekenkėjiškais tekstais, ne aptikimų eksperimentas.\n\n');self.output.see('end');self.output.configure(state='disabled')
                elif kind=='scanner_deferred_restoring':self.status.set('Defender kontrolė atidėta. Atkuriama VM; palauk, kol bus patvirtinta švari būsena.')
                elif kind=='lab_waiting':
                    if value['inventory'].get('procmon',{}).get('operator_license_accepted') is True:
                        message='ARM įrankiai patikrinti; ankstesnis operatoriaus licencijos patvirtinimas išlikęs. Programa ruošia naują švarią įrankių kopiją.'
                    else:
                        message='ARM įrankių parašai ir kompiliatorius patikrinti. Windows darbalaukyje paleisk '+Path(value['launcher'].replace('\\','/')).name+'. Peržiūrėk Process Monitor licenciją pats, tada uždaryk jo langą. Programa išsaugos paruoštų įrankių pradinę kopiją.'
                    self.status.set(message)
                    self.output.configure(state='normal');self.output.insert('end',message+'\n\n');self.output.see('end');self.output.configure(state='disabled')
                elif kind=='lab_ready':
                    self.status.set('Paruoštų ARM įrankių kopija išsaugota. Windows darbalaukyje paleisk '+value['launcher']+' ir patvirtink įprastą UAC „Yes“. Repeticijos įrodymus programa pasiims pati ir atkurs VM.')
                elif kind=='lab_requested':
                    self.status.set('Tiksli paruošta repeticija paprašyta. Windows lange patvirtink įprastą UAC „Yes“. Rezultatą programa pasiims pati.')
                elif kind=='transfer_restoring':
                    self.status.set('Pasirinkti failai perduoti ir jų atsakymas išsaugotas Mac. Failai nevykdyti. Dabar atkuriama VM.')
                elif kind=='lab_restoring':
                    report=value['report'];message='PE repeticija: '+('visos kontrolės praėjo.' if report['all_checks_passed'] else 'yra nepatvirtintų kontrolių; žiūrėk ataskaitą.')
                    self.status.set(message)
                    self.output.configure(state='normal');self.output.insert('end',message+'\n'+str(value['host_root'])+'\nTai ne tyrimo eksperimentas.\n\n');self.output.see('end');self.output.configure(state='disabled')
                else:
                    message='Veiksmas nebaigtas: '+value
                    if self.manager and self.manager.lab.pending:
                        message+=' Laboratorijos darbas nebaigtas: gauk PE repeticijos rezultatą arba rinkis „Atidėti ir atkurti VM“.'
                    elif self.manager and self.manager.scanner_cleanup:
                        message+=' Skenerių darbo atkūrimas dar būtinas; spausk „Vykdyti kontrolę ir atkurti VM“.'
                    self.status.set(message)
                    self.output.configure(state='normal');self.output.insert('end',message+'\n\n');self.output.see('end');self.output.configure(state='disabled')
                if not intermediate:self.render_buttons()
        except queue.Empty:pass
        self.window.after(100,self.poll)

    def open_results(self):
        path=self.workspace/'vm-controls'
        if path.is_dir():service.open_path(path)

    def auto_boot(self):
        if self.closed:return
        pending=self.awaiting_connect or (self.manager and self.manager.session and self.manager.session.state in {'awaiting_baseline_boot','awaiting_restore_boot'})
        if pending and not self.busy:self.submit('check_boot')
        elif self.manager and self.manager.pending_scan and not self.busy:self.submit('scanner_poll')
        elif self.manager and self.manager.lab.pending and not self.busy and not self.lab_poll_paused:self.submit('lab_poll')
        elif (self.manager and self.manager.scanner_cleanup and not self.busy and not self.cleanup_resume_attempted
              and self.manager.session and self.manager.session.state in {'baseline_ready','restored','result_saved'}):
            self.cleanup_resume_attempted=True;self.submit('cycle')
        self.window.after(3000,self.auto_boot)

    def close(self):
        if self.busy:self.status.set('Palauk, kol baigsis VM veiksmas. Jo nutraukti automatiškai negalima.');return
        parent=self.window.master
        self.closed=True;self.actions.put(('close',None))
        self.window.grab_release();self.window.destroy()
        if parent.winfo_exists():parent.lift();parent.focus_force()
        if self.on_close:self.on_close()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--workspace',required=True);parser.add_argument('--lab-status',required=True);args=parser.parse_args(argv)
    parent=tk.Tk();parent.withdraw();config=json.loads(Path(args.lab_status).read_text())
    VMControlWindow(parent,args.workspace,config,on_close=parent.destroy);parent.mainloop()


if __name__=='__main__':main()
