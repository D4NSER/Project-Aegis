"""Project Aegis desktop lab panel. Local controls, catalogue and live VM status."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import queue
import sys
import threading
import time
import ui_design as design
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from control_workspace import CONTROLS, ControlWorkspace
import control_panel as service

BG, WHITE, NAVY, INK, MUTED, BLUE = design.BG, design.WHITE, design.WHITE, design.INK, design.MUTED, design.ACCENT
GREEN, AMBER, RED, LINE = '#13785a', '#9b650b', '#b73c40', '#e2e7f0'
PAGES = [('overview', 'Darbo erdvė', 'Viskas tavo laboratorijos darbui vienoje vietoje'),
         ('machine', 'VM ir saugykla', 'Windows aplinka ir vieta diske'),
         ('control', 'Kontrolinė patikra', 'Išbandyk failų ir rezultatų eigą'),
         ('catalog', 'Failai', 'Pasirink tik reikalingus kolekcijos failus'),
         ('results', 'Rezultatai', 'Patikros ir pasirinkimo planai vienoje vietoje'),
         ('settings', 'Nustatymai', 'Vietiniai aplankai ir VM pasirinkimas'),
         ('help', 'Kaip naudotis', 'Kas vyksta Mac, o kas turi vykti VM')]
MODES = {'inert_text_control': 'Vietinė kontrolė', 'catalog_hash_check': 'Failų maišos', 'selection_plan': 'Pasirinkimo planas',
         'guest_inert_transfer_control': 'Windows VM kontrolė','scanner_inert_control':'Skenerių kontrolė',
         'benign_pe_rehearsal':'PE repeticija','selection_transfer_control':'Pasirinkimo perdavimas'}


def gb(value):
    return '—' if value is None else '{:.1f} GB'.format(value / 1_000_000_000).replace('.', ',')


def stamp(value):
    try:
        return datetime.fromisoformat(value).astimezone().strftime('%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return str(value)


class App:
    def __init__(self, root, workspace, lab_status=None):
        self.root, self.workspace = root, ControlWorkspace(workspace)
        self.lab_status_path = Path(lab_status) if lab_status else None
        self.settings = service.load_settings(self.workspace.root)
        self.record, self.vm_state, self.budget, self.catalog = {}, {}, None, None
        self.result_items, self.pages, self.nav, self.canvases = {}, {}, {}, {}
        self.busy, self.dialog_open, self.inbox, self.actions = False, False, queue.Queue(), []
        self.vm_controls = None
        self.page_windows, self._page_motion_job = {}, None
        self.root._aegis_motion=True
        design.choose_font(root)
        self.status = tk.StringVar(value='Parengta. Pasirink veiksmą kairėje.')
        root.title('Project Aegis')
        root.geometry('1180x800')
        root.minsize(1020, 720)
        root.configure(bg=BG)
        if sys.platform=='darwin':
            root.createcommand('tk::mac::ShowPreferences',lambda:self.show('settings'))
            root.createcommand('tk::mac::ShowHelp',lambda:self.show('help'))
            root.createcommand('tk::mac::standardAboutPanel',lambda:messagebox.showinfo('Apie Project Aegis',
                'Project Aegis · 0.6\nVietinis laboratorijos valdymas\n\nKontrolinės patikros, failų pasirinkimas ir išsaugoti rezultatai.',parent=root))
        self.style()
        self.build_shell()
        self.build_overview()
        self.build_machine()
        self.build_control()
        self.build_catalog()
        self.build_results()
        self.build_settings()
        self.build_help()
        self.show('overview')
        self.refresh_results()
        self.root.after(80, self.drain)
        self.root.after(150, self.refresh)
        self.root.after(20000, self.poll)
        self.root.protocol('WM_DELETE_WINDOW', self.close)
        if sys.platform=='darwin':self.root.createcommand('tk::mac::Quit',self.close)

    def style(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background=BG, foreground=INK, font=(design.FONT, 12))
        style.configure('TFrame', background=BG)
        style.configure('Card.TFrame', background=WHITE)
        style.configure('TLabel', background=BG)
        style.configure('Card.TLabel', background=WHITE)
        style.configure('Muted.TLabel', foreground=MUTED)
        style.configure('Title.TLabel', font=(design.FONT, 27, 'bold'))
        style.configure('Heading.TLabel', background=WHITE, font=(design.FONT, 14, 'bold'))
        style.configure('Value.TLabel', background=WHITE, font=(design.FONT, 23, 'bold'))
        style.configure('TButton', padding=(13, 9), background=WHITE, borderwidth=1, relief='flat')
        style.configure('TMenubutton',padding=(13,9),background=WHITE,borderwidth=0,
            bordercolor=WHITE,lightcolor=WHITE,darkcolor=WHITE,arrowcolor=MUTED)
        style.map('TButton', background=[('active', '#e9eef9'), ('disabled', '#edf0f5')],
                  foreground=[('disabled', '#8c96a7')])
        style.configure('Primary.TButton', background=BLUE, foreground=WHITE, borderwidth=0)
        style.map('Primary.TButton', background=[('active', '#244bd1'), ('disabled', '#9caedb')], foreground=[('disabled', WHITE)])
        style.configure('TCheckbutton', background=WHITE, padding=(0, 7))
        style.map('TCheckbutton', background=[('active', WHITE)])
        style.configure('Treeview', background=WHITE, fieldbackground=WHITE, rowheight=32, borderwidth=0)
        style.configure('Treeview.Heading', background='#edf1f8', foreground=MUTED, padding=8, relief='flat')
        style.map('Treeview', background=[('selected', '#dfe8ff')], foreground=[('selected', INK)])
        style.configure('TEntry', fieldbackground=WHITE, padding=8, bordercolor=LINE,
            lightcolor=LINE,darkcolor=LINE,relief='flat')
        style.map('TEntry',bordercolor=[('focus',BLUE)],lightcolor=[('focus',BLUE)],darkcolor=[('focus',BLUE)])
        style.configure('TCombobox', padding=6,fieldbackground=WHITE,background=WHITE,
            bordercolor=LINE,lightcolor=LINE,darkcolor=LINE,arrowcolor=MUTED)
        style.map('TCombobox',fieldbackground=[('readonly',WHITE)],background=[('readonly',WHITE)])
        style.configure('Treeview',bordercolor=WHITE,lightcolor=WHITE,darkcolor=WHITE)
        style.configure('Horizontal.TProgressbar', background=BLUE, troughcolor=LINE, borderwidth=0, thickness=8)
        style.layout('Vertical.TScrollbar', [('Vertical.Scrollbar.trough', {'sticky':'ns', 'children':[
            ('Vertical.Scrollbar.thumb', {'expand':1,'sticky':'nswe'})]})])
        style.configure('Vertical.TScrollbar', background='#d2dae7', troughcolor=BG,
            borderwidth=0, arrowsize=7, width=7,lightcolor=BG,darkcolor=BG,bordercolor=BG,gripcount=0)
        style.layout('Horizontal.TScrollbar', [('Horizontal.Scrollbar.trough', {'sticky':'ew', 'children':[
            ('Horizontal.Scrollbar.thumb', {'expand':1,'sticky':'nswe'})]})])
        style.configure('Horizontal.TScrollbar',background='#d2dae7',troughcolor=WHITE,
            borderwidth=0,arrowsize=7,lightcolor=WHITE,darkcolor=WHITE,bordercolor=WHITE,gripcount=0)
        style.layout('Horizontal.TProgressbar', [('Horizontal.Progressbar.trough', {'sticky':'nswe', 'children':[
            ('Horizontal.Progressbar.pbar', {'side':'left','sticky':'ns'})]})])

    def label(self, parent, text='', muted=False, card=True, **kw):
        widget = ttk.Label(parent, text=text, background=WHITE if card else BG,
                           foreground=kw.pop('foreground', MUTED if muted else INK), **kw)
        if 'wraplength' in kw:
            limit = kw['wraplength']
            parent.bind('<Configure>', lambda e, w=widget, maximum=limit:
                        w.configure(wraplength=max(100, min(maximum, e.width - 40))), add='+')
        return widget

    def button(self, parent, text, command, primary=False, action=True):
        widget = design.Button(parent, text=text, command=command, primary=primary)
        if action:
            self.actions.append(widget)
        return widget

    def build_shell(self):
        menubar = tk.Menu(self.root)
        sections = tk.Menu(menubar, tearoff=False)
        for i, (key, title, _) in enumerate(PAGES):
            sections.add_command(label=title, command=lambda k=key: self.show(k),
                                 accelerator=('⌘' if sys.platform == 'darwin' else 'Ctrl+') + str(i + 1))
        menubar.add_cascade(label='Skyriai', menu=sections)
        actions = tk.Menu(menubar, tearoff=False)
        actions.add_command(label='Windows kontrolė ir atkūrimas', command=self.open_vm_controls)
        actions.add_command(label='Atnaujinti VM būseną', command=self.refresh)
        actions.add_command(label='Paleisti vietinę patikrą', command=self.run)
        actions.add_command(label='Atverti mokomąjį katalogą', command=self.load_demo)
        actions.add_command(label='Atnaujinti kolekcijos katalogą', command=self.reload_collection)
        actions.add_command(label='Pasirinkti visus matomus objektus', command=lambda: self.catalog_tree.selection_set(self.catalog_tree.get_children()))
        actions.add_command(label='Patikrinti pasirinktas maišas', command=self.check_catalog)
        actions.add_command(label='Išsaugoti pasirinkimo planą', command=self.plan_selection)
        actions.add_command(label='Eksportuoti pasirinktą rezultatą', command=self.export_selected)
        menubar.add_cascade(label='Veiksmai', menu=actions)
        view=tk.Menu(menubar,tearoff=False)
        self.reduced_motion=tk.BooleanVar(value=False)
        view.add_checkbutton(label='Sumažinti judesį',variable=self.reduced_motion,command=self.set_motion)
        menubar.add_cascade(label='Vaizdas',menu=view)
        self.root.configure(menu=menubar)
        self.sidebar = tk.Frame(self.root, bg=NAVY, width=210, highlightbackground=LINE, highlightthickness=1)
        self.sidebar.pack(side='left', fill='y')
        self.sidebar.pack_propagate(False)
        brand = tk.Frame(self.sidebar, bg=WHITE)
        brand.pack(fill='x', padx=24, pady=(32, 6))
        mark = tk.Canvas(brand, width=34, height=38, bg=WHITE, highlightthickness=0)
        mark.pack(side='left', padx=(0, 10))
        mark.create_polygon(17,2,32,8,30,25,17,36,4,25,2,8,fill=BLUE,outline='')
        mark.create_line(10,19,15,24,25,12,fill=WHITE,width=3)
        tk.Label(brand, text='Aegis', bg=WHITE, fg=INK, font=(design.FONT, 23, 'bold')).pack(side='left')
        tk.Label(self.sidebar, text='Tyrimo laboratorija', bg=NAVY, fg=MUTED, font=(design.FONT, 11)).pack(anchor='w', padx=25, pady=(3, 30))
        self.advanced_nav = tk.Frame(self.sidebar, bg=WHITE)
        order = ['overview', 'catalog', 'results', 'help', 'machine', 'control', 'settings']
        titles_by_key = {key:title for key,title,_ in PAGES}
        for key in order:
            title = titles_by_key[key]
            advanced = key in {'machine', 'control', 'settings'}
            parent = self.advanced_nav if advanced else self.sidebar
            icons={'overview':'◈','catalog':'▤','results':'◷','help':'?','machine':'▣','control':'✓','settings':'⚙'}
            item = design.Button(parent,text=icons[key]+'   '+title,command=lambda k=key:self.show(k))
            item.pack(fill='x',padx=14,pady=4)
            i = next(i for i,p in enumerate(PAGES) if p[0] == key)
            self.root.bind('<{}-Key-{}>'.format('Command' if sys.platform == 'darwin' else 'Control', i + 1),
                           lambda e, k=key: self.show(k))
            self.nav[key] = item
        self.advanced_toggle = design.Button(self.sidebar,text='›  Išplėstiniai',command=self.toggle_advanced)
        self.advanced_toggle.pack(fill='x',padx=14,pady=(22,0))
        self.advanced_open = False
        tk.Label(self.sidebar, text='PROJECT AEGIS\nVietinė darbo aplinka', bg=NAVY, fg=MUTED,
                 justify='left', font=(design.FONT, 10), anchor='w').pack(side='bottom', fill='x', padx=25, pady=28)
        main = ttk.Frame(self.root, padding=(28, 25, 28, 12))
        main.pack(side='left', fill='both', expand=True)
        head = ttk.Frame(main)
        head.pack(fill='x', pady=(0, 21))
        titles = ttk.Frame(head)
        titles.pack(side='left', fill='x', expand=True)
        self.page_title = ttk.Label(titles, style='Title.TLabel')
        self.page_title.pack(anchor='w')
        self.page_sub = ttk.Label(titles, style='Muted.TLabel')
        self.page_sub.pack(anchor='w', pady=(5, 0))
        self.button(head, 'Atnaujinti', self.refresh).pack(side='right')
        self.body = ttk.Frame(main)
        self.body.pack(fill='both', expand=True)
        self.body.grid_propagate(False)
        self.body.rowconfigure(0, weight=1)
        self.body.columnconfigure(0, weight=1)
        ttk.Separator(main).pack(fill='x', pady=(15, 10))
        ttk.Label(main, textvariable=self.status, foreground=MUTED, wraplength=830).pack(anchor='w')

    def page(self, key):
        outer = ttk.Frame(self.body)
        outer.grid(row=0, column=0, sticky='nsew')
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(0, weight=1)
        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0)
        canvas.grid(row=0, column=0, sticky='nsew')
        bar = ttk.Scrollbar(outer, orient='vertical', command=canvas.yview)
        bar.grid(row=0, column=1, sticky='ns')
        def scroll_state(first,last):
            bar.set(first,last)
            if float(first)<=0 and float(last)>=1:bar.grid_remove()
            else:bar.grid()
        canvas.configure(yscrollcommand=scroll_state)
        frame = ttk.Frame(canvas)
        window = canvas.create_window(0, 0, window=frame, anchor='nw')
        def layout(event=None):
            width, height = canvas.winfo_width(), canvas.winfo_height()
            needed = frame.winfo_reqheight()
            canvas.itemconfigure(window, width=width, height=max(needed, height))
            canvas.configure(scrollregion=canvas.bbox('all'))
        frame.bind('<Configure>', layout)
        canvas.bind('<Configure>', layout)
        self.pages[key], self.canvases[key], self.page_windows[key] = outer, canvas, window
        if not self.canvases or len(self.canvases) == 1:
            def wheel(event):
                if event.widget.winfo_class() not in {'Text', 'Treeview', 'TCombobox'}:
                    target = self.canvases.get(getattr(self, 'current_page', ''))
                    if target and target.yview() != (0.0, 1.0):
                        delta = -event.delta if sys.platform == 'darwin' else -int(event.delta / 120)
                        target.yview_scroll(delta, 'units')
            self.root.bind_all('<MouseWheel>', wheel, add='+')
        return frame

    def card(self, parent, title=None):
        box = design.Surface(parent,padding=22)
        if title:
            ttk.Label(box, text=title, style='Heading.TLabel').pack(anchor='w', pady=(0, 12))
        return box

    def text_box(self, parent, height=8):
        widget = tk.Text(parent, bg=WHITE, fg=INK, relief='flat', borderwidth=0, wrap='word',
                         height=height, font=(design.FONT, 12), padx=2, pady=5,
                         highlightthickness=0, selectbackground='#dfe8ff')
        scroll = ttk.Scrollbar(parent, command=widget.yview)
        scroll.pack(side='right', fill='y')
        widget.configure(yscrollcommand=scroll.set)
        widget.pack(fill='both', expand=True)
        widget.configure(state='disabled')
        return widget

    @staticmethod
    def set_text(widget, text):
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', text)
        widget.configure(state='disabled')

    def build_overview(self):
        page = self.page('overview')
        self.hero = design.Hero(page,self.open_vm_controls,lambda:self.show('catalog'))
        self.hero.pack(fill='x',pady=(0,20))
        self.actions.append(self.hero.connect)
        stats = ttk.Frame(page)
        stats.pack(fill='x')
        self.overview_values = {}
        for i, (key, title) in enumerate([('vm', 'WINDOWS VM'), ('space', 'LAISVA VM SAUGYKLOJE'), ('runs', 'IŠSAUGOTI ĮRAŠAI')]):
            stats.columnconfigure(i, weight=1, uniform='stats')
            box = self.card(stats)
            box.grid(row=0, column=i, sticky='nsew', padx=(0 if i == 0 else 10, 0))
            self.label(box, title, muted=True, font=(design.FONT, 9, 'bold')).pack(anchor='w')
            value = ttk.Label(box, text='—', style='Value.TLabel')
            value.pack(anchor='w', pady=(10, 0))
            self.overview_values[key] = value
        box = self.card(page, 'Nuo failų iki išsaugoto rezultato')
        box.pack(fill='x', pady=(16, 0))
        for number,title,detail in [('01','Pasirink failus','HDD katalogas arba mokomieji failai. Pasirinkimas išsaugomas plane.'),
            ('02','Atlik kontrolę Windows','Paruoštos tekstų, skenerių ir nepavojingų programų patikros.'),
            ('03','Peržiūrėk rezultatus','Ataskaita išsaugoma Mac prieš grąžinant VM į švarią kopiją.')]:
            row=ttk.Frame(box,style='Card.TFrame');row.pack(fill='x',pady=8)
            self.label(row,number,foreground=BLUE,font=(design.FONT,15,'bold')).pack(side='left',padx=(0,18))
            texts=ttk.Frame(row,style='Card.TFrame');texts.pack(side='left',fill='x',expand=True)
            self.label(texts,title,font=(design.FONT,12,'bold')).pack(anchor='w')
            self.label(texts,detail,muted=True,wraplength=680).pack(anchor='w',pady=(3,0))
        self.label(page,'Dabar prieinamos kontrolinės patikros. Tyrimo imtis ir tikrų objektų vykdymas dar neparengti.',
            muted=True,card=False,wraplength=790).pack(anchor='w',pady=(16,6))

    def toggle_advanced(self, force=None):
        self.advanced_open = not self.advanced_open if force is None else force
        if self.advanced_open:
            self.advanced_nav.pack(fill='x',after=self.advanced_toggle)
        else:self.advanced_nav.pack_forget()
        self.advanced_toggle.configure(text=('⌄' if self.advanced_open else '›')+'  Išplėstiniai')

    def build_machine(self):
        page = self.page('machine')
        box = self.card(page, 'Gyva Fusion ir saugyklos patikra')
        box.pack(fill='x')
        self.machine_text = tk.StringVar(value='Tikrinama…')
        self.label(box, textvariable=self.machine_text, justify='left', wraplength=760).pack(anchor='w')
        self.space_bar = ttk.Progressbar(box, maximum=100)
        self.space_bar.pack(fill='x', pady=(16, 10))
        self.budget_text = tk.StringVar(value='Biudžeto duomenys dar nepatikrinti.')
        self.label(box, textvariable=self.budget_text, muted=True, wraplength=760).pack(anchor='w')
        actions = ttk.Frame(box, style='Card.TFrame')
        actions.pack(fill='x', pady=(16, 0))
        self.button(actions, 'Atverti Windows VM', self.open_vm, True).pack(side='left')
        self.button(actions, 'Prijungti VM saugyklą', self.mount_storage).pack(side='left', padx=8)
        self.button(actions, 'Atverti laboratoriją', self.open_vm_controls).pack(side='left')
        box = self.card(page, 'Pasirengimas bandymui')
        box.pack(fill='both', expand=True, pady=(16, 0))
        self.readiness_text = tk.StringVar(value='Parengimo įrašas dar neįkeltas.')
        self.label(box, textvariable=self.readiness_text, justify='left', wraplength=760).pack(anchor='w')
        self.label(box, 'Veikiančios VM būsena tikrinama per Fusion. Tinklo ir bendrinimo eilutės\n'
                   'rodo VM konfigūraciją; jos nėra nepriklausomas izoliacijos įrodymas.\n'
                   'Windows valdyme vykdomi tik kontroliniai tekstai. Jei šifruotos VM paleidimas\n'
                   'nepavyksta automatiškai, programa išsaugo etapą ir laukia Start Up Fusion lange.', muted=True, wraplength=760).pack(anchor='w', pady=(18, 0))

    def build_control(self):
        page = self.page('control')
        box = self.card(page, 'Vietinė patikra · šiame kompiuteryje')
        box.pack(fill='x')
        self.label(box, 'Patikrina kopijavimą, SHA-256, paprastą žymeklį ir darbo kopijų išvalymą.\n'
                   'Failai nevykdomi. AV ir YARA šiuo veiksmu nepaleidžiamos.', muted=True, wraplength=760).pack(anchor='w')
        self.run_title = tk.StringVar()
        self.label(box, 'Patikros pavadinimas (nebūtinas)', muted=True).pack(anchor='w', pady=(14, 5))
        ttk.Entry(box, textvariable=self.run_title).pack(fill='x')
        self.choices = {}
        for key, (label, _) in CONTROLS.items():
            value = tk.BooleanVar(value=True)
            self.choices[key] = value
            ttk.Checkbutton(box, text=label, variable=value).pack(anchor='w')
        self.control_button = self.button(box, 'Paleisti vietinę patikrą', self.run, True)
        self.control_button.pack(anchor='w', pady=(10, 0))
        box = self.card(page, 'Patikros eiga ir rezultatas')
        box.pack(fill='both', expand=True, pady=(16, 0))
        self.control_output = self.text_box(box, 7)
        self.set_text(self.control_output, 'Pasirink failus ir paleisk patikrą.\n\n'
                      'Pirmiausia išsaugomi rezultatai, tik tada išvalomos darbo kopijos.\n'
                      'Pradiniai kontroliniai failai ir rezultatai išlieka.')

    def tree(self, parent, columns, height=7):
        frame = ttk.Frame(parent, style='Card.TFrame')
        frame.pack(fill='both', expand=True)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show='headings', height=height, selectmode='extended')
        for key, label, width in columns:
            tree.heading(key, text=label)
            tree.column(key, width=width, minwidth=50, stretch=True)
        vertical = ttk.Scrollbar(frame, orient='vertical', command=tree.yview)
        horizontal = ttk.Scrollbar(frame, orient='horizontal', command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        tree.grid(row=0, column=0, sticky='nsew')
        vertical.grid(row=0, column=1, sticky='ns')
        horizontal.grid(row=1, column=0, sticky='ew')
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return tree

    def build_catalog(self):
        page = self.page('catalog')
        box = self.card(page)
        box.pack(fill='x')
        line = ttk.Frame(box, style='Card.TFrame')
        line.pack(fill='x')
        self.catalog_label = tk.StringVar(value='Kolekcija nepasirinkta. HDD galima prijungti vėliau.')
        self.label(line, textvariable=self.catalog_label, muted=True, wraplength=300).pack(side='left', fill='x', expand=True)
        self.button(line, 'Atnaujinti katalogą', self.reload_collection).pack(side='right', padx=(8, 0))
        self.button(line, 'Pasirinkti kolekciją', self.choose_collection).pack(side='right')
        filters = ttk.Frame(box, style='Card.TFrame')
        filters.pack(fill='x', pady=14)
        self.search, self.split_filter = tk.StringVar(), tk.StringVar(value='Visos dalys')
        self.label(filters,'Paieška',muted=True).pack(side='left',padx=(0,10))
        entry = ttk.Entry(filters, textvariable=self.search)
        entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        entry.bind('<KeyRelease>', lambda e: self.filter_catalog())
        select = ttk.Combobox(filters, textvariable=self.split_filter, values=['Visos dalys', 'Kalibravimas', 'Vertinimas', 'Nepriskirta'], state='readonly', width=17)
        select.pack(side='left')
        select.bind('<<ComboboxSelected>>', lambda e: self.filter_catalog())
        self.catalog_tree = self.tree(box, [('id', 'Objektas', 135), ('project', 'Projektas', 140),
                                           ('label', 'Žyma', 90), ('split', 'Dalis', 110), ('size', 'Dydis', 75), ('ready', 'Tinkamumas', 100)],5)
        self.catalog_tree.bind('<<TreeviewSelect>>', self.catalog_selection)
        self.catalog_detail = tk.StringVar(value='Pasirink kolekciją arba pradėk nuo mokomųjų failų.')
        self.label(box, textvariable=self.catalog_detail, muted=True, wraplength=760).pack(anchor='w', pady=12)
        line = ttk.Frame(box, style='Card.TFrame')
        line.pack(fill='x')
        self.button(line, 'Patikrinti pasirinktas maišas', self.check_catalog, True).pack(side='left')
        self.button(line, 'Pasirinkti visus matomus', lambda: self.catalog_tree.selection_set(self.catalog_tree.get_children()), action=False).pack(side='left', padx=8)
        plan = ttk.Frame(box, style='Card.TFrame')
        plan.pack(fill='x', pady=(12, 0))
        self.plan_title = tk.StringVar(value='Pirmas pasirinkimas')
        ttk.Entry(plan, textvariable=self.plan_title).pack(side='left', fill='x', expand=True, padx=(0, 10))
        self.button(plan, 'Išsaugoti pasirinkimo planą', self.plan_selection).pack(side='left')
        self.label(box, 'Planas tik užregistruoja pasirinkimą ir tikrina maišas. Į VM niekas neįkeliama.\n'
                   'Kolekcija tik skaitoma; pirminiai failai nekeičiami ir nevykdomi.', muted=True, wraplength=760).pack(anchor='w', pady=(14, 0))
        self.button(box, 'Neturi HDD? Atverti mokomąjį katalogą', self.load_demo).pack(anchor='w', pady=(12, 0))

    def build_results(self):
        page = self.page('results')
        box = self.card(page)
        box.pack(fill='both', expand=True)
        line = ttk.Frame(box, style='Card.TFrame')
        line.pack(fill='x', pady=(0, 12))
        self.result_filter = tk.StringVar(value='Visi įrašai')
        select = ttk.Combobox(line, textvariable=self.result_filter, values=['Visi įrašai', *MODES.values()], state='readonly', width=23)
        select.pack(side='left')
        select.bind('<<ComboboxSelected>>', lambda e: self.refresh_results())
        self.button(line, 'Atverti rezultatų aplanką', lambda: self.attempt(lambda: service.open_path(self.workspace.root))).pack(side='right')
        self.result_tree = self.tree(box, [('time', 'Laikas', 115), ('name', 'Pavadinimas', 220), ('count', 'Failai', 50), ('state', 'Būsena', 145)], 5)
        self.result_tree.configure(selectmode='browse')
        self.result_tree.bind('<<TreeviewSelect>>', self.show_result)
        self.result_output = tk.Text(box, bg=WHITE, fg=INK, height=9, wrap='word', relief='flat',
                                     font=(design.FONT, 11), highlightthickness=0, state='disabled')
        self.result_output.pack(fill='both', expand=True, pady=12)
        line = ttk.Frame(box, style='Card.TFrame')
        line.pack(fill='x')
        self.button(line, 'Eksportuoti pasirinktą įrašą', self.export_selected, True).pack(side='left')
        extra=ttk.Menubutton(line,text='Išplėstiniai ▾')
        extra.pack(side='left',padx=8)
        menu=tk.Menu(extra,tearoff=False)
        menu.add_command(label='Atverti pirminį JSON įrašą',command=self.open_result)
        extra.configure(menu=menu)

    def build_settings(self):
        page = self.page('settings')
        box = self.card(page, 'Vietiniai keliai')
        box.pack(fill='x')
        self.setting_vars = {}
        for key, label, picker in [('vm_bundle', 'Windows VM paketas (.vmwarevm)', self.choose_vm),
                                   ('disk_image', 'VM saugykla (.sparsebundle)', self.choose_image)]:
            self.label(box, label, muted=True).pack(anchor='w', pady=(8, 5))
            line = ttk.Frame(box, style='Card.TFrame')
            line.pack(fill='x')
            var = tk.StringVar(value=self.settings.get(key, ''))
            self.setting_vars[key] = var
            ttk.Entry(line, textvariable=var).pack(side='left', fill='x', expand=True, padx=(0, 10))
            self.button(line, 'Pasirinkti', picker).pack(side='left')
        self.button(box, 'Išsaugoti nustatymus', self.store_settings, True).pack(anchor='w', pady=(20, 0))
        box = self.card(page, 'Kur laikomi programos duomenys')
        box.pack(fill='both', expand=True, pady=(16, 0))
        self.label(box, str(self.workspace.root), muted=True, wraplength=740).pack(anchor='w')
        self.label(box, 'Šiame aplanke lieka patikros, planai ir eksportui skirti rezultatai.\n'
                   'Jis yra už viešo kodo saugyklos ir už atkuriamos VM ribų.\n\n'
                   'Windows valdymas naudoja esamus VM ir atskiros lab paskyros slaptažodžius tik sesijos atmintyje.\n'
                   'Patvirtintas laboratorijos biudžetas keičiamas atskirai.', wraplength=740).pack(anchor='w', pady=18)
        self.button(box, 'Atverti programos aplanką', lambda: self.attempt(lambda: service.open_path(self.workspace.root))).pack(anchor='w')

    def build_help(self):
        page = self.page('help')
        box = self.card(page, 'Paprasta darbo eiga')
        box.pack(fill='both', expand=True)
        text = self.text_box(box, 20)
        self.set_text(text, 'PRADĖK ČIA\n\n'
            '1. Desktop atverk „Project Aegis“. Darbo erdvėje spausk „Atverti laboratoriją“.\n\n'
            '2. Įvesk esamus Fusion VM ir AegisLab slaptažodžius. Enter arba „Paleisti ir prisijungti“ '
            'atveria VM ir patvirtina valdymo ryšį. Duomenys laikomi tik šios sesijos atmintyje; '
            'uždarius sesiją juos reikia įvesti iš naujo. Microsoft paskyros nereikia.\n\n'
            '3. Pasirink paruoštą kontrolę. Eigos kontrolė tikrina tris tekstus ir VM atkūrimą. '
            'YARA ir Defender kontrolė tikrina skenerius. Defender ar PE repeticijai gali reikėti '
            'Windows UAC „Yes“. Nepradėk antro veiksmo, kol pirmasis nebaigtas.\n\n'
            '4. „Failai“ skyriuje pasirink kolekciją arba mokomąjį katalogą. Pažymėk objektus, '
            'patikrink jų maišas ir išsaugok pasirinkimo planą. VM sesijoje galima patikrinti tik '
            'šio plano failų perdavimą; perduoti failai nevykdomi.\n\n'
            '5. „Rezultatai“ skyriuje pasirink įrašą ir eksportuok ataskaitą. Rezultatas pirmiausia '
            'išsaugomas Mac, tada atkuriama švari VM kopija. Patvirtintas atkūrimas turi naują Windows atsakymą.\n\n'
            'JEI REIKIA WINDOWS DARBALAUKIO\n\n'
            '„Atverti Windows darbalaukį“ parodo Fusion. Matomame Windows prisijungimo lange '
            'kol kas prisijunk pats prie AegisLab. Automatinis valdymo ryšys dar nereiškia '
            'automatinio darbalaukio atrakinimo. Jei Fusion nepaleidžia VM, pasirink '
            '„Virtual Machine → Start Up“; Aegis tęs pats.\n\n'
            'IŠPLĖSTINIAI\n\n'
            'Kairėje: VM saugykla, vietinė Mac tekstų patikra ir keliai. Laboratorijos lange: '
            'įrankių paruošimas, PE repeticija, nebaigtų veiksmų užbaigimas ir eiga. '
            'Reikalingi nebaigto darbo valdikliai atveriami automatiškai.\n\n'
            'SVARBU DARBUI\n\n'
            'HDD Mac sistemoje tik skaitomas, duomenys įrašomi per Windows PC atskiroje sesijoje. '
            'Bandymų failai vykdomi tik paruoštose Windows kontrolėse. Tikrų tyrimo objektų vykdymas '
            'ir tyrimo eksperimentai dar neparengti.\n\n'
            '„Laisva VM saugykloje“ rodo VM tomo vietą Mac kompiuteryje. Įprastai išjunk '
            'Windows; „Suspend“ neišvalo VM ir papildomai naudoja vietą. ISO netrinamas. '
            'Fusion įrankių juostą palik paslėptą dėl ankstesnės strigties.\n\n'
            'Skyriai pasiekiami ir viršutiniame Mac meniu. Lentelėse keliems objektams '
            'pasirinkti naudok Shift arba ⌘. Failų maišos sutapimas nėra nekenkėjiškumo įrodymas.')

    def set_motion(self):
        self.root._aegis_motion=not self.reduced_motion.get()
        if self.root._aegis_motion:self.hero._start()
        else:self.hero._stop()
        if self.vm_controls:self.vm_controls.window._aegis_motion=self.root._aegis_motion
        if self._page_motion_job:self.root.after_cancel(self._page_motion_job);self._page_motion_job=None
        for key,canvas in self.canvases.items():canvas.coords(self.page_windows[key],0,0)

    def reveal(self,key):
        if self._page_motion_job:self.root.after_cancel(self._page_motion_job);self._page_motion_job=None
        for name,canvas in self.canvases.items():canvas.coords(self.page_windows[name],0,0)
        if not self.root._aegis_motion:return
        start=time.monotonic();canvas=self.canvases[key];window=self.page_windows[key]
        def frame():
            t=min(1,(time.monotonic()-start)/.18)
            canvas.coords(window,0,round(12*(1-t)**3))
            self._page_motion_job=self.root.after(16,frame) if t<1 else None
        frame()

    def show(self, key):
        if key in {'machine','control','settings'} and not self.advanced_open:self.toggle_advanced(True)
        self.pages[key].tkraise()
        self.current_page = key
        if key=='overview':self.hero._start()
        else:self.hero._stop()
        self.reveal(key)
        for name, item in self.nav.items():
            item.configure(selected=name==key)
        _, title, subtitle = next(p for p in PAGES if p[0] == key)
        self.page_title.configure(text=title)
        self.page_sub.configure(text=subtitle)
        if key == 'results':
            self.refresh_results()

    def job(self, label, work, done):
        if self.busy or self.dialog_open:
            self.status.set('Palauk, kol baigsis dabartinis veiksmas arba užverk atskirą valdymo langą.')
            return
        self.busy = True
        self.status.set(label)
        for button in self.actions:
            button.configure(state='disabled')
        def execute():
            try:
                value = work()
                self.inbox.put((done, value, None))
            except Exception as exc:
                self.inbox.put((done, None, str(exc)))
        threading.Thread(target=execute, daemon=True).start()

    def drain(self):
        try:
            while True:
                done, value, error = self.inbox.get_nowait()
                self.busy = False
                for button in self.actions:
                    button.configure(state='normal')
                if error:
                    self.status.set('Veiksmas nebaigtas: ' + error)
                    messagebox.showerror('Veiksmas nebaigtas', error, parent=self.root)
                else:
                    try:
                        done(value)
                    except Exception as exc:
                        self.status.set('Nepavyko parodyti rezultato: ' + str(exc))
                        messagebox.showerror('Rezultato klaida', str(exc), parent=self.root)
        except queue.Empty:
            pass
        self.root.after(80, self.drain)

    def attempt(self, action):
        try:
            return action()
        except (OSError, ValueError, KeyError) as exc:
            self.status.set(str(exc))
            messagebox.showerror('Veiksmas nebaigtas', str(exc), parent=self.root)

    def choose_path(self, dialog, **options):
        if self.busy or self.dialog_open:
            self.status.set('Palauk, kol baigsis dabartinis veiksmas.')
            return ''
        self.dialog_open = True
        try:
            return dialog(parent=self.root, **options)
        finally:
            self.dialog_open = False

    def config(self):
        record = service.read_json(self.lab_status_path) if self.lab_status_path and self.lab_status_path.is_file() else {}
        return record, {**record, **{k: v for k, v in self.settings.items() if v and k != 'collection_root'}}

    def refresh(self):
        if self.busy or self.dialog_open:
            return
        def work():
            record, config = self.config()
            state = service.probe_vm(config)
            budget = service.budget_snapshot(self.workspace.root, config)
            return record, config, state, budget
        def done(value):
            self.record, config, self.vm_state, self.budget = value
            self.render_vm()
            for key, var in self.setting_vars.items():
                if not var.get():
                    var.set(config.get(key, ''))
            self.status.set('Būsena atnaujinta ' + stamp(self.vm_state['checked_at']) + '.')
        self.job('Tikrinama Fusion ir laisva vieta…', work, done)

    def poll(self):
        if not self.busy and not self.dialog_open:
            self.refresh()
        self.root.after(20000, self.poll)

    def render_vm(self):
        s = self.vm_state
        state = {'running': 'Veikia', 'suspended': 'Pristabdyta', 'stopped': 'Išjungta',
                 'storage_unavailable': 'Neprijungta', 'unknown': 'Nežinoma', 'unconfigured': 'Nepasirinkta'}.get(s.get('state'), '—')
        self.overview_values['vm'].configure(text=state)
        self.overview_values['space'].configure(text=gb(s.get('vm_free_bytes')))
        free, memory = s.get('vm_free_bytes'), s.get('memory_bytes')
        reserve = (memory or 6 * 1024**3) + 1024**3
        warning = ''
        if free is not None and free < reserve:
            warning = ('\n\nVM pristabdyta: išsaugota RAM būsena taip pat užima vietą šiame tome.'
                       if s.get('state') == 'suspended' and free >= 2 * 1024**3 else
                       '\n\nMažai vietos: prieš naują RAM būsenos kopiją reikia vietos ir 1 GiB rezervo.')
        network = 'Atjungimas nurodytas' if s.get('network_config') == 'disconnected' else 'Prijungtas arba atjungimas nenurodytas'
        sharing = 'Kopijavimas ir tempimas išjungti' if s.get('sharing_config') == 'disabled' else 'Išjungimas nepatvirtintas'
        self.machine_text.set('VM: {}   ·   patikrinta {}\n\nVM tome laisva: {}   ·   Mac diske laisva: {}\n\n'
                              'Tinklo konfigūracija: {}\nBendrinimo konfigūracija: {}'.format(
                                  state, stamp(s.get('checked_at')), gb(free), gb(s.get('host_free_bytes')), network, sharing)
                              + warning + ('\n\n' + s['error'] if s.get('error') else ''))
        limit = s.get('image_limit_bytes')
        self.space_bar['value'] = max(0, min(100, 100 * (1 - free / limit))) if free is not None and limit else 0
        if self.budget:
            b = self.budget
            self.budget_text.set('Dabar užimta apie {}. Su visa VM talpos riba numatoma {} iš {}.\n'
                                 'Skaičiuojami VM, ISO, Fusion ir vietiniai įrankiai.'.format(
                                     gb(b['current_bytes']), gb(b['reserved_bytes']), gb(b['budget_bytes'])))
        else:
            self.budget_text.set('Viso laboratorijos biudžeto šiuo metu apskaičiuoti nepavyko.\nVM tomo laisva vieta rodoma atskirai.')
        recorded_vm = Path(self.record.get('vm_bundle', '.')).resolve()
        _, config = self.config()
        same = bool(self.record.get('vm_bundle')) and Path(config.get('vm_bundle', '.')).resolve() == recorded_vm
        rows = [('Windows įdiegta', 'windows_installed'), ('Kontroliniai tekstai patikrinti VM', 'guest_cycle_verified'),
                ('Tinklo atjungimas ir bendrinimo nustatymai patikrinti', 'network_and_sharing_checks_verified'),
                ('Švarios būsenos atkūrimas patikrintas kontrolėmis', 'restore_verified')]
        self.readiness_text.set('\n\n'.join(('✓  ' if same and self.record.get(k) is True else '○  ') + title
                                             + ('' if same and self.record.get(k) is True else ' — dar nepatvirtinta') for title, k in rows)
                                + '\n\nTai parengimo įrašas, atskirtas nuo gyvos Fusion patikros.')

    def open_vm(self):
        def work():
            _, config = self.config()
            state = service.probe_vm(config)
            if not state['bundle_exists']:
                raise ValueError('VM nerasta. Pirmiausia prijunk jos saugyklą arba patikrink nustatymus.')
            if state['state'] != 'running' and (state['vm_free_bytes'] is None or state['vm_free_bytes'] < 2 * 1024**3):
                raise ValueError('Prieš paleidžiant VM reikia bent 2 GiB laisvos vietos jos tome ir patikimo vietos rodmens.')
            service.open_path(config['vm_bundle'])
        self.job('Atveriama Windows VM…', work, lambda _: self.status.set('VM atverta per Fusion. Jos paleidimo būseną parodys kita patikra.'))

    def open_vm_controls(self):
        if self.vm_controls and self.vm_controls.window.winfo_exists():
            self.vm_controls.window.lift();return
        if self.busy or self.dialog_open:return
        _, config = self.config()
        if self.catalog:config['collection_root']=self.catalog['root']
        if not config.get('guest_media_root') or not config.get('vm_bundle'):
            self.status.set('Windows valdymui reikia paruošto vietinio kontrolės rinkinio ir VM nustatymų.');return
        from vm_control_ui import VMControlWindow
        self.hero._stop()
        self.dialog_open = True
        def closed():
            self.vm_controls = None;self.dialog_open = False;self.refresh_results();self.refresh()
            if self.current_page=='overview':self.hero._start()
        self.vm_controls = VMControlWindow(self.root,self.workspace.root,config,on_close=closed)
        self.vm_controls.window.transient(self.root)

    def mount_storage(self):
        _, config = self.config()
        self.job('Prijungiama tik pasirinkta VM saugykla…', lambda: service.mount_vm_storage(config),
                 lambda state: (setattr(self, 'vm_state', state), self.render_vm(), self.status.set('VM saugykla prijungta.')))

    def run(self):
        selected, title = [k for k, v in self.choices.items() if v.get()], self.run_title.get()
        def done(value):
            path, report = value
            lines = ['PATIKRA BAIGTA · ' + stamp(report['created_at_utc']), '']
            lines += ['{}: SHA-256 sutampa; žymeklis {}.'.format(CONTROLS[r['id']][0], 'rastas' if r['literal_marker_found'] else 'nerastas') for r in report['files']]
            lines += ['', 'Rezultatai išsaugoti. Darbo kopijų išvalymas patvirtintas.',
                      'AV / YARA: nepaleistos. VM atkūrimas: netikrintas.', '', str(path)]
            self.set_text(self.control_output, '\n'.join(lines))
            self.refresh_results()
            self.status.set('Vietinė patikra baigta. Rezultatas išsaugotas.')
        self.job('Kopijuojami ir tikrinami pasirinkti kontroliniai tekstai…', lambda: self.workspace.run(selected, title), done)

    def choose_collection(self):
        path = self.choose_path(filedialog.askdirectory, title='Pasirink Project Aegis kolekcijos aplanką su catalog/')
        if not path:
            return
        def done(value):
            self.catalog = value
            self.settings['collection_root'] = path
            service.save_settings(self.workspace.root, self.settings)
            self.catalog_label.set('{} objektų · {}'.format(len(value['objects']), path))
            self.filter_catalog()
            self.status.set('Katalogas įkeltas. Failų turinys dar neskaitytas; maišos tikrinamos pasirinkus.')
        self.job('Skaitomi kolekcijos registrai…', lambda: service.load_catalog(path, self.workspace.root), done)

    def load_demo(self):
        def done(value):
            self.catalog = value
            self.catalog_label.set('MOKOMASIS KATALOGAS · 3 nekenkėjiški tekstai · tyrimo imčiai nepriklauso')
            self.filter_catalog()
            self.show('catalog')
            self.status.set('Atverti tik vietoje sugeneruoti mokomieji tekstai. HDD nenaudojamas.')
        self.job('Parengiamas mokomasis katalogas…', lambda: service.demo_catalog(self.workspace.root), done)

    def reload_collection(self):
        path = self.settings.get('collection_root')
        if not path:
            if self.catalog:
                path = self.catalog['root']
            else:
                self.status.set('Kolekcija dar nepasirinkta. Pasirink aplanką arba atverk mokomąjį katalogą.')
                return
        def done(value):
            self.catalog = value
            self.catalog_label.set('{} objektų · {}'.format(len(value['objects']), path))
            self.filter_catalog()
            self.status.set('Kolekcijos katalogas atnaujintas.')
        self.job('Atnaujinamas kolekcijos katalogas…', lambda: service.load_catalog(path, self.workspace.root), done)

    def filter_catalog(self):
        self.catalog_tree.delete(*self.catalog_tree.get_children())
        if not self.catalog:
            return
        query = self.search.get().strip().casefold()
        split = {'Kalibravimas': 'calibration', 'Vertinimas': 'evaluation', 'Nepriskirta': ''}.get(self.split_filter.get())
        for key, row in self.catalog['objects'].items():
            part = self.catalog['selection'].get(key, {}).get('split', '')
            if split is not None and part != split or query and query not in ' '.join(row.values()).casefold():
                continue
            self.catalog_tree.insert('', 'end', iid=key, values=(key, row['project_id'], row['label'],
                                     {'calibration': 'Kalibravimas', 'evaluation': 'Vertinimas', '': 'Nepriskirta'}[part],
                                     row['bytes'] + ' B', row['eligibility_status']))
        self.catalog_selection()

    def catalog_selection(self, event=None):
        selected = self.catalog_tree.selection()
        if not self.catalog:
            return
        if len(selected) == 1:
            row = self.catalog['objects'][selected[0]]
            self.catalog_detail.set('{}\nSHA-256: {}\nPasirinktas 1 failas. Maiša dar turi būti patikrinta.'.format(row['relative_path'], row['sha256']))
        else:
            self.catalog_detail.set('Matoma {} objektų. Pasirinkta {}. Paieška pagal objektą, projektą ar kitus metaduomenis.'.format(
                len(self.catalog_tree.get_children()), len(selected)))

    def check_catalog(self):
        if not self.catalog:
            self.status.set('Pirmiausia pasirink kolekcijos aplanką arba atverk mokomąjį katalogą.')
            return
        catalog, selected = self.catalog, list(self.catalog_tree.selection())
        def done(value):
            _, report = value
            good = sum(r['verified'] for r in report['files'])
            self.catalog_detail.set('Patikrinta {} / {} failų. {}\nPatikros rezultatas išsaugotas Mac.'.format(
                good, len(report['files']), 'Visos maišos sutampa.' if report['all_verified'] else 'Rasti neatitikimai.'))
            self.refresh_results()
            self.status.set('Pasirinktų failų maišos patikrintos. Pirminiai failai nepakeisti.')
        self.job('Skaitomi tik pasirinktų objektų baitai ir tikrinamos maišos…',
                 lambda: service.save_catalog_check(self.workspace.root, catalog, selected), done)

    def plan_selection(self):
        if not self.catalog:
            return self.check_catalog()
        catalog, selected, title = self.catalog, list(self.catalog_tree.selection()), self.plan_title.get()
        def done(value):
            self.refresh_results()
            self.status.set('Pasirinkimo planas išsaugotas. Bandymas nepaleistas, failai į VM neperduoti.')
        self.job('Tikrinamos maišos ir išsaugomas pasirinkimo planas…',
                 lambda: service.save_selection_plan(self.workspace.root, catalog, selected, title), done)

    def refresh_results(self):
        previous = self.result_tree.selection()
        self.result_tree.delete(*self.result_tree.get_children())
        self.result_items = {}
        count = 0
        for path in service.result_paths(self.workspace.root):
            count += 1
            key = str(path.relative_to(self.workspace.root))
            try:
                item = service.result_summary(path, self.workspace.root)
                if self.result_filter.get() != 'Visi įrašai' and MODES[item['mode']] != self.result_filter.get():
                    continue
                values = (stamp(item['date']), item['title'], item['count'], item['state'])
            except (OSError, ValueError, KeyError, TypeError):
                values = ('—', 'Nepavyko perskaityti įrašo', '—', 'Reikia patikros')
            self.result_items[key] = path
            self.result_tree.insert('', 'end', iid=key, values=values)
        self.overview_values['runs'].configure(text=str(count))
        if previous and previous[0] in self.result_items:
            self.result_tree.selection_set(previous[0])
            self.result_tree.focus(previous[0])
            self.show_result()
        elif self.result_items:
            first=next(iter(self.result_items))
            self.result_tree.selection_set(first)
            self.result_tree.focus(first)
            self.show_result()
        else:
            self.set_text(self.result_output, 'Įrašų dar nėra. Pradėk nuo vietinės kontrolinės patikros.')

    def selected_result(self):
        selection = self.result_tree.selection()
        if not selection:
            raise ValueError('Pasirink rezultatą lentelėje.')
        return self.result_items[selection[0]]

    def show_result(self, event=None):
        if not self.result_tree.selection():
            return
        try:
            path = self.selected_result()
            report = service.validated_result(path, self.workspace.root)
            lines = [report.get('title') or MODES[report['mode']], stamp(report['created_at_utc']),
                     'Tai kontrolė arba planas; tyrimo eksperimentas neatliktas.', '']
            for row in report['files']:
                good = row.get('verified', row.get('hash_verified'))
                lines.append('{} · {} B · {}'.format(row.get('object_id', row.get('id', '—')), row.get('bytes', '—'),
                             'maiša sutampa' if good else 'maiša nepatvirtinta'))
            if report['mode'] == 'inert_text_control':
                lines += ['', 'Darbo kopijos: ' + ('pašalintos' if service.cleanup_confirmed(path) else 'išvalymas nepatvirtintas')]
            if report['mode'] == 'guest_inert_transfer_control':
                from vm_results import restore_confirmed
                lines += ['', 'AV / YARA: nepaleistos. VM atkūrimas: '+('patvirtintas nauju Windows atsakymu' if restore_confirmed(path,self.workspace.root) else 'dar nepatvirtintas')+'.',str(path)]
            elif report['mode']=='scanner_inert_control':
                lines+=['','YARA '+report['yara_version']+' · kontrolinis žymeklis nėra kenkėjiškumo klasifikacija.']
                lines += [row['id']+': YARA '+row['yara_status']+' · Defender '+row['av_status'] for row in report['files']]
                lines += ['',str(path)]
            elif report['mode']=='benign_pe_rehearsal':
                lines+=['','Dvi nekenkėjiškos .NET AnyCPU PE programos; ne visų native PE suderinamumo patikra.']
                lines += [key+': '+('patvirtinta' if passed else 'reikia patikros') for key,passed in report['checks'].items()]
                lines += ['','VM atkūrimas: '+('patvirtintas atskiru įrodymu' if path.with_name('restoration.json').is_file() else 'dar laukia'),str(path)]
            elif report['mode']=='selection_transfer_control':
                lines+=['','Tik pasirinkto poaibio baitų perdavimas. Failai nevykdyti, AV / YARA nepaleistos.']
                lines += [row['id']+': '+row['status'] for row in report['files']]
                lines += ['','VM atkūrimas: '+('patvirtintas; perduotų failų nebėra' if path.with_name('restoration.json').is_file() else 'dar laukia'),str(path)]
            else:lines += ['', 'AV / YARA: nepaleistos. Švarios VM būsenos atkūrimas: netikrintas.', str(path)]
            self.set_text(self.result_output, '\n'.join(line for line in lines if line != str(path)))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self.set_text(self.result_output, 'Įrašas neparodytas: ' + str(exc))

    def export_selected(self):
        try:
            path = self.selected_result()
            report = service.validated_result(path, self.workspace.root)
        except (OSError, ValueError) as exc:
            return messagebox.showerror('Pasirink rezultatą', str(exc), parent=self.root)
        target = self.choose_path(filedialog.asksaveasfilename, title='Eksportuoti rezultatą (JSON + CSV)',
                                            initialfile=report['run_id'] + '.zip', defaultextension='.zip', filetypes=[('ZIP archyvas', '*.zip')])
        if target:
            protected = [self.catalog['root']] if self.catalog else []
            if self.settings.get('collection_root'):
                protected.append(self.settings['collection_root'])
            self.job('Eksportuojamas pasirinktas rezultatas…', lambda: service.export_result(path, self.workspace.root, target, protected),
                     lambda p: self.status.set('Eksportuota: ' + str(p)))

    def open_result(self):
        def action():
            path = self.selected_result()
            service.validated_result(path, self.workspace.root)
            service.open_path(path)
        self.attempt(action)

    def choose_vm(self):
        path = self.choose_path(filedialog.askdirectory, title='Pasirink .vmwarevm paketą')
        if path:
            self.setting_vars['vm_bundle'].set(path)

    def choose_image(self):
        path = self.choose_path(filedialog.askdirectory, title='Pasirink .sparsebundle atvaizdą')
        if path:
            self.setting_vars['disk_image'].set(path)

    def store_settings(self):
        def action():
            settings = dict(self.settings)
            for key, var in self.setting_vars.items():
                value = var.get().strip()
                if value:
                    suffix = '.vmwarevm' if key == 'vm_bundle' else '.sparsebundle'
                    if not Path(value).is_absolute() or Path(value).suffix != suffix:
                        raise ValueError('Reikia pilno kelio į ' + suffix + ' paketą.')
                    service.external_path(value)
                settings[key] = value
            service.save_settings(self.workspace.root, settings)
            self.settings = settings
            self.status.set('Nustatymai išsaugoti tik šiame kompiuteryje.')
            self.refresh()
        self.attempt(action)

    def close(self):
        if self.vm_controls:
            self.vm_controls.window.lift()
            self.status.set('Pirmiausia užbaik ir uždaryk Windows valdymo sesiją.');return
        if self.busy:
            messagebox.showinfo('Veiksmas dar vyksta', 'Palauk, kol bus išsaugotas rezultatas. Tada galėsi užverti programą.', parent=self.root)
            return
        self.root.destroy()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--lab-status')
    args = parser.parse_args()
    root = tk.Tk()
    try:
        App(root, args.workspace, args.lab_status)
    except (ValueError, OSError) as exc:
        root.withdraw()
        messagebox.showerror('Project Aegis nepaleista', str(exc), parent=root)
        root.destroy()
        return 1
    root.mainloop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
