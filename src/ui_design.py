"""Local, vector-drawn surfaces and motion. No assets, downloads or VM actions."""
import math
import time
import tkinter as tk
from tkinter import font as tkfont, ttk

BG = '#f4f5fa'
WHITE = '#ffffff'
INK = '#20263d'
MUTED = '#7a8097'
ACCENT = '#7660dc'
LINE = '#e9eaf3'
FONT = 'Avenir Next'


def choose_font(root):
    global FONT
    installed = set(tkfont.families(root))
    FONT = next((name for name in ('Avenir Next', 'SF Pro Text', 'Helvetica Neue', 'Helvetica') if name in installed), 'TkDefaultFont')
    return FONT


def motion(widget):
    return bool(getattr(widget.winfo_toplevel(), '_aegis_motion', True))


def blend(first, last, amount):
    amount = min(1, max(0, amount))
    a = [int(first[i:i+2], 16) for i in (1, 3, 5)]
    b = [int(last[i:i+2], 16) for i in (1, 3, 5)]
    return '#' + ''.join(f'{round(x+(y-x)*amount):02x}' for x, y in zip(a, b))


def rounded(canvas, x1, y1, x2, y2, radius=14, **options):
    r = max(0, min(radius, (x2-x1)/2, (y2-y1)/2))
    points = [x1+r,y1, x2-r,y1, x2,y1, x2,y1+r, x2,y2-r, x2,y2,
              x2-r,y2, x1+r,y2, x1,y2, x1,y2-r, x1,y1+r, x1,y1]
    return canvas.create_polygon(points, smooth=True, splinesteps=24, **options)


class Button(tk.Canvas):
    """Rounded mouse/keyboard button with cancellable, nonblocking hover motion."""
    def __init__(self, parent, text='', command=None, *, primary=False, style='', state='normal', width=None, **options):
        self._text, self._command, self._enabled = text, command, state != 'disabled'
        self._primary = primary or style == 'Primary.TButton'
        self._selected, self._hover, self._pressed = False, False, False
        self._job, self._color, self._foreground = None, None, None
        self._explicit_width = width
        self._font = tkfont.Font(family=FONT, size=11, weight='bold')
        try: background = parent.cget('background')
        except tk.TclError: background = WHITE
        super().__init__(parent, background=background, highlightthickness=0, borderwidth=0,
                         height=44, takefocus=True, cursor='hand2', **options)
        self._size()
        self.bind('<Configure>', lambda e:self._draw())
        self.bind('<Enter>', lambda e:self._hover_to(True))
        self.bind('<Leave>', self._leave)
        self.bind('<ButtonPress-1>', self._press)
        self.bind('<ButtonRelease-1>', self._release)
        self.bind('<KeyPress-space>', self._press)
        self.bind('<KeyRelease-space>', self._key_release)
        self.bind('<Return>', lambda e:self.invoke())
        self.bind('<FocusIn>', lambda e:self._draw())
        self.bind('<FocusOut>', lambda e:self._draw())
        self.bind('<Destroy>', lambda e:self._cancel() if e.widget is self else None)

    def _size(self):
        width = self._font.measure(self._text) + 36
        if self._explicit_width: width = max(width, self._font.measure('0') * self._explicit_width)
        super().configure(width=width)

    def _palette(self):
        if not self._enabled:return '#ececf4', '#9a9daf'
        if self._primary:return ('#5843b4' if self._pressed else '#6750c8' if self._hover else ACCENT), WHITE
        if self._selected:return '#eeeafa', '#6851c9'
        return ('#e5def9' if self._pressed else '#f0edf9' if self._hover else '#f8f8fc'), INK

    def _draw(self):
        if not self.winfo_exists():return
        self.delete('all')
        width,height = self.winfo_width(),self.winfo_height()
        color,foreground = self._palette()
        self._color = self._color or color
        rounded(self, 1, 1, width-1, height-2, 12, fill=self._color, outline='')
        if self.focus_get() is self:
            rounded(self, 4, 4, width-4, height-5, 10, fill='', outline=WHITE if self._primary else ACCENT, width=2)
        self.create_text(width/2, height/2-1+(1 if self._pressed else 0), text=self._text,
                         font=self._font, fill=foreground)

    def _cancel(self):
        if self._job:
            self.after_cancel(self._job);self._job=None

    def _hover_to(self, value):
        self._hover = value
        self._cancel()
        target,_ = self._palette()
        start=self._color or target;began=time.monotonic()
        def tick():
            amount=min(1,(time.monotonic()-began)/.14) if motion(self) else 1
            self._color=blend(start,target,1-(1-amount)**3);self._draw()
            self._job=self.after(16,tick) if amount<1 else None
        tick()

    def _leave(self,event):
        self._pressed=False;self._hover_to(False)

    def _press(self,event):
        if self._enabled:
            self.focus_set();self._pressed=True;self._hover_to(self._hover)
        return 'break'

    def _release(self,event):
        pressed=self._pressed
        self._pressed=False;self._hover_to(self._hover)
        if pressed and 0<=event.x<self.winfo_width() and 0<=event.y<self.winfo_height():self.invoke()
        return 'break'

    def _key_release(self,event):
        pressed=self._pressed;self._pressed=False;self._hover_to(self._hover)
        if pressed:self.invoke()
        return 'break'

    def invoke(self):
        if self._enabled and self._command:return self._command()

    def configure(self, cnf=None, **options):
        if cnf is not None:return super().configure(cnf,**options)
        if not hasattr(self,'_font'):return super().configure(**options)
        if 'state' in options:self._enabled=options.pop('state')!='disabled'
        if 'text' in options:self._text=options.pop('text');self._size()
        if 'command' in options:self._command=options.pop('command')
        if 'selected' in options:self._selected=options.pop('selected')
        options.pop('fg',None)
        if options:super().configure(**options)
        self._cancel();self._color=self._palette()[0];self._draw()

    config=configure

    def cget(self,key):
        if key=='state':return 'normal' if self._enabled else 'disabled'
        if key=='text':return self._text
        return super().cget(key)


class Surface(ttk.Frame):
    """A normal content frame, with geometry delegated to its rounded shell."""
    def __init__(self,parent,*,padding=20,**options):
        try: background=parent.cget('background')
        except tk.TclError:background=BG
        self.shell=tk.Canvas(parent,background=background,highlightthickness=0,borderwidth=0,width=1,height=1)
        super().__init__(self.shell,style='Card.TFrame',**options)
        self._padding=padding
        self._window=self.shell.create_window(padding,padding,window=self,anchor='nw')
        self.bind('<Configure>',self._layout,add='+')
        self.shell.bind('<Configure>',self._layout,add='+')

    def _layout(self,event=None):
        padding=self._padding
        wanted_h=self.winfo_reqheight()+padding*2+3
        wanted_w=self.winfo_reqwidth()+padding*2
        if int(self.shell.cget('height'))!=wanted_h:self.shell.configure(height=wanted_h)
        if int(self.shell.cget('width'))!=wanted_w:self.shell.configure(width=wanted_w)
        w,h=self.shell.winfo_width(),self.shell.winfo_height()
        self.shell.itemconfigure(self._window,width=max(1,w-padding*2),height=max(self.winfo_reqheight(),h-padding*2-3))
        self.shell.delete('surface')
        rounded(self.shell,1,4,w-1,h-1,18,fill='#e9eaf2',outline='',tags='surface')
        rounded(self.shell,1,1,w-1,h-4,18,fill=WHITE,outline=LINE,width=1,tags='surface')
        self.shell.tag_lower('surface')

    def pack(self,*args,**kwargs):return self.shell.pack(*args,**kwargs)
    def grid(self,*args,**kwargs):return self.shell.grid(*args,**kwargs)
    def pack_forget(self):return self.shell.pack_forget()
    def grid_forget(self):return self.shell.grid_forget()


class Hero(tk.Canvas):
    """Decorative local vector scene; never represents a measurement or progress."""
    def __init__(self,parent,on_connect,on_files):
        super().__init__(parent,background=BG,highlightthickness=0,height=240)
        self._phase=0;self._job=None;self._bob=0;self._center=None;self._until=0
        self.connect=Button(self,text='Atverti laboratoriją  →',command=on_connect,primary=True)
        self.files=Button(self,text='Pasirinkti failus',command=on_files)
        for button in (self.connect,self.files):button.configure(background='#20263e')
        self._first=self.create_window(26,185,window=self.connect,anchor='nw')
        self._second=self.create_window(260,185,window=self.files,anchor='nw')
        self.bind('<Configure>',lambda e:self._draw())
        self.bind('<Map>',self._start)
        self.bind('<Unmap>',lambda e:self._stop())
        self.bind('<Destroy>',lambda e:self._stop() if e.widget is self else None)

    def _draw(self):
        self.delete('art')
        self._bob=0;self._center=None
        w=self.winfo_width()
        rounded(self,0,0,w,238,22,fill='#20263e',outline='',tags='art')
        self.create_text(28,28,text='P R O J E C T   A E G I S',anchor='nw',fill='#c5b8f3',font=(FONT,9,'bold'),tags='art')
        self.create_text(26,57,text='Tavo tyrimo erdvė.',anchor='nw',fill=WHITE,font=(FONT,30,'bold'),tags='art')
        self.create_text(28,112,text='Windows laboratorija, pasirinkti failai\nir išsaugoti rezultatai. Viskas vienoje vietoje.',
            anchor='nw',fill='#bec3d9',font=(FONT,12),width=max(270,w-310),tags='art')
        if w>700:
            cx,cy=w-130,117
            self._center=cx,cy
            self.create_oval(cx-98,cy-96,cx+98,cy+96,fill='#2a2b4c',outline='',tags='art')
            self.create_oval(cx-76,cy-75,cx+76,cy+75,outline='#494363',dash=(3,7),tags='art')
            rounded(self,cx-53,cy-48,cx+62,cy+39,13,fill='#383758',outline='#777094',tags=('art','back'))
            rounded(self,cx-69,cy-31,cx+40,cy+55,13,fill='#e9e3ff',outline='',tags=('art','front'))
            self.create_line(cx-50,cy-10,cx+21,cy-10,fill='#c3b4e7',width=2,tags=('art','front'))
            for i in range(3):self.create_oval(cx-51+i*8,cy-20,cx-48+i*8,cy-17,fill='#a796d1',outline='',tags=('art','front'))
            self.create_polygon(cx-17,cy+1,cx+8,cy+9,cx+4,cy+31,cx-17,cy+43,cx-38,cy+31,cx-42,cy+9,
                fill=ACCENT,outline='',smooth=True,tags=('art','front'))
            self.create_line(cx-28,cy+22,cx-20,cy+29,cx-7,cy+14,fill=WHITE,width=3,tags=('art','front'))
            for i in range(3):
                angle=self._phase*.15+i*2.1
                x,y=cx+math.cos(angle)*88,cy+math.sin(angle)*88
                self.create_oval(x-3,y-3,x+3,y+3,fill='#b7a3f0',outline='',tags=('art','orb'+str(i)))
        self.tag_lower('art')
        self.coords(self._second,28+self.connect.winfo_reqwidth()+10,185)

    def _start(self,event=None):
        if self._job is None and motion(self):
            self._until=time.monotonic()+1.8
            self._tick()

    def _tick(self):
        self._job=None
        if not self.winfo_ismapped() or not motion(self) or time.monotonic()>=self._until:return
        if self._center:
            self._phase+=.075
            bob=math.sin(self._phase)*4
            self.move('front',0,bob-self._bob);self.move('back',0,self._bob-bob);self._bob=bob
            cx,cy=self._center
            for i in range(3):
                angle=self._phase*.15+i*2.1
                x,y=cx+math.cos(angle)*88,cy+math.sin(angle)*88
                self.coords('orb'+str(i),x-3,y-3,x+3,y+3)
        self._job=self.after(90,self._tick)

    def _stop(self):
        if self._job:self.after_cancel(self._job);self._job=None
