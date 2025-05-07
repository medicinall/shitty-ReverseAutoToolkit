import os, subprocess, threading, time, re, tkinter.font as tkfont
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk

"""
Advanced Reverse-Engineering & Malware Analysis Toolkit
Improved Tkinter GUI
"""

# ------------- Helper Functions -------------
def run_cmd(cmd, timeout=5):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout + proc.stderr
    except Exception as e:
        return f"Error running {' '.join(cmd)}: {e}\n"

# Static Analysis
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    def disassemble(path):
        with open(path,'rb') as f: code = f.read()
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        return [f"0x{i.address:x}: {i.mnemonic} {i.op_str}" for i in md.disasm(code, 0x400000)]
except ImportError:
    def disassemble(path):
        return run_cmd(["objdump","-d","--demangle",path]).splitlines()

def extract_strings(path):
    return run_cmd(["strings",path]).splitlines()

def guess_transform(insns):
    for ins in insns:
        m = re.match(r"0x[0-9a-f]+: lea .+,-0x([0-9a-f]+)\(.+\)", ins)
        if m: return -int(m.group(1),16)
        m2 = re.match(r"0x[0-9a-f]+: add .+,(0x[0-9a-f]+)", ins)
        if m2: return int(m2.group(1),16)
    return 0

# Dynamic Analysis
def dynamic_trace(path):
    out = run_cmd(["strace","-e","trace=all","-f",path])
    out += run_cmd(["ltrace",path])
    return out.splitlines()

# Malware Scanning
def yara_scan(path, url):
    try:
        import requests, yara
        rules = yara.compile(source=requests.get(url).text)
        return rules.match(path)
    except:
        return []

# CFG Analysis
def angr_cfg(path):
    try:
        import angr
        proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        return list(cfg.functions.keys())[:20]
    except:
        return []

# ------------- GUI Application -------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔍 RE & Malware Toolkit")
        self.geometry("1100x800")
        # Apply theme
        style = ttk.Style(self)
        style.theme_use('clam')
        # Fonts
        self.font_mono = tkfont.Font(family="Courier", size=10)
        self._create_menu()
        self._create_toolbar()
        self._create_tabs()

    def _create_menu(self):
        menubar = tk.Menu(self)
        filem = tk.Menu(menubar, tearoff=0)
        filem.add_command(label="Open...", command=self._browse)
        filem.add_separator()
        filem.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=filem)
        self.config(menu=menubar)

    def _create_toolbar(self):
        toolbar = ttk.Frame(self, relief=tk.RAISED)
        ttk.Label(toolbar, text="File:").pack(side=tk.LEFT, padx=5)
        self.path_var = tk.StringVar()
        entry = ttk.Entry(toolbar, textvariable=self.path_var, width=60)
        entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Browse", command=self._browse).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Analyze All", command=lambda: threading.Thread(target=self._analyze_all).start()).pack(side=tk.LEFT, padx=5)
        toolbar.pack(fill=tk.X, pady=5)

    def _create_tabs(self):
        self.tabs = ttk.Notebook(self)
        self.frames = {}
        for name in ["Home","Static","Dynamic","Malware","CFG"]:
            frame = ttk.Frame(self.tabs)
            self.tabs.add(frame, text=name)
            self.frames[name] = frame
        self.tabs.pack(expand=1, fill='both')
        # Populate tabs
        self._build_home()
        self._build_static()
        self._build_dynamic()
        self._build_malware()
        self._build_cfg()

    def _build_home(self):
        f = self.frames["Home"]
        self.home_text = scrolledtext.ScrolledText(f, font=self.font_mono)
        self.home_text.pack(expand=1, fill='both', padx=10, pady=10)

    def _build_static(self):
        f = self.frames["Static"]
        btns = ttk.Frame(f)
        ttk.Button(btns, text="Strings", command=self._show_strings).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Disasm", command=self._show_disasm).pack(side=tk.LEFT, padx=5)
        btns.pack(anchor=tk.W, pady=5)
        self.static_text = scrolledtext.ScrolledText(f, font=self.font_mono)
        self.static_text.pack(expand=1, fill='both', padx=10, pady=5)

    def _build_dynamic(self):
        f = self.frames["Dynamic"]
        ttk.Button(f, text="Run Traces", command=self._show_trace).pack(anchor=tk.W, pady=5)
        self.dynamic_text = scrolledtext.ScrolledText(f, font=self.font_mono)
        self.dynamic_text.pack(expand=1, fill='both', padx=10, pady=5)

    def _build_malware(self):
        f = self.frames["Malware"]
        ttk.Button(f, text="YARA Scan", command=self._show_yara).pack(anchor=tk.W, pady=5)
        self.malware_text = scrolledtext.ScrolledText(f, font=self.font_mono)
        self.malware_text.pack(expand=1, fill='both', padx=10, pady=5)

    def _build_cfg(self):
        f = self.frames["CFG"]
        ttk.Button(f, text="Gen CFG", command=self._show_cfg).pack(anchor=tk.W, pady=5)
        self.cfg_text = scrolledtext.ScrolledText(f, font=self.font_mono)
        self.cfg_text.pack(expand=1, fill='both', padx=10, pady=5)

    # Event Handlers
    def _browse(self):
        path = filedialog.askopenfilename()
        if path: self.path_var.set(path)

    def _analyze_all(self):
        path = self.path_var.get()
        if not os.path.isfile(path): messagebox.showerror("Error","Invalid path"); return
        txt = self.home_text; txt.delete('1.0','end')
        txt.insert('end', f"🔍 Analyzing: {path}\n")
        start = time.time()
        # Static
        s = extract_strings(path); txt.insert('end', f"📜 Strings: {len(s)} lines\n")
        i = disassemble(path); txt.insert('end', f"💻 Instructions: {len(i)} lines\n")
        # Dynamic
        d = dynamic_trace(path); txt.insert('end', f"🧵 Trace output: {len(d)} lines\n")
        # Malware
        y = yara_scan(path, 'https://example.com/yara_rules.yar'); txt.insert('end', f"🕷️ YARA matches: {y}\n")
        # CFG
        c = angr_cfg(path); txt.insert('end', f"🔗 CFG funcs: {c}\n")
        txt.insert('end', f"✅ Completed in {time.time()-start:.2f}s\n")

    def _show_strings(self):
        self.static_text.delete('1.0','end')
        self.static_text.insert('end','\n'.join(extract_strings(self.path_var.get())))

    def _show_disasm(self):
        self.static_text.delete('1.0','end')
        self.static_text.insert('end','\n'.join(disassemble(self.path_var.get())))

    def _show_trace(self):
        self.dynamic_text.delete('1.0','end')
        self.dynamic_text.insert('end','\n'.join(dynamic_trace(self.path_var.get())))

    def _show_yara(self):
        res = yara_scan(self.path_var.get(), 'https://example.com/yara_rules.yar')
        self.malware_text.delete('1.0','end')
        self.malware_text.insert('end', str(res))

    def _show_cfg(self):
        res = angr_cfg(self.path_var.get())
        self.cfg_text.delete('1.0','end')
        self.cfg_text.insert('end', str(res))

if __name__ == '__main__':
    app = App()
    app.mainloop()
