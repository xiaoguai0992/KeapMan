import os
import re
import sys
import gdb
import json
import traceback

VMLINUX_PATH = None
POC_PATH = None
GDBSERVER_PORT = None
OUT_FILE = None
POC_NAME = None
CURRENT_TASK_OFF = None

bpaddr = {}
bpname = {}

class TraceManager:
    def __init__(self):
        self.trace = []

    def add(self, entry):
        self.trace.append(entry)

    def dump(self, f):
        for entry in self.trace:
            f.write(str(entry)+'\n')

trace_mgr = TraceManager()

class TraceEntry:
    def __init__(self, entry_name, addr, uline, regs):
        self.entry_name = entry_name
        self.addr = addr
        self.uline = uline
        self.regs = regs

    def dump_regs(self):
        return f'{self.regs["RAX"]} {self.regs["RDI"]} {self.regs["RSI"]} {self.regs["RDX"]} {self.regs["R10"]} {self.regs["R8"]} {self.regs["R9"]} '
    
    def __str__(self):
        return ''

class CopyToUserEntry(TraceEntry):
    def __init__(self, entry_name, addr, uline, regs, to, sz):
        super().__init__(entry_name, addr, uline, regs)
        self.to = to
        self.sz = sz
    
    def __str__(self):
        return self.dump_regs() + f'{self.entry_name} {self.addr} {self.uline} {hex(self.to)} {hex(self.sz)}'

def copy_to_user_handler(addr, uline, regs):
    frame = gdb.newest_frame().select()
    rdi = int(gdb.parse_and_eval("$rdi")) & 0xFFFFFFFFFFFFFFFF # to
    rsi = int(gdb.parse_and_eval("$rsi")) & 0xFFFFFFFFFFFFFFFF # from
    rdx = int(gdb.parse_and_eval("$rdx")) & 0xFFFFFFFFFFFFFFFF # n
    trace_mgr.add(CopyToUserEntry('copy_to_user', addr, uline, regs, rdi, rdx))

class CopyFromUserEntry(TraceEntry):
    def __init__(self, entry_name, addr, uline, regs, fr, sz):
        super().__init__(entry_name, addr, uline, regs)
        self.fr = fr
        self.sz = sz
    
    def __str__(self):
        return self.dump_regs() + f'{self.entry_name} {self.addr} {self.uline} {hex(self.fr)} {hex(self.sz)}'

def copy_from_user_handler(addr, uline, regs):
    frame = gdb.newest_frame().select()
    rdi = int(gdb.parse_and_eval("$rdi")) & 0xFFFFFFFFFFFFFFFF # to
    rsi = int(gdb.parse_and_eval("$rsi")) & 0xFFFFFFFFFFFFFFFF # from
    rdx = int(gdb.parse_and_eval("$rdx")) & 0xFFFFFFFFFFFFFFFF # n
    trace_mgr.add(CopyFromUserEntry('copy_from_user', addr, uline, regs, rsi, rdx))

bp_handler = {
    '_copy_to_user': copy_to_user_handler,
    '_copy_from_user': copy_from_user_handler,
} # 'name': handler(addr, uline)

def parse_input(cfg_path):
    global VMLINUX_PATH
    global POC_PATH
    global GDBSERVER_PORT
    global OUT_FILE
    global POC_NAME
    global CURRENT_TASK_OFF

    with open(cfg_path, 'r') as f:
        d = json.load(f)
        VMLINUX_PATH = d['vmlinux']
        POC_PATH = d['poc']
        GDBSERVER_PORT = d['gdb_port']
        QUERY = d['query']
        OUT_FILE = d['output_txt']
        CURRENT_TASK_OFF = d['current_task_pcpu_offset']
        POC_NAME = os.path.basename(POC_PATH)

    for name, addr in QUERY.items():
        bpaddr[name] = addr
        bpname[addr] = name

def get_process_name():
    gs_base = int(gdb.parse_and_eval("$gs_base")) & 0xFFFFFFFFFFFFFFFF
    current_task_ptr = gdb.parse_and_eval(f'*(unsigned long*){gs_base+CURRENT_TASK_OFF}')
    comm = gdb.parse_and_eval(f'((struct task_struct *){hex(current_task_ptr)})->comm').string()
    return comm

def get_syscall_regs():
    rsp = int(gdb.parse_and_eval('$rsp')) & 0xFFFFFFFFFFFFFFFF
    rax = int(gdb.parse_and_eval(f'((struct pt_regs *){rsp})->orig_ax')) & 0xFFFFFFFFFFFFFFFF
    rdi = int(gdb.parse_and_eval(f'((struct pt_regs *){rsp})->di')) & 0xFFFFFFFFFFFFFFFF
    rsi = int(gdb.parse_and_eval(f'((struct pt_regs *){rsp})->si')) & 0xFFFFFFFFFFFFFFFF
    rdx = int(gdb.parse_and_eval(f'((struct pt_regs *){rsp})->dx')) & 0xFFFFFFFFFFFFFFFF
    r10 = int(gdb.parse_and_eval(f'((struct pt_regs *){rsp})->r10')) & 0xFFFFFFFFFFFFFFFF
    r8 = int(gdb.parse_and_eval(f'((struct pt_regs *){rsp})->r8')) & 0xFFFFFFFFFFFFFFFF
    r9 = int(gdb.parse_and_eval(f'((struct pt_regs *){rsp})->r9')) & 0xFFFFFFFFFFFFFFFF

    return {'RAX': rax, "RDI": rdi, "RSI": rsi, "RDX": rdx, "R10": r10, "R8": r8, "R9": r9}

def get_uline_of_current_callstack(breakpoint_addr):
    frame = gdb.newest_frame()
    regs = None

    fid = 0
    try:
        while frame is not None:
            fname = frame.name()
            if fname and 'entry_SYSCALL_64' in fname:
                frame.select()
                regs = get_syscall_regs()
                gdb.newest_frame().select()
                break
            fid += 1
            frame = frame.older()
    except Exception as e:
        return None, None

    if frame is None:
        return None, None

    gdb.execute(f'fr {fid}')
    rsp = int(gdb.parse_and_eval('$rsp')) & 0xFFFFFFFFFFFFFFFF
    user_sp = int(gdb.parse_and_eval(f'((struct pt_regs *){rsp})->sp')) & 0xFFFFFFFFFFFFFFFF

    # check 1000 8-bytes value to parse the call stack in uspace
    for i in range(0, 1000):
        try:
            v = gdb.parse_and_eval(f'*(unsigned long*){hex(user_sp+i*8)}')
            # if "x/-1i <addr>" reports "No line", then it is a out-of-poc address, just ignore
            pc = gdb.execute(f'x/-1i {hex(v)}', to_string=True)
        except Exception as e:
            return None, None
        if pc.startswith("No"):
            continue
        pc, func = pc.strip().split()[:2]
        pc = pc.strip()
        func = func.strip().split('+')[0][1:]
        line = gdb.execute(f'info line *{pc}', to_string=True)
        line = line.strip().split()
        lineno = line[1]
        fname = line[3][1:-1]
        return fname+":"+lineno, regs

    return None, None

class TraceBreakpoint(gdb.Breakpoint):
    def __init__(self, addr, bname):
        super().__init__(f'*{hex(addr)}', type=gdb.BP_HARDWARE_BREAKPOINT, internal=False)
        self.addr = addr
        self.bname = bname
    def stop(self):
        if not get_process_name().startswith(POC_NAME):
            return False

        uline, regs = get_uline_of_current_callstack(self.addr)
        if uline is None:
            return False

        bp_handler[self.bname](self.addr, uline, regs)

        return False

def init_breakpoints():
    for name in bpaddr:
        TraceBreakpoint(bpaddr[name], name)

def init_envs():
    global CFGPATH
    parse_input(CFGPATH)

    gdb.execute(f'file {VMLINUX_PATH}')
    gdb.execute(f'add-symbol-file {POC_PATH}')

    gdb.execute(f'target remote localhost:{GDBSERVER_PORT}')
 
    init_breakpoints()

    print('[GDB] init done.')
    gdb.execute('continue')

def on_exit(event):
    global OUT_FILE
    with open(OUT_FILE, 'w') as f:
        trace_mgr.dump(f)

gdb.events.exited.connect(on_exit)
init_envs()
