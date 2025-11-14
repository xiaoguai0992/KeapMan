import os
import re
import sys
import gdb
import json
import traceback

VMLINUX_PATH = None
POC_PATH = None
GDBSERVER_PORT = None
OUTPUT_JSON = None
POC_NAME = None
CURRENT_TASK_OFF = None

bp_n2a = {}
bp_a2n = {}

def parse_input(cfg_path):
    global VMLINUX_PATH
    global POC_PATH
    global GDBSERVER_PORT
    global OUTPUT_JSON
    global POC_NAME
    global CURRENT_TASK_OFF
    global ALLOC_FUNCS
    global VULN_TYPE

    with open(cfg_path, 'r') as f:
        d = json.load(f)
        VMLINUX_PATH = d['vmlinux']
        POC_PATH = d['poc']
        POC_NAME = os.path.basename(POC_PATH)
        GDBSERVER_PORT = d['gdb_port']
        OUTPUT_JSON = d['output_json']
        CURRENT_TASK_OFF = d['current_task_pcpu_offset']

        bp_n2a['alloc_site'] = d['k_alloc_addr']
        bp_n2a['free_site'] = d['k_free_addr']

        for bname in bp_n2a:
            bp_a2n[bp_n2a[bname]] = bname

def get_process_name():
    gs_base = int(gdb.parse_and_eval("$gs_base")) & 0xFFFFFFFFFFFFFFFF
    current_task_ptr = gdb.parse_and_eval(f'*(unsigned long*){gs_base+CURRENT_TASK_OFF}')
    comm = gdb.parse_and_eval(f'((struct task_struct *){hex(current_task_ptr)})->comm').string()
    return comm

def get_uline_of_current_callstack(breakpoint_addr):
    frame = gdb.newest_frame()

    fid = 0
    try:
        while frame is not None:
            fname = frame.name()
            if fname and 'entry_SYSCALL_64' in fname:
                break
            fid += 1
            frame = frame.older()
    except Exception as e:
        return None

    if frame is None:
        return None

    gdb.execute(f'fr {fid}')
    rsp = int(gdb.parse_and_eval('$rsp')) & 0xFFFFFFFFFFFFFFFF
    user_sp = int(gdb.parse_and_eval(f'((struct pt_regs *){rsp})->sp')) & 0xFFFFFFFFFFFFFFFF

    # check 1000 8-bytes value to parse the call stack in uspace
    for i in range(0, 1000):
        try:
            v = gdb.parse_and_eval(f'*(unsigned long*){hex(user_sp+i*8)}')
            pc = gdb.execute(f'x/-1i {hex(v)}', to_string=True)
        except Exception as e:
            return None
        if pc.startswith("No"):
            continue
        pc, func = pc.strip().split()[:2]
        pc = pc.strip()
        func = func.strip().split('+')[0][1:]
        if func == 'main':
            line = gdb.execute(f'info line *{pc}', to_string=True)
            line = line.strip().split()
            lineno = line[1]
            fname = line[3][1:-1]

            return fname+":"+lineno

    return None

def delay_bpdelete(bp):
    bp.delete()

obj_allocs = {}
obj_frees = {}

class VulAllocBreakpoint(gdb.Breakpoint):
    def __init__(self, addr, bname):
        super().__init__(f'*{hex(addr)}', type=gdb.BP_HARDWARE_BREAKPOINT, internal=False)
        self.addr = addr
        self.bname = bname

    def stop(self):
        if not get_process_name().startswith(POC_NAME):
            return False

        uline = get_uline_of_current_callstack(self.addr)
        if not uline:
            uline = '?'

        obj = int(gdb.parse_and_eval("$rax")) & 0xFFFFFFFFFFFFFFFF

        obj_allocs[obj] = uline

        return False

def get_callee_name(current_insn):
    match = re.search(r"call\s+.*<(.+)>", current_insn)
    target_func = match.group(1)
    return target_func

class VulFreeBreakpoint(gdb.Breakpoint):
    def __init__(self, addr, bname):
        super().__init__(f'*{hex(addr)}', type=gdb.BP_HARDWARE_BREAKPOINT, internal=False)
        self.addr = addr
        self.bname = bname

    def stop(self):
        if not get_process_name().startswith(POC_NAME):
            return False

        current_pc = int(gdb.parse_and_eval("$rip")) & 0xFFFFFFFFFFFFFFFF
        current_insn = gdb.execute(f'x/i {hex(current_pc)}', to_string=True)
        if 'call' in current_insn:
            func_name = get_callee_name(current_insn)

        uline = get_uline_of_current_callstack(self.addr)
        if not uline:
            uline = '?'

        if func_name == 'kvfree_call_rcu':
            rdi = int(gdb.parse_and_eval("$rdi")) & 0xFFFFFFFFFFFFFFFF
            rsi = int(gdb.parse_and_eval("$rsi")) & 0xFFFFFFFFFFFFFFFF
            obj = rdi - rsi
        if func_name == 'kmem_cache_free':
            obj = int(gdb.parse_and_eval("$rsi")) & 0xFFFFFFFFFFFFFFFF
        else:
            obj = int(gdb.parse_and_eval("$rdi")) & 0xFFFFFFFFFFFFFFFF

        obj_frees[obj] = uline

        return False

def init_breakpoints():
    VulAllocBreakpoint(bp_n2a['alloc_site'], 'alloc_site')
    VulFreeBreakpoint(bp_n2a['free_site'], 'free_site')

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
    d = {}

    for obj in obj_allocs:
        if obj_allocs[obj] != '?':
            if obj in obj_frees:
                if obj_frees[obj] != '?':
                    d['u_alloc_site'] = obj_allocs[obj]
                    d['u_free_site'] = obj_frees[obj]
                    break

    with open(OUTPUT_JSON, 'w') as f:
        json.dump(d, f, indent=4)

    gdb.execute('quit')

gdb.events.exited.connect(on_exit)
init_envs()

