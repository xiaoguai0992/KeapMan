# automatically generate syscall definitions for KotoriPlugin
# i.e. syscall_table.h
# for linux kernel 5.10

import os
import json
import subprocess

KERNEL_DIR = os.getenv("KERNEL_DIR")
ID_LIST = 'arch/x86/entry/syscalls/syscall_64.tbl'

syscalls = {} # {name: [param1, param2, ...]}

def register_syscall(defarr):
    try:
        n_arg = int(defarr[0][-1]) # SYSCALL_DEFINEn, n is arg number
    except:
        return # SYSCALL_DEFINEn itself

    if len(defarr) / 2 - 1 != n_arg and 'COMPAT' not in defarr[0]: 
        # import pdb 
        # pdb.set_trace()
        raise AttributeError("ERROR: inconsistent syscall argument number")
    
    name = defarr[1]

    if (not name in syscalls) or (defarr[0].startswith('COMPAT')):
        arglist = []
        for i in range(2, len(defarr), 2):
            arg = defarr[i]
            arglist.append(arg)
        syscalls[name] = arglist

def generate_syscall_defs():
    with open(os.path.join(KERNEL_DIR, ID_LIST), 'r') as f:
        ids = f.readlines()

    ids = [[ele for ele in line.strip().split('\t') if ele != ''] for line in ids if line.strip() != '' and '#' not in line]
    entries = {} # {id: [name, entry_point]}
    syscall_map = {}
    max_id = 0
    for id_entry in ids:
        if len(id_entry) == 4:
            call_id, _, name, __ = id_entry
        else: # len(id_entry) == 3
            call_id, _, name = id_entry

        call_id = int(call_id)
        entries[call_id] = name
        if max_id < call_id:
            max_id = call_id

    for i in range(max_id + 1):
        if i in entries:
            name = entries[i]
            if name in syscalls:
                args = syscalls[name]
                syscall_map[i] = {'name': name, 'args': args}

    return syscall_map

def parse_syscall_from_source():
    cmdline = ['grep', '"SYSCALL_DEFINE"', '-nir', KERNEL_DIR, '>', './syscall_lines.txt.tmp']
    os.system(' '.join(cmdline))

    with open('./syscall_lines.txt.tmp', 'r') as f:
        lines = f.readlines()

    os.system('rm ./syscall_lines.txt.tmp')

    for line in lines:
        if 'Binary file' in line:
            continue

        fname, lno, defstr = line.strip().split(':', 2)

        lno = int(lno)

        # skip other architectures
        if 'arch' in fname and not 'x86' in fname:
            continue

        # skip C MACRO
        if '#' in defstr:
            continue

        # skip syscall_wrapper.h
        if 'syscall_wrapper.h' in fname:
            continue

        # skip kernel_doc
        if 'kernel-doc' in fname:
            continue

        # skip tag.sh
        if 'tags.sh' in fname:
            continue

        # skip adding-syscalls.rst
        if 'adding-syscalls.rst' in fname:
            continue

        # invalid define
        if not defstr.startswith("SYSCALL_DEFINE") and not defstr.startswith("COMPAT_SYSCALL_DEFINE"):
            continue

        if ')' not in defstr:
            with open(fname, 'r') as f:
                source = f.readlines()
                # actual line no is start from 1, but here we use as index, which start from 0
                for i in range(lno, len(source)):
                    defstr += source[i].strip()
                    if ')' in source[i]:
                        break
        
        # only preserve function specification
        defstr = defstr.split(')')[0]
        
        defstr = defstr.replace('(', ',').replace(')', ',')
        defarr = [s.strip() for s in defstr.split(',') if s.strip() != '']

        register_syscall(defarr)

def main():
    parse_syscall_from_source()
    syscall_defs = generate_syscall_defs()
    with open('syscall_defs.json', 'w') as f:
        json.dump(syscall_defs, f, indent=4)

if __name__ == '__main__':
    main()
