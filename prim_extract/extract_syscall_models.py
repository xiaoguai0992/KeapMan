import os
import re
import json

from config import Config

pattern = r'syscall_(\w+)\s*\('

if __name__ == '__main__':
    extapi_c = os.path.join(Config.svf_dir, 'svf-llvm/lib/extapi.c')
    syscall_decl = {}
    with open(extapi_c, 'r') as f:
        lines = f.readlines()

    for line in lines:
        if 'syscall_' in line:
            matches = re.findall(r'syscall_(\w+)\s*\(', line)
            syscall_name = list(matches)[0]
            syscall_decl[syscall_name] = line.strip()

    with open(os.path.join(Config.workspace_dir, 'syscall_decl.json'), 'w') as f:
        json.dump(syscall_decl, f, indent=4)

