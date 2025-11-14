import os
import sys
import json
import signal
import subprocess
import re

from config import Config

def exec_sync_stdout(cmd, timeout=60, echo=False):

    def timeout_handler(signum, frame):
        raise Exception("Timeout!")

    signal.signal(signal.SIGALRM, timeout_handler)

    signal.alarm(timeout)
    try:
        if echo:
            print('[EXEC]', cmd)
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
    except Exception as e:
        raise (e)
    finally:
        signal.alarm(0)

    return out.decode()

def static_analyze_sa(Config, try_depth):
    bc_path = os.path.join(Config.workspace_dir, 'repro.reshape.bc')

    with open(os.path.join(Config.workspace_dir, 'reshape_mapping.txt'), 'r') as f:
        lines = f.readlines()
        line = lines[0].strip()
        line_mapping = eval(line)

    with open(os.path.join(Config.workspace_dir, 'uline.json'), 'r') as f:
        j = json.load(f)
        alloc_lineno = j['alloc']
        alloc_lineno = line_mapping[alloc_lineno]

    cmd = f'{Config.prim_sa_bin} {bc_path} {alloc_lineno} {try_depth}'
    out = exec_sync_stdout(cmd, echo=True)
    print(out)

    # remap results to original c poc
    with open(os.path.join(Config.workspace_dir, 'primitive_sa.json'), 'r') as f:
        primitive = json.load(f)

    for prim_name in ['setup', 'alloc']:
        if prim_name in primitive:
            for i, lineno in enumerate(primitive[prim_name]):
                ori_lineno = line_mapping.index(lineno)
                primitive[prim_name][i] = ori_lineno

    print(f'[*] setup/alloc primitives')
    print(json.dumps(primitive, indent=4))
    with open(os.path.join(Config.workspace_dir, 'primitive_sa_remap.json'), 'w') as f:
        json.dump(primitive, f, indent=4)

def main():
    if len(sys.argv) != 2:
        print("Usage: python step2_gen_sa.py <num_syscall>")
        sys.exit(1)
    num_syscall = int(sys.argv[1])
    static_analyze_sa(Config, num_syscall)

if __name__ == '__main__':
    main()
