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

def check_free(Config):
    test_free_c = os.path.join(Config.workspace_dir, 'test_free.c')
    primitive_spaf_h = os.path.join(Config.workspace_dir, 'primitive_spaf.h')
    
    objmeasure_input_dir = os.path.join(Config.objmeasure_root_dir, 'input')
    dst_primitive_spaf_h = os.path.join(objmeasure_input_dir, 'primitive_spaf.h')
    print('[*] Copying primitive_sa.h to objmeasure input directory')
    with open(primitive_spaf_h, 'r') as src, open(dst_primitive_spaf_h, 'w') as dst:
        dst.write(src.read())

    # build alloc_config.json
    with open(os.path.join(Config.workspace_dir, 'gdb_config.json'), 'r') as f:
        j = json.load(f)
        # trick: assume length of call ins is 5
        alloc_addr = j['k_alloc_addr'] - 5
        free_addr = j['k_free_addr']

    expected_free_times = 10
    alloc_config = {}
    alloc_config['testcase'] = test_free_c
    alloc_config['goal_addrs'] = [alloc_addr, free_addr]
    alloc_config['expected_times'] = expected_free_times
    with open(os.path.join(Config.workspace_dir, 'free_config.json'), 'w') as f:
        json.dump(alloc_config, f, indent=4)
    print('[*] write free_config.json')
    
    # run check
    cwd = os.getcwd()
    os.chdir(Config.objmeasure_root_dir)
    check_free_cmd = f'python3 {Config.freecheck_py} {Config.workspace_dir}'
    print('[*] Running check_free.py')
    out = os.system(check_free_cmd)
    os.chdir(cwd)
    print(out)

    # check whether the allocation is expected
    with open(os.path.join(Config.workspace_dir, 'free_times.json'), 'r') as f:
        j = json.load(f)
        actual_free_times = j['times']
    
    if actual_free_times == expected_free_times:
        print('[*] Correct free primitive!')
        return True
    else:
        print('[*] Incorrect free primitive.')
        return False

def main():
    check_free(Config)

if __name__ == '__main__':
    main()
