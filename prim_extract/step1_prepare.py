import os
import sys
import json
import signal
import subprocess
import re

from config import Config
from dynamic_analysis import dynamic_utils
import agent

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

def static_analyze_prepare(Config, cprog_path):
    cprog_dir, cprog_file = os.path.split(cprog_path)
    cprog_name, cprog_ext = os.path.splitext(cprog_file)

    bc_path = os.path.join(cprog_dir, cprog_name+'.bc')
    #  clang -g3 -emit-llvm -c reshape_repro.c -o reshape_repro.bc
    cmd = f'clang -g3 -emit-llvm -Wno-int-conversion -c {cprog_path} -o {bc_path}'
    out = exec_sync_stdout(cmd, echo=True)
    print(out)

    cmd = f'llvm-dis {bc_path}'
    out = exec_sync_stdout(cmd, echo=True)
    print(out)

    return bc_path

def reshape_poc(Config):
    poc_path = os.path.join(Config.workspace_dir, 'repro.c')

    cmd = f'python3 reshape_poc.py {poc_path}'
    out = exec_sync_stdout(cmd, echo=True)

    with open(os.path.join(Config.workspace_dir, 'reshape_mapping.txt'), 'r') as f:
        lines = f.readlines()
        line = lines[0].strip()
        src_to_reshaped_mapping = eval(line)

    reshaped_poc_path = os.path.join(Config.workspace_dir, 'repro.reshape.c')

    return reshaped_poc_path, src_to_reshaped_mapping

def main():
    if not os.path.exists(Config.workspace_dir):
        os.makedirs(Config.workspace_dir)

    ## Step 1: read allocation/free site in linux src
    with open(os.path.join(Config.dataset_dir, 'sites.json'), 'r') as f:
        j = json.load(f)
        alloc_site = j['alloc']
        free_site = j['free']

    ## Step 2: directed fuzzing

    fuzzed_poc = os.path.join(Config.dataset_dir, 'repro.c')
    if os.path.exists(fuzzed_poc):
        print('[*] found fuzzed poc')
        repro_src = os.path.join(Config.dataset_dir, 'repro.c')
        repro_dst = os.path.join(Config.workspace_dir, 'repro.c')
        print('[*] copying repro.c to workspace directory')
        with open(repro_src, 'r') as src, open(repro_dst, 'w') as dst:
            dst.write(src.read())
    else:
        raise FileNotFoundError(fuzzed_poc)

    ## Step 3: dynamically analyze the alloc/free ulines
    if not os.path.exists(os.path.join(Config.workspace_dir, "uline.json")):
        alloc_uline, free_uline = dynamic_utils.k2uline(Config, alloc_site, free_site)
        print(f'[*] alloc uline {alloc_uline}')
        print(f'[*] free uline {free_uline}')

        alloc_lineno = int(alloc_uline.split(':')[1])
        free_lineno = int(free_uline.split(':')[1])
        with open(os.path.join(Config.workspace_dir, 'uline.json'), 'w') as f:
            json.dump({'alloc': alloc_lineno, 'free': free_lineno}, f, indent=4)

    ## Step 4: dynamically analyze the side-effect of syscalls
    # This is used to model syscall in extapi.c and side-effects for LLM code generator
    if not os.path.exists(os.path.join(Config.workspace_dir, 'gdb_uaccess_output.txt')):
        side_effects = dynamic_utils.analyze_side_effect(Config)
        print(f'[*] found side effects')
        for effect in side_effects:
            print(effect)
    else:
        with open(os.path.join(Config.workspace_dir, 'gdb_uaccess_output.txt'), 'r') as f:
            side_effects = [l.strip() for l in f.readlines() if l.strip() != '']

    ## Step 5: Copy extapi.c and build SVF
    extapi_src = os.path.join(Config.dataset_dir, 'extapi.c')
    extapi_dst = os.path.join(Config.svf_root_dir, 'svf-llvm/lib/extapi.c')
    
    print('[*] Copying extapi.c to SVF/svf-llvm/lib/extapi.c')
    with open(extapi_src, 'r') as src, open(extapi_dst, 'w') as dst:
        dst.write(src.read())

    print('[*] Building SVF...')
    build_cmd = f'cd {Config.svf_root_dir} && ./build.sh'
    cwd = os.getcwd()
    out = os.system(build_cmd)
    os.chdir(cwd)

    ## Step 6: Extract syscall models
    extract_cmd = f'python3 extract_syscall_models.py'
    out = exec_sync_stdout(extract_cmd, echo=True)
    print(out)
    print('[*] Extract syscall models ok.')

    ## Step 7: reshape poc and compile it into bc
    with open(os.path.join(Config.workspace_dir, 'uline.json'), 'r') as f:
        j = json.load(f)
        alloc_lineno = j['alloc']
        free_lineno = j['free']
    reshaped_cprog_path, line_mapping = reshape_poc(Config)
    reshaped_alloc_lineno = line_mapping[alloc_lineno]
    reshaped_free_lineno = line_mapping[free_lineno]
    print(f'[*] reshaped alloc uline {reshaped_cprog_path}:{reshaped_alloc_lineno}')
    print(f'[*] reshaped free uline {reshaped_cprog_path}:{reshaped_free_lineno}')

    with open(os.path.join(Config.workspace_dir, 'reshaped_uline.json'), 'w') as f:
        json.dump({'alloc': reshaped_alloc_lineno, 'free': reshaped_free_lineno}, f, indent=4)

    reshaped_bc_path = static_analyze_prepare(Config, reshaped_cprog_path)
    print(f'[*] POC bc has been saved in {reshaped_bc_path}')

    ## Step 8: Build side effect comments for LLM
    with open(os.getenv("SYSCALL_DEFS"), 'r') as f:
        syscall_defs = json.load(f)

    comments = {}
    for effect in side_effects:
        effect = effect.split(' ')
        fname, lineno = effect[-3].split(':')
        access_addr = int(effect[-2], 16)
        access_size = int(effect[-1], 16)

        if 'repro.c' not in fname:
            continue

        syscall_id = effect[0]
        len_args = len(syscall_defs[syscall_id]['args'])
        param_id = -1
        offset = 0xffffffffffffffff
        for i in range(len_args):
            arg_i = int(effect[i+1])
            print(hex(access_addr), hex(arg_i), offset)
            if access_addr >= arg_i and access_addr - arg_i < offset:
                offset = access_addr - arg_i
                param_id = i
        assert(param_id >= 0 and param_id < len_args)
        real_param_id = param_id + 1 # skip syscall id

        with open(os.path.join(Config.workspace_dir, 'repro.prim.c')) as f:
            code = f.readlines()[int(lineno) - 1] # lineno start from 1

        # Extracting syscall parameters simply and directly
        start = code.find('syscall(') + 8  # Skip 'syscall('
        end = code.rfind(');')  # Find the last ');'
        args_str = code[start:end]
        args = [arg.strip() for arg in args_str.split(',')]
        param_str = args[real_param_id]
        access_param = param_str + '+' + str(offset)

        access_type = effect[-5]
        comment = None
        if access_type == 'copy_to_user':
            comment = f'this syscall writes memory {access_param}, length {access_size}, this side-effect should also be considered as an output if other primitive uses it'
        elif access_type == 'copy_from_user':
            comment = f'this syscall reads memory {access_param}, length {access_size}, this side-effect should also be considered as an input if other primitive returns it'

        if comment is not None:
            if lineno not in comments:
                comments[lineno] = []
            comments[lineno].append(comment)

    side_effect_comments = {}
    for lineno in comments:
        side_effect_comments[lineno] = ';'.join(comments[lineno])
    with open(os.path.join(Config.workspace_dir, 'side_effects.json'), 'w') as f:
        json.dump(side_effect_comments, f, indent=4)

    print(f'[*] following side effect are captured:')
    for lineno in comments:
        for comment in comments[lineno]:
            print(lineno, ":", comment)

if __name__ == '__main__':
    main()

