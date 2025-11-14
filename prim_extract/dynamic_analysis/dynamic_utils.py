import os
import sys
import json
import time
import signal
import subprocess

import paramiko
from . import line2addr

GDB_CONFIG = 'gdb_config.json'
GDB_PORT = 13447
QEMU_SSH_PORT = 10437
OUTPUT_JSON = 'gdb_output.json'

UACCESS_GDB_CONFIG = 'gdb_uaccess_config.json'
UACCESS_OUTPUT_TXT = 'gdb_uaccess_output.txt'

def timeout_handler(signum, frame):
    raise Exception("Timeout!")

def get_kaddr(vmlinux, uline, type):
    src_line, func = uline.split(' ')
    src, lineno = src_line.split(':')
    kaddr = line2addr.get_address_from_line(src, lineno, vmlinux, type, func)
    return kaddr

def get_current_task_pcpu_offset(system_map_path):
    with open(system_map_path, 'r') as f:
        for line in f.readlines():
            if 'current_task' in line:
                return int(line.split(' ')[0], 16)

def get_symbol_addr(symbol_name, system_map_path):
    # ffffffff81438aa0 T _copy_from_user
    with open(system_map_path, 'r') as f:
        for line in f.readlines():
            addr, _, name = line.strip().split(' ')[:3]
            if name == symbol_name:
                return int(addr, 16)

def build_k2uline_config(Config, poc_path, alloc_site, free_site):
    vmlinux_path = os.path.join(Config.linux_src_dir, 'vmlinux')
    bzimage_path = os.path.join(Config.linux_build_dir, 'arch/x86/boot/bzImage')

    k_alloc_addr = get_kaddr(vmlinux_path, alloc_site, 'alloc')
    assert(k_alloc_addr is not None)
    print(f'[*] k_alloc_addr {hex(k_alloc_addr)}')
    k_free_addr = get_kaddr(vmlinux_path, free_site, 'free')
    assert(k_free_addr is not None)
    print(f'[*] k_free_addr {hex(k_free_addr)}')

    current_off = get_current_task_pcpu_offset(os.path.join(Config.linux_build_dir, 'System.map'))

    gdb_config = {
        'vmlinux': vmlinux_path,
        'poc': poc_path,
        'gdb_port': GDB_PORT,
        'k_alloc_addr': k_alloc_addr,
        'k_free_addr': k_free_addr,
        'current_task_pcpu_offset': current_off,
        'output_json': os.path.join(Config.workspace_dir, OUTPUT_JSON),
    }

    gdb_config_path = os.path.join(Config.workspace_dir, GDB_CONFIG)
    with open(gdb_config_path, 'w') as f:
        json.dump(gdb_config, f, indent=4)
    return gdb_config_path

def exec_sync_stdout(cmd, timeout=60, echo=False):
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

def kill_existing_qemu():
    try:
        uid = os.getuid()
        # The regular expression matches both "qemu-system-x86_64" and "hostfwd=tcp::10437-:22"
        pattern = f"qemu-system-x86_64.*hostfwd=tcp::{QEMU_SSH_PORT}-:22"
        result = subprocess.run(
            ["pgrep", "-u", str(uid), "-f", pattern],
            capture_output=True, text=True
        )
        pids = [pid for pid in result.stdout.strip().split("\n") if pid]

        if not pids:
            print("[+] No matching QEMU processes found.")
            return

        print(f"[+] Found matching QEMU processes: {pids}, killing them...")

        for pid in pids:
            os.kill(int(pid), signal.SIGTERM)  # Try terminating normally first
            time.sleep(1)  # Wait for process to exit

        # Ensure the process terminates; if it still exists, use SIGKILL.
        result = subprocess.run(
            ["pgrep", "-u", str(uid), "-f", pattern],
            capture_output=True, text=True
        )
        pids = [pid for pid in result.stdout.strip().split("\n") if pid]

        if pids:
            print(f"[!] Force killing QEMU processes: {pids}")
            for pid in pids:
                os.kill(int(pid), signal.SIGKILL)  # Forced termination

    except Exception as e:
        print(f"[!] Error while killing existing QEMU processes: {e}")
 
def start_vm(Config):
    kill_existing_qemu()

    bzimage_path = os.path.join(Config.linux_build_dir, 'arch/x86/boot/bzImage')
    fsimage_path = os.path.join(Config.fsimage_dir, 'bullseye.img')
    log_path = os.path.join(Config.workspace_dir, 'vm_console.txt')

    with open(log_path, "w") as f:
        vm = subprocess.Popen([
            'qemu-system-x86_64',
            '-m', '2G',
            '-cpu', 'host',
            '-smp', 'cores=1',
            '-kernel', f'{bzimage_path}',
            '-drive', f'file={fsimage_path},format=raw',
            '-nographic',
            '-serial', 'mon:stdio',
            '-net', f'user,host=10.0.2.10,hostfwd=tcp::{QEMU_SSH_PORT}-:22',
            '-net', 'nic,model=e1000',
            '-enable-kvm',
            '-append', 'console=ttyS0 root=/dev/sda rw rdinit=/sbin/init pti=off nosmap nosmep nokaslr net.ifnames=0',
            '-no-reboot',
            '-device', 'virtio-gpu-pci',
            '-gdb', f'tcp:localhost:{GDB_PORT}'
        ], stdout=f, stderr=f)

    return vm

def wait_vm_ready(Config):
    private_key = os.path.join(Config.fsimage_dir, 'bullseye.id_rsa')

    while True:
        try:
            out = exec_sync_stdout(f"ssh -i {private_key} -p {QEMU_SSH_PORT} root@localhost 'echo hello'", timeout=2)
        except Exception as e:
            msg = str(e)
            if msg == 'Timeout!':
                print('waiting vm start ...')
                continue
            else:
                raise(e)
        print(out)
        if 'hello' in out:
            print(f'vm ready!')
            break

def k2uline(Config, alloc_site, free_site):
    vmlinux_path = os.path.join(Config.linux_src_dir, 'vmlinux')
    bzimage_path = os.path.join(Config.linux_build_dir, 'arch/x86/boot/bzImage')

    # compile poc
    cflags = '-w -static -O2 -fno-inline -g -fno-pie'
    poc_src_path = os.path.join(Config.dataset_dir, 'repro.c')
    poc_path = os.path.join(Config.workspace_dir, 'repro')
    poc_file = os.path.basename(poc_path)
    cmd = f'gcc {cflags} {poc_src_path} -o {poc_path}'
    exec_sync_stdout(cmd, echo=True)

    gdb_config_path = build_k2uline_config(Config, poc_path, alloc_site, free_site)

    start_vm(Config)
    wait_vm_ready(Config)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # client.connect(hostname='localhost', port=f'{QEMU_SSH_PORT}', username='user', password="1")
    client.connect(hostname='localhost', port=f'{QEMU_SSH_PORT}', username='root', password="root")

    sftp = client.open_sftp()
    sftp.put(poc_path, os.path.join('/root/', os.path.basename(poc_file)))
    sftp.close()

    cin, cout, cerr = client.exec_command(f"chmod +x ~/{poc_file}")

    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    gdb_script = os.path.join(SCRIPT_DIR, 'k2uline-gdb.py')
    gdb_cmd = ['gdb', '-ex', f'python CFGPATH="{gdb_config_path}"', '-x', f'{gdb_script}']
    print('[EXEC] ', ' '.join([f"'{cmd}'" if i == 2 else cmd for i, cmd in enumerate(gdb_cmd)]))
    gdb = subprocess.Popen(gdb_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=False, text=True)
    for line in gdb.stdout:
        print('[K2U]', line, end='')
        if "[GDB] init done" in line:
            break

    cin, cout, cerr = client.exec_command(f"~/{poc_file}")
    vm_cout = cout.read() # wait for execution finish
    vm_cerr = cerr.read() # wait for execution finish

    print(vm_cerr)
    print(vm_cout)

    kill_existing_qemu()

    for line in gdb.stdout:
        print('[K2U]', line, end='')

    time.sleep(1) # wait gdb result writeback

    with open(os.path.join(Config.workspace_dir, OUTPUT_JSON), 'r') as f:
        res = json.load(f)

    return res['u_alloc_site'], res['u_free_site']

def build_uaccess_config(Config, poc_path):
    vmlinux_path = os.path.join(Config.linux_src_dir, 'vmlinux')
    current_off = get_current_task_pcpu_offset(os.path.join(Config.linux_build_dir, 'System.map'))

    addr_copy_from_user = get_symbol_addr('_copy_from_user', os.path.join(Config.linux_build_dir, 'System.map'))
    addr_copy_to_user = get_symbol_addr('_copy_to_user', os.path.join(Config.linux_build_dir, 'System.map'))
    gdb_config = {
        'vmlinux': vmlinux_path,
        'poc': poc_path,
        'gdb_port': GDB_PORT,
        'current_task_pcpu_offset': current_off,
        'output_txt': os.path.join(Config.workspace_dir, UACCESS_OUTPUT_TXT),
        'query' : {
            '_copy_from_user': addr_copy_from_user,
            '_copy_to_user': addr_copy_to_user,
        },
    }

    gdb_config_path = os.path.join(Config.workspace_dir, UACCESS_GDB_CONFIG)
    with open(gdb_config_path, 'w') as f:
        json.dump(gdb_config, f, indent=4)
    return gdb_config_path

def analyze_side_effect(Config):
    vmlinux_path = os.path.join(Config.linux_src_dir, 'vmlinux')
    bzimage_path = os.path.join(Config.linux_build_dir, 'arch/x86/boot/bzImage')

    # PoC should have been compiled in the previous step k2uline
    poc_path = os.path.join(Config.workspace_dir, 'repro')
    poc_file = os.path.basename(poc_path)

    gdb_config_path = build_uaccess_config(Config, poc_path)

    start_vm(Config)
    wait_vm_ready(Config)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # client.connect(hostname='localhost', port=f'{QEMU_SSH_PORT}', username='user', password="1")
    client.connect(hostname='localhost', port=f'{QEMU_SSH_PORT}', username='root', password="root")

    sftp = client.open_sftp()
    sftp.put(poc_path, os.path.join('/root/', os.path.basename(poc_file)))
    sftp.close()

    cin, cout, cerr = client.exec_command(f"chmod +x ~/{poc_file}")

    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    gdb_script = os.path.join(SCRIPT_DIR, 'uaccess-gdb.py')
    gdb_cmd = ['gdb', '-ex', f'python CFGPATH="{gdb_config_path}"', '-x', f'{gdb_script}']
    print('[EXEC] ', ' '.join([f"'{cmd}'" if i == 2 else cmd for i, cmd in enumerate(gdb_cmd)]))
    gdb = subprocess.Popen(gdb_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=False, text=True)
    for line in gdb.stdout:
        print('[UAC]', line, end='')
        if "[GDB] init done" in line:
            break

    cin, cout, cerr = client.exec_command(f"~/{poc_file}")
    vm_cout = cout.read() # wait for execution finish
    vm_cerr = cerr.read() # wait for execution finish

    print(vm_cerr)
    print(vm_cout)

    kill_existing_qemu()

    time.sleep(1) # wait gdb result writeback

    with open(os.path.join(Config.workspace_dir, UACCESS_OUTPUT_TXT), 'r') as f:
        res = [l.strip() for l in f.readlines()]

    return res
