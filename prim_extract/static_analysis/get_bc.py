import os
import sys
import subprocess

KERNEL_SRC_DIR = os.getenv("KERNEL_DIR")
BC_TARGET_DIR = os.getenv("LINUX_BC_DIR")

def is_elf_file(file_path):
    try:
        output = subprocess.check_output(["file", file_path], stderr=subprocess.DEVNULL, text=True)
        return "ELF" in output
    except subprocess.CalledProcessError:
        return False

def has_sec_section(file_path):
    try:
        output = subprocess.check_output(["readelf", "-S", file_path], stderr=subprocess.DEVNULL, text=True)
        return ".llvm_bc" in output
    except subprocess.CalledProcessError:
        return False

def extract_bc(source_dir, target_dir):
    for root, _, files in os.walk(source_dir):
        for file in files:
            if file.startswith('.'):
                continue

            source_file = os.path.join(root, file)

            if not is_elf_file(source_file):
                continue
            
            if has_sec_section(source_file):
                relative_path = os.path.relpath(source_file, source_dir)
                target_file = os.path.join(target_dir, relative_path)
                target_bc_file = target_file + ".bc"

                os.makedirs(os.path.dirname(target_bc_file), exist_ok=True)

                print(f"\033[92m[+] Extracting BC for: {source_file}\033[0m")
                try:
                    subprocess.run(["extract-bc", "--output", target_bc_file, source_file], check=True)
                    print(f"Saved to: {target_bc_file}")
                except subprocess.CalledProcessError:
                    print(f"Failed to extract BC for {source_file}")

if __name__ == "__main__":
    extract_bc(KERNEL_SRC_DIR, BC_TARGET_DIR)
