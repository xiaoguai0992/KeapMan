import os
import re
import sys
import subprocess

def find_call_instructions_around_address(start_address, executable_path, type=None):
    """
    Search for the address of the call instruction around the specified address (5 instructions forward and 5 instructions backward).

    Args:
        start_address (str): Starting address (e.g., "0xffffffff81a1757f")
        executable_path (str): Executable file path

    Returns:
        list: It contains the addresses of all found call instructions (e.g., ["0xffffffff81a17560", "0xffffffff81a17580"]).
              If it fails, return an empty list.
    """
    start_address = hex(start_address)
    try:
        # Obtain disassembled code
        command = [
            "gdb", "--batch","-nx",
            "-ex", f"disassemble {start_address}",
            executable_path
        ]
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10  # Prevent hangs
        )
        
        if result.returncode != 0:
            print(f"GDB error: {result.stderr}")
            return []
        
        # Analyze the disassembly output
        disassembly = result.stdout.splitlines()
        instructions = []
        for line in disassembly:
            match = re.match(r"\s*([0-9a-fA-Fx]+)\s+<\+\d+>:\s+(\w+)\s+(.*)", line)
            if match:
                address = match.group(1)  # Instruction address
                opcode = match.group(2)   # Opcodes (such as call, mov, etc.)
                operands = match.group(3) # Operands (such as function names or registers)
                instructions.append((address, opcode, operands))
        
        # Find the index of start_address
        start_index = None
        for i, (addr, _, _) in enumerate(instructions):
            if addr.lower() == start_address.lower():
                start_index = i
                break
        
        if start_index is None:
            print(f"Start address {start_address} not found in disassembly")
            return []

        # 10 instructions after extraction
        upper_bound = min(len(instructions), start_index + 10)  # +6 Because slices do not include an upper limit.
        lower_bound = max(0, start_index - 5)
        surrounding_instructions_down = instructions[start_index:upper_bound]
        surrounding_instructions_up = instructions[lower_bound:start_index]
        
        # Filter out call commands
        call_addresses = []
        for addr, opcode, oprand in surrounding_instructions_down:
            if opcode == "call" and type in oprand:
                call_addresses.append(addr)

        # Sometimes the gdb info line is crooked; you should also check it from the front.
        if len(call_addresses) == 0:
            for addr, opcode, oprand in surrounding_instructions_up[::-1]:
                if opcode == "call" and type in oprand:
                    call_addresses.append(addr)

        # If no call is found, it may be a jmp call.
        if len(call_addresses) == 0:
            for addr, opcode, oprand in surrounding_instructions_down:
                if opcode == "jmp" and type in oprand:
                    call_addresses.append(addr)

        return call_addresses
    
    except subprocess.TimeoutExpired:
        print("GDB command timed out")
        return []
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return []
 
def gdb_info_line(file_path, line_number, executable_path, symbol):
    """
    Retrieving information about a specific line of code (requires a debug build) may be achieved through a jmp call.

    Args:
        file_path (str): Source code file path (absolute path or path relative to the executable file)
        line_number (int): code line number
        executable_path (str): Executable file path

    Returns:
        str: Instruction information; returns None if it fails.
    """
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    command = [
        "gdb", "--batch", '-nx',
        "-ex", f"set pagination off",
        "-ex", f"source {os.path.join(SCRIPT_DIR, 'inline_addr.py')}",
        "-ex", f"find_bp_addrs {file_path} {line_number} {symbol}",
        executable_path
    ]
    
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10  # Prevent hangs
        )
        
        if result.returncode != 0:
            print(f"GDB error: {result.stderr}")
            return None
        lines = [l for l in result.stdout.splitlines() if l.strip()]
        summary = lines[-1]
            
        # Match format: 0x... - 0x...
        for part in re.findall(r"0x[0-9a-fA-F]+(?:\s*-\s*0x[0-9a-fA-F]+)?", summary):
            if '-' in part:
                start_str, end_str = map(str.strip, part.split('-'))
                start = int(start_str, 16)
                end = int(end_str, 16)
            else:
                start = end = int(part, 16)
            # ranges.append((start, end))
            return [start, end]
    except subprocess.TimeoutExpired:
        print("GDB command timed out")
        return None
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

def get_address_from_line(file_path, line_number, executable_path, type=None, symbol=None):
    """
    Get the memory address corresponding to a specified line of code (must be compiled into a debug version).

    Args:
        file_path (str): Source code file path (absolute path or path relative to the executable file)
        line_number (int): code line number
        executable_path (str): Executable file path

    Returns:
        str: The memory address (e.g., "0x4015a6") will be returned if the error occurs.
    """

    lines = gdb_info_line(file_path, line_number, executable_path, symbol)
    if lines is None:
        return None

    # tricky: assume 0
    address = lines[0]

    if type == "alloc" or type == 'free':
        # Find the call instruction associated with this address
        call_addresses = find_call_instructions_around_address(address, executable_path, type)
        if call_addresses and type == 'free':
            return int(call_addresses[0], 16)
        elif call_addresses and type == 'alloc':
            return int(call_addresses[0], 16) + 5 # call/jmp length 5, we find ret position
    return None

if __name__ == '__main__':
    # Replace "/path/to/linux/" with your own Linux kernel source code path.
    alloc_addr = get_address_from_line('fs/pipe.c', 1263, os.getenv("KERNEL_DIR")+'/vmlinux', 'alloc', 'pipe_resize_ring')
    free_addr = get_address_from_line('fs/pipe.c', 848, os.getenv("KERNEL_DIR")+'/vmlinux', 'free', 'free_pipe_info')
    print(alloc_addr, free_addr)

