import gdb
import re

class FindBPAddrs(gdb.Command):
    """
    find_bp_addrs FILE LINE FUNCNAME

    Set breakpoint at FILE:LINE (without running), and for each matching address,
    use 'info line *ADDR' to find and return address ranges where FUNCNAME appears.
    """
    def __init__(self):
        super(FindBPAddrs, self).__init__("find_bp_addrs", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if len(argv) != 3:
            print("Usage: find_bp_addrs <source_file> <line_no> <funcname>")
            return

        source_file, line_str, target_func = argv
        try:
            line_no = int(line_str)
        except ValueError:
            print(f"Invalid line number: {line_str}")
            return

        # Set breakpoint without running
        bp = gdb.Breakpoint(f"{source_file}:{line_no}")
        if not bp:
            print(f"Failed to set breakpoint at {source_file}:{line_no}")
            return

        # Get breakpoint info
        info = gdb.execute("info breakpoints", to_string=True)
        lines = info.splitlines()

        # Parse lines manually
        addr_candidates = []
        for line in lines:
            if ' in ' in line and f'at {source_file}' in line:
                parts = line.strip().split()
                addr = next((p for p in parts if p.startswith('0x')), None)
                if addr:
                    addr_candidates.append(addr)

        addr_ranges = []
        for addr in addr_candidates:
            try:
                line_info = gdb.execute(f"info line *{addr}", to_string=True)
                # Check if target_func appears in line info
                if target_func in line_info:
                    # Parse address range
                    m = re.search(r'starts at address (0x[0-9a-fA-F]+) .*? and ends at (0x[0-9a-fA-F]+)', line_info)
                    if m:
                        start, end = m.group(1), m.group(2)
                        addr_ranges.append((int(start, 16), int(end, 16)))
                    else:
                        # Possibly only one address without a range
                        m2 = re.search(r'is at address (0x[0-9a-fA-F]+)', line_info)
                        if m2:
                            addr_val = int(m2.group(1), 16)
                            addr_ranges.append((addr_val, addr_val))
                    break
            except gdb.error as e:
                print(f"Failed to get line info for {addr}: {e}")

        if addr_ranges:
            print(f"Address ranges for {target_func} at {source_file}:{line_no}:", end='')
            for start, end in addr_ranges:
                print(f" {hex(start)} - {hex(end)}")
        else:
            print(f"No matching address ranges found for function {target_func}.")

# Register command
FindBPAddrs()
