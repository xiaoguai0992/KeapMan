import gdb
import pwn

class kmalloc(gdb.Command):
    """在断点触发时打印所有寄存器"""

    def __init__(self):
        super(kmalloc, self).__init__("kmalloc", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if "0x" in arg:
            arg = int(arg, 16)
        else:
            arg = int(arg)
        offset = 0
        if arg == 96:
            offset = 8
        elif arg == 192:
            offset = 16
        else:
            offset = 0
            while True:
                if 2 ** offset == arg:
                    break
                offset += 1
            #print("offset == ", offset)  
            offset *= 8
        o = gdb.execute("p &kmalloc_caches", to_string=True)
        print(o)
        o = o[o.find("0x"):o.find("0x")+18]
        kmalloc_caches = int(o, 16)
        cmd = f"tele 0x{(kmalloc_caches+offset):x}"
        o = gdb.execute(cmd, to_string=True)
        o = o[o.find("0x")+2:]
        o = o[o.find("0x"):o.find("0x")+18]
        kmem_cache = int(o, 16)
        gs_base = gdb.execute("info r gs_base", to_string=True)
        gs_base = gs_base[gs_base.find("0x"):gs_base.find("0x")+18]
        gs_base = int(gs_base, 16)
        o = gdb.execute(f"tele 0x{kmem_cache:x}", to_string=True)
        o = o[o.find("0x")+2:]
        o = o[o.find("0x"):o.find("\n")]
        cpu_offset = int(o, 16)
        print(f"gs_base == 0x{gs_base:x}, cpu_offset == 0x{cpu_offset:x}")
        kmem_cache_cpu = gs_base + cpu_offset
        gdb.execute(f"p *(struct kmem_cache *) 0x{kmem_cache:x}")
        gdb.execute(f"p *(struct kmem_cache_cpu *) 0x{kmem_cache_cpu:x}")

class dump_list(gdb.Command):
    """在断点触发时打印所有寄存器"""

    def __init__(self):
        super(dump_list, self).__init__("dump_list", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if "0x" in arg:
            arg = int(arg, 16)
        else:
            arg = int(arg)
        offset = 0
        if arg == 96:
            offset = 8
        elif arg == 192:
            offset = 16
        else:
            offset = 0
            while True:
                if 2 ** offset == arg:
                    break
                offset += 1
            #print("offset == ", offset)  
            offset *= 8
        o = gdb.execute("p &kmalloc_caches", to_string=True)
        print(o)
        o = o[o.find("0x"):o.find("0x")+18]
        kmalloc_caches = int(o, 16)
        cmd = f"tele 0x{(kmalloc_caches+offset):x}"
        o = gdb.execute(cmd, to_string=True)
        o = o[o.find("0x")+2:]
        o = o[o.find("0x"):o.find("0x")+18]
        kmem_cache = int(o, 16)
        gs_base = gdb.execute("info r gs_base", to_string=True)
        gs_base = gs_base[gs_base.find("0x"):gs_base.find("0x")+18]
        gs_base = int(gs_base, 16)
        o = gdb.execute(f"tele 0x{kmem_cache:x}", to_string=True)
        o = o[o.find("0x")+2:]
        o = o[o.find("0x"):o.find("\n")]
        cpu_offset = int(o, 16)
        print(f"gs_base == 0x{gs_base:x}, cpu_offset == 0x{cpu_offset:x}")
        kmem_cache_cpu = gs_base + cpu_offset
        #gdb.execute(f"p *(struct kmem_cache *) 0x{kmem_cache:x}")
        o = gdb.execute(f"p *(struct kmem_cache_cpu *) 0x{kmem_cache_cpu:x}", to_string= True)
        o = o[o.find("freelist"):]
        o = o[:o.find("\n")]
        o = o[o.find("0x"):o.find("0x")+18]
        addr = int(o, 16)
        o = gdb.execute(f"p *(struct kmem_cache *) 0x{kmem_cache:x}", to_string=True)
        o = o[o.find("offset"):]
        o = o[:o.find("\n")]
        o = o[o.find("= ")+2:o.find(",")]
        off = int(o)
        
        while addr:
            print(f"obj : 0x{addr:x}")
            o = gdb.execute(f"tele 0x{(addr+off):x}", to_string=True)
            o = o[:o.find("\n")]
            o = o[o.find("0x")+2:]
            o = o[o.find("0x"):o.find("0x")+18]
            if "0x0 <fixed_percpu_" == o:
                addr = 0
                break
            addr = int(o, 16)
            
class kmem_cache(gdb.Command):
    def __init__(self):
        super(kmem_cache, self).__init__("kmem_cache", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        import telnetlib
        #os.system("telnet 127.0.0.1 5555")
        tn = telnetlib.Telnet("127.0.0.1", 5555)
        print(tn.read_until(b"qemu) "))
        tn.write(b'begin_record poc\n')
        gdb.execute("c")

import telnetlib
class BreakParse_begin(gdb.Breakpoint):
    def __init__(self, func_name):
        super(BreakParse_begin, self).__init__(func_name, gdb.BP_BREAKPOINT, internal=False)
    def stop(self):
        #print("here begin")
        #os.system("telnet 127.0.0.1 5555")
        tn = telnetlib.Telnet("127.0.0.1", 5555)
        print(tn.read_until(b"qemu) "))
        tn.write(b'begin_record poc\n')
        #gdb.execute("c")
class BreakParse_end(gdb.Breakpoint):
    def __init__(self, func_name):
        super(BreakParse_end, self).__init__(func_name, gdb.BP_BREAKPOINT, internal=False)
    def stop(self):
        #print("here end")
        tn = telnetlib.Telnet("127.0.0.1", 5555)
        tn.write(b'end_record\n')
        tn.write((b'q\n'))
        #gdb.execute("c")

elf = pwn.ELF("./test")
begin = elf.sym["begin"]
end = elf.sym['end']

kmem_cache()
BreakParse_begin(f"*(0x{begin:x})")
BreakParse_end(f"*(0x{end:x})")
