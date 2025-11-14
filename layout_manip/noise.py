import os
from capstone import *
from pwn import *
from pandare import Panda
from color import *
import json
import subprocess
import sys

class PreParse:  
    def __init__(self, objname:str):
        self.path = "./obj/"+objname+"/"
    def parse_syscall(self, syscall:dict, times:int): 
        if 'sys_number' not in syscall:
            return '\n', '\n'
        res = 'syscall('
        global_res = '' 
        sys_number = syscall['sys_number']
        res += str(sys_number)+", "
        for arg in syscall['args']:
            #print(type(arg))
            if type(arg) == str:
                res += arg+", "
            elif type(arg) == dict:
                arg_name = "tmp_"+str(arg['idx'])+'_'+str(times)
                if arg['if_create'] == 1:
                    if '[' in arg['type']:  
                        o = arg['type']
                        array_type = o[:o.find('[')]
                        array_length = o[o.find('['):]
                        global_res += array_type + ' ' + arg_name +array_length+';\n'
                    else:
                        global_res += arg['type'] + ' ' + arg_name +';\n'
                if '[' in arg['type'] and 'offset' in arg:
                    res += f"{arg_name}[{arg['offset']}], "
                else:
                    res += arg_name+", "
            else:
                print("bad type of arg!")
        res = res[:-2]
        res += ");\n"
        if type(syscall['retval']) == dict:
            retval_name = "tmp_"+str(syscall['retval']['idx'])+"_"+str(times)
            if syscall['retval']['if_create'] == 1:
                if '[' in syscall['retval']['type']:
                    o = syscall['retval']['type']
                    array_type = o[:o.find('[')]
                    array_length = o[o.find('['):]
                    global_res += array_type + ' ' + retval_name + array_length+';\n'
                else:
                    global_res += syscall['retval']['type'] + ' ' + retval_name+';\n'
            if '[' in syscall['retval']['type'] and 'offset' in syscall['retval']:
                res = f"{retval_name}[{syscall['retval']['offset']}] = " + res
            else:
                res = retval_name + " = " + res
        
        #print(global_res)
        #print(res)
        
        return global_res, res
    def alloc_code(self, tot_times:int)->str:
        res = ''
        f = open(self.path+"setup.c", "r")
        res = f.read()
        #print(res)
        f = open(self.path+"prepare.json", "r")
        prepare_con = json.loads(f.read())
        f = open(self.path+"alloc.json", "r")
        alloc_con = json.loads(f.read())
        global_code = ''
        prepare_code = ''
        begin_code = ''
        for i in range(tot_times):
            for syscall in prepare_con:
                p1, p2 = self.parse_syscall(syscall, i)
                if len(p1) > 1:
                    global_code += p1
                if len(p2) > 1:
                    prepare_code += "\t"+p2
        for i in range(tot_times):
            for syscall in alloc_con:
                a1, a2 = self.parse_syscall(syscall, i)
                if len(a1) > 1:
                    global_code += a1
                if len(a2) > 1:
                    begin_code += "\t"+a2
        prepare_code = "void prepare(){\n"+prepare_code+"}\n"
        begin_code = "void begin(){\n"+begin_code+"}\n"
        res += global_code + prepare_code + begin_code
        res += "void end(){\n\t;\n}\n"
        res += "int main(){\n\tsetup();\n\tprepare();\n\tbegin();\n\tend();\n}\n"
        print(res)
        return res
        
    def free_code(self, tot_times:int)->str:
        res = ''
        f = open(self.path+"setup.c", "r")
        res = f.read()
        #print(res)
        f = open(self.path+"prepare.json", "r")
        prepare_con = json.loads(f.read())
        f = open(self.path+"alloc.json", "r")
        alloc_con = json.loads(f.read())
        f = open(self.path+"free_prepare.json", "r")
        free_prepare_con = json.loads(f.read())
        f = open(self.path+"free.json")
        free_con = json.loads(f.read())

        global_code = ''
        prepare_code = ''
        begin_code = ''

        for i in range(tot_times):
            for syscall in prepare_con:
                p1, p2 = self.parse_syscall(syscall, i)
                if len(p1) > 1:
                    global_code += p1
                if len(p2) > 1:
                    prepare_code += "\t"+p2
        for i in range(tot_times):
            for syscall in alloc_con:
                a1, a2 = self.parse_syscall(syscall, i)
                if len(a1) > 1:
                    global_code += a1
                if len(a2) > 1:
                    prepare_code += "\t"+a2
        for i in range(tot_times):
            for syscall in free_prepare_con:
                fp1, fp2 = self.parse_syscall(syscall, i)
                if len(fp1) > 1:
                    global_code += fp1
                if len(fp2) > 1:
                    prepare_code += "\t"+fp2
        for i in range(tot_times):
            for syscall in free_con:
                f1, f2 = self.parse_syscall(syscall, i)
                if len(f1) > 1:
                    global_code += f1
                if len(f2) > 1:
                    begin_code += "\t"+f2
        prepare_code = "void prepare(){\n"+prepare_code+"}\n"
        begin_code = "void begin(){\n"+begin_code+"}\n"
        res += global_code + prepare_code + begin_code
        res += "void end(){\n\t;\n}\n"
        res += "int main(){\n\tsetup();\n\tprepare();\n\tbegin();\n\tend();\n}\n"
        print(res)
        return res
    def save(self, con:str):
        f = open("./input/exp.c", "w")
        f.write(con)
class prepare:  
    def __init__(self):
        pass
    def snap(self):
        os.chdir("./input")
        os.system("./compile.sh")
        os.system("./start")
        os.chdir("..")

class noise:
    def __init__(self):
        self.code = None
        print("Loading vmlinux ...")
        self.vmlinux = ELF("./input/vmlinux", checksec=False)
        print("Getting struct info ...")
        self.sh = process(["gdb", "./input/vmlinux"])
        self.kmem_cache_name_offset = self.get_struct_offset(self.sh, "kmem_cache", "name")
        self.slab_cache_offset = self.get_struct_offset(self.sh, "page", "slab_cache")
        if self.slab_cache_offset == -1:
            self.slab_cache_offset = self.get_struct_offset(self.sh, "slab", "slab_cache")
        self.page_next_offset = self.get_struct_offset(self.sh, "page", "next")
        if self.page_next_offset == -1:
            self.page_next_offset = self.get_struct_offset(self.sh, "slab", "next")
        #print(f"kmem_cache_name_offset == 0x{self.kmem_cache_name_offset:x}")
        self.test = ELF("./input/test", checksec=False)
        if "prim_in" in self.test.sym and "prim_out" in self.test.sym:
            self.use_prim = True
            self.prim_in = self.test.sym['prim_in']
            self.prim_out = self.test.sym['prim_out']
        else:
            self.use_prim = False
    def get_struct_offset(self, sh, struct:str, number:str)->int:
        sh.recvuntil("pwndbg>")
        sh.sendline(f"p &(*(struct {struct} *)0)->{number}")
        Ox = sh.recvuntil("0x", timeout=2)
        if Ox == b'':
            return -1
        con = sh.recvuntil("\n", timeout=3)
        if len(con) == 0:
            return -1
        res = ''
        for ch in con:
            if chr(ch) not in "1234567890abcdef":
                break
            res += chr(ch)   
        res = int(res, 16)
        return res
    def get_function_addr(self, sh, function:str)->int:
        sh.recvuntil("pwndbg>")
        sh.sendline(f"b {function}")
        con = sh.recvuntil("0x", timeout=3)
        if len(con) == 0:
            return -1
        con = sh.recvuntil("\n", timeout=3)
        if len(con) == 0:
            return -1
        res = ''
        for ch in con:
            if chr(ch) not in "1234567890abcdef":
                break
            res += chr(ch)   
        res = int(res, 16)
        return res
    def prepare(self):
        os.system("cp ./input/bzImage ./sym/")
        os.chdir("./sym/")
        os.system("python3 pro.py")
        os.chdir("..")
        os.system("readelf -wF ./input/vmlinux > ./output/fpinfo")
    def extract_syscall(self, poc_path:str)->list: 
        '''
        list格式如下：
        [{
            "sysnumber":int,
            "addr":int
        }, {...}, {...}]
        '''
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        elf = ELF(poc_path)
        text_section = elf.get_section_by_name('.text')
        text_start = text_section.header.sh_addr  
        text_size = text_section.header.sh_size   
        text_data = elf.read(text_start, text_size)  
        insns = []
        for insn in md.disasm(text_data, text_start):
            insns.append(insn)
        rev_insns = insns[::-1]
        res = {}
        for insn in rev_insns:
            #print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
            #print(insn.op_str)
            if insn.mnemonic == "syscall":
                #print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                res[insn.address] = 1
        return res
    def get_func_addr(self, name:str):
        f = open("./sym/file")
        for line in f:
            if f" {name}\n" in line:
                addr = line[0:16]
                addr = int(addr, 16)
                return addr
        if name in self.vmlinux.sym:
            addr = self.vmlinux.sym[name]
        else:
            addr = self.get_function_addr(self.sh, name)
        return addr
    def init_fp_info(self)->map:
        res = {}
        f = open("./output/fpinfo")
        for line in f:
            if "rsp+" not in line:
                continue
            addr = int(line[0:16], 16)
            fp = line[17:]
            fp = fp[:fp.find(" ")]
            #print(fp)
            res[addr] = fp
        return res
    def parse(self, poc_path:str, snap:str, goal_addr=[]):
        sys_entry = self.get_func_addr("entry_SYSCALL_64")
        current_task_offset = self.get_func_addr("current_task")
        syscall_info = self.extract_syscall(poc_path)
        end_addrs = {}
        for x in syscall_info:
            end_addrs[x+2] = 1
        kmalloc = self.get_func_addr("__kmalloc")
        kvmalloc = self.get_func_addr("kvmalloc_node")
        kmalloc_track_caller = self.get_func_addr("__kmalloc_track_caller")
        kmem_cache_alloc_trace = self.get_func_addr("kmem_cache_alloc_trace")
        kmem_cache_alloc = self.get_func_addr("kmem_cache_alloc")
        kmalloc_node_track_caller = self.get_func_addr("__kmalloc_node_track_caller")
        kmem_cache_alloc_node_trace = self.get_func_addr("kmem_cache_alloc_node_trace")
        kfree = self.get_func_addr("kfree")
        kmem_cache_free = self.get_func_addr("kmem_cache_free")
        kvfree = self.get_func_addr("kvfree")
        kvfree_call_rcu = self.get_func_addr("kvfree_call_rcu")
        #print(f"kmalloc == 0x{kmalloc:x}, kfree == 0x{kfree:x}")
        panda = Panda(arch="x86_64", mem='512M', extra_args=["-nographic"])
        #panda.load_plugin("taint2")  
        panda.cb_insn_translate(lambda x,y: True)
        self.if_check = False 
        self.kmalloc_ret_addr = 0
        self.objs = {}
        self.record = []
        self.res = [] # record all record in same task
        self.other_record = [] 
        self.other_res = [] # record all record in other task
        self.full_record = []
        self.full_res = [] # record all record in same&other task
        self.sys_task = 0
        self.goal_idxs = [] # used to record the idx of the target operation in each tested system call
        self.goal_addr = goal_addr
        self.log_for_obj = [] # record the addresses of all objects during the execution of a syscall, and update them at the entry point of each syscall
        self.log_for_goal_objs = [] # record all goalobj during this execution process
        self.this_goal_idxs = [] # record all goal_idx during the execution of a syscall
        self.log_for_all_obj = [] # record all object information captured during the entire snapshot execution process
        self.current_in_goal = False # used to identify the first memory operation after goal_addr. It is set to True at goal_addr and set to False at the first free or alloc_ret_addr operation thereafter.
        self.sys_idx = 0 # used to record the sequence number of syscall
        self.prim_idx = 0 # used to record the sequence number of prim_idx; only one of prim_idx and sys_idx is active.
        if len(self.goal_addr) == 0:
            red("goal_addr is not given!")
        if "--backtrace" in sys.argv:
            self.fp_info = self.init_fp_info()
            self.addr2name = {}
            for name in self.vmlinux.sym:
                addr = self.vmlinux.sym[name]
                self.addr2name[addr] = name
        @panda.cb_insn_exec
        def on_insn(cpu, pc):
            if self.use_prim == False and pc == sys_entry+3  :
                rax = panda.arch.get_reg(cpu, 0)
                #if rax not in self.interesting:
                #    return
                self.if_check = True
                print(f"\n======== parse syscall at 0x{pc:x} -> sys_number == {rax}, sys_idx:{self.sys_idx} ========")
                rdi = panda.arch.get_reg(cpu, 7)
                rsi = panda.arch.get_reg(cpu, 6)
                rdx = panda.arch.get_reg(cpu, 2)
                r10 = panda.arch.get_reg(cpu, 10)
                print(f"rdi == 0x{rdx:x}\nrsi == 0x{rsi:x}\nrdx == 0x{rdx:x}\nr10 == 0x{r10:x}\n") 
                self.record = []
                self.other_record = []
                self.full_record = []
                self.objs = {}
                self.sys_task = get_task(cpu)
                if self.code == None:
                    self.code = f"syscall({rax}, 0x{rdi:x}, 0x{rsi:x}, 0x{rdx:x}, 0x{r10:x})"
                    print(self.code)
                self.op_idx = 0 # used to count the operation sequence number in each syscall
                self.hav_in_goal = False 
                self.log_for_obj = []
                self.this_goal_idxs = []
            if self.use_prim == False and pc in end_addrs:
                print(f"self.op_idx == {self.op_idx}")
                self.if_check = False
                self.sys_task = 0
                for obj in self.objs:
                    light_blue(f"obj : 0x{obj:x} -> cache : {self.objs[obj]}")
                self.res.append(self.record)
                self.other_res.append(self.other_record)
                self.full_res.append(self.full_record)
                #print(f"record : {self.record}")
                #print(f"other_record : {self.other_record}")
                #print(f"full_record : {self.full_record}")
                self.op_idx = 0
                if self.hav_in_goal == False:
                    self.goal_idxs.append(-1) 
                #print(f"this goal_idxs : {self.this_goal_idxs}")
                self.sys_idx += 1
            if self.use_prim == True and pc == self.prim_in:
                self.if_check = True
                print(f"\n======== prim_in, prim_idx : {self.prim_idx} ========")
                self.record = []
                self.other_record = []
                self.full_record = []
                self.objs = {}
                self.sys_task = 0#get_task(cpu)
                #if self.code == None:
                #    self.code = f"syscall({rax}, 0x{rdi:x}, 0x{rsi:x}, 0x{rdx:x}, 0x{r10:x})"
                #    print(self.code)
                self.op_idx = 0 # used to count the operation sequence number in each syscall
                self.hav_in_goal = False 
                self.log_for_obj = []
                self.this_goal_idxs = []
            if self.use_prim == True and pc == self.prim_out:
                #print(f"self.op_idx == {self.op_idx}")
                self.if_check = False
                self.sys_task = 0
                #for obj in self.objs:
                #    light_blue(f"obj : 0x{obj:x} -> cache : {self.objs[obj]}")
                self.res.append(self.record)
                self.other_res.append(self.other_record)
                self.full_res.append(self.full_record)
                #print(f"record : {self.record}")
                #print(f"other_record : {self.other_record}")
                #print(f"full_record : {self.full_record}")
                self.op_idx = 0
                self.prim_idx += 1
            if self.if_check == False:
                return
            if pc == kmalloc:
                self.op_idx += 1
                backtrace(cpu, pc)
                rsp = panda.arch.get_reg(cpu, 4)
                self.kmalloc_ret_addr = panda.virtual_memory_read(cpu, rsp, 8)
                self.kmalloc_ret_addr = u64(self.kmalloc_ret_addr)
                #print(f"kmalloc_ret_addr : 0x{self.kmalloc_ret_addr:x}")
            elif pc == kvmalloc:
                self.op_idx += 1
                backtrace(cpu, pc)
                rsp = panda.arch.get_reg(cpu, 4)
                self.kmalloc_ret_addr = panda.virtual_memory_read(cpu, rsp, 8)
                self.kmalloc_ret_addr = u64(self.kmalloc_ret_addr)
            elif pc == kmalloc_track_caller:
                self.op_idx += 1
                backtrace(cpu, pc)
                rsp = panda.arch.get_reg(cpu, 4)
                self.kmalloc_ret_addr = panda.virtual_memory_read(cpu, rsp, 8)
                self.kmalloc_ret_addr = u64(self.kmalloc_ret_addr)
            elif pc == kmem_cache_alloc_trace:
                self.op_idx += 1
                #print("Here pc == ", hex(pc))
                backtrace(cpu, pc)
                rsp = panda.arch.get_reg(cpu, 4)
                self.kmalloc_ret_addr = panda.virtual_memory_read(cpu, rsp, 8)
                self.kmalloc_ret_addr = u64(self.kmalloc_ret_addr)
            elif pc == kmem_cache_alloc:
                self.op_idx += 1
                backtrace(cpu, pc)
                rsp = panda.arch.get_reg(cpu, 4)
                self.kmalloc_ret_addr = panda.virtual_memory_read(cpu, rsp, 8)
                self.kmalloc_ret_addr = u64(self.kmalloc_ret_addr)
            elif pc == kmalloc_node_track_caller:
                self.op_idx += 1
                backtrace(cpu, pc)
                rsp = panda.arch.get_reg(cpu, 4)
                self.kmalloc_ret_addr = panda.virtual_memory_read(cpu, rsp, 8)
                self.kmalloc_ret_addr = u64(self.kmalloc_ret_addr)
            elif pc == kmem_cache_alloc_node_trace:
                self.op_idx += 1
                backtrace(cpu, pc)
                rsp = panda.arch.get_reg(cpu, 4)
                self.kmalloc_ret_addr = panda.virtual_memory_read(cpu, rsp, 8)
                self.kmalloc_ret_addr = u64(self.kmalloc_ret_addr)
            elif pc == self.kmalloc_ret_addr: 
                rax = panda.arch.get_reg(cpu, 0)
                self.kmalloc_ret_addr = 0
                try:
                    cache_name = get_kmem_cache(cpu, rax)
                except:
                    print(f"get cache name error, obj : {rax:x}")
                    self.op_idx -= 1 # in previous kmalloc hooks, the value would be incremented by 1, but this is now abandoned; instead, it should be decremented by 1.
                    return
                green(f"obj : 0x{rax:x}, kmem_cache : {cache_name}, opid is {len(self.full_record)}")
                self.objs[rax] = cache_name
                self.log_for_obj.append(rax)
                if self.current_in_goal == True:
                    self.current_in_goal = False
                    self.log_for_goal_objs.append(f"a@{cache_name}@{hex(rax)}@{len(self.log_for_all_obj)}")
                self.log_for_all_obj.append(f"a@{cache_name}@{hex(rax)}@{len(self.log_for_all_obj)}")
                user_ret = get_user_ret(cpu)
                if user_ret-2  in syscall_info:
                    #red(f"same task 0x{user_ret:x}")
                    self.record.append(f"a@{cache_name}")
                else:
                    #red(f"different task 0x{user_ret:x}")
                    self.other_record.append(f"a@{cache_name}")
                self.full_record.append(f"a@{cache_name}")
            elif pc == kfree:
                self.op_idx += 1
                backtrace(cpu, pc)
                rdi = panda.arch.get_reg(cpu, 7)
                objidx = 0 
                for obj in self.objs:
                    if obj == rdi:
                        break
                    objidx += 1
                if objidx == len(self.objs):
                    objidx = -1
                try:
                    cache_name = get_kmem_cache(cpu, rdi)
                except:
                    if rdi == 0:
                        return 
                    print(f"get cache name error, obj : {rdi:x}")
                    self.op_idx -= 1
                    return
                self.log_for_obj.append(rdi)
                if self.current_in_goal == True:
                    self.current_in_goal = False
                    self.log_for_goal_objs.append(f"f@{cache_name}@{hex(rdi)}@{len(self.log_for_all_obj)}")
                self.log_for_all_obj.append(f"f@{cache_name}@{hex(rdi)}@{len(self.log_for_all_obj)}")
                yellow(f"kfree with rdi == 0x{rdi:x}, objidx == {objidx}, kmem_cache : {cache_name}, opid is {len(self.full_record)}")
                user_ret = get_user_ret(cpu)
                if user_ret-2  in syscall_info:
                    #red(f"same task 0x{user_ret:x}")
                    self.record.append(f"f@{cache_name}@{objidx}")
                else:
                    #backtrace(cpu)
                    #red(f"different task 0x{user_ret:x}")
                    self.other_record.append(f"f@{cache_name}@{objidx}")
                self.full_record.append(f"f@{cache_name}@{objidx}")
            elif pc == kmem_cache_free:
                self.op_idx += 1
                backtrace(cpu, pc)
                rsi = panda.arch.get_reg(cpu, 6)
                objidx = 0
                for obj in self.objs:
                    if obj == rsi:
                        break
                    objidx += 1
                if objidx == len(self.objs):
                    objidx = -1
                try:
                    cache_name = get_kmem_cache(cpu, rsi)
                except:
                    print(f"get cache name error, obj : {rsi:x}")
                    self.op_idx -= 1
                    return
                self.log_for_obj.append(rsi)
                if self.current_in_goal == True:
                    self.current_in_goal = False
                    self.log_for_goal_objs.append(f"f@{cache_name}@{hex(rsi)}@{len(self.log_for_all_obj)}")
                self.log_for_all_obj.append(f"f@{cache_name}@{hex(rsi)}@{len(self.log_for_all_obj)}")
                yellow(f"kmem_cache_free with rsi == 0x{rsi:x}, objidx == {objidx}, kmem_cache : {cache_name}, opid is {len(self.full_record)}")
                info = {}
                info['action'] = 'free'
                info['cache'] = cache_name
                info['objidx'] = objidx
                user_ret = get_user_ret(cpu)
                if user_ret-2  in syscall_info:
                    #red(f"same task 0x{user_ret:x}")
                    self.record.append(f"f@{cache_name}@{objidx}")
                else:
                    #red(f"different task 0x{user_ret:x}")
                    self.other_record.append(f"f@{cache_name}@{objidx}")
                self.full_record.append(f"f@{cache_name}@{objidx}")
            elif pc == kvfree_call_rcu:
                self.op_idx += 1
                backtrace(cpu, pc)
                rdi = panda.arch.get_reg(cpu, 7)
                rsi = panda.arch.get_reg(cpu, 6)
                objidx = 0
                for obj in self.objs:
                    if obj == (rdi-rsi):
                        break
                    objidx += 1
                if objidx == len(self.objs):
                    objidx = -1
                try:
                    cache_name = get_kmem_cache(cpu, rdi-rsi)
                except:
                    print(f"get cache name error, obj : {rdi-rsi:x}")
                    self.op_idx -= 1
                    return
                self.log_for_obj.append(rdi-rsi)
                if self.current_in_goal == True:
                    self.current_in_goal = False
                    self.log_for_goal_objs.append(f"f@{cache_name}@{hex(rdi-rsi)}@{len(self.log_for_all_obj)}")
                self.log_for_all_obj.append(f"f@{cache_name}@{hex(rdi-rsi)}@{len(self.log_for_all_obj)}")
                yellow(f"kvfree_call_rcu with (rdi-rsi) == 0x{(rdi-rsi):x}, objidx == {objidx}, kmem_cache : {cache_name}, opid is {len(self.full_record)}")
                user_ret = get_user_ret(cpu)
                if user_ret-2  in syscall_info:
                    #red(f"same task 0x{user_ret:x}")
                    self.record.append(f"f@{cache_name}@{objidx}")
                else:
                    #backtrace(cpu)
                    #red(f"different task 0x{user_ret:x}")
                    self.other_record.append(f"f@{cache_name}@{objidx}")
                self.full_record.append(f"f@{cache_name}@{objidx}")
            elif pc in self.goal_addr: 
                #print(f"op_idx == {self.op_idx}")
                print("here goal")
                self.goal_idxs.append(self.op_idx)
                self.hav_in_goal = True
                self.this_goal_idxs.append(self.op_idx)
                self.current_in_goal = True
        def get_kmem_cache(cpu, addr:int)->str:
            page = addr - (addr & 0xfff)
            page_base_offset = addr & 0xffff888000000000
            page_offset = (page - page_base_offset) // 0x1000
            page_struct = 0xffffea0000000000 + page_offset * 0x40
            next = panda.virtual_memory_read(cpu, page_struct+self.page_next_offset, 8)
            next = u64(next)
            if next&1 == 1:
                page_struct = next - 1
            kmem_cache = panda.virtual_memory_read(cpu, page_struct+self.slab_cache_offset, 8)
            kmem_cache = u64(kmem_cache)
            name_addr = panda.virtual_memory_read(cpu, kmem_cache+self.kmem_cache_name_offset, 8)
            name_addr = u64(name_addr)
            name = panda.virtual_memory_read(cpu, name_addr, 0x10)
            name = name.decode("iso-8859-1")
            name = name[:name.find("\x00")]
            return name
        def get_task(cpu)->int:
            gs_base = panda.arch.get_reg(cpu, "gs")
            #print(f"gs_base == {hex(gs_base)}")
            task = panda.virtual_memory_read(cpu, gs_base+current_task_offset, 8)
            #print(task)
            task = u64(task)
            #print(f"task == {hex(task)}")   
            return task
        def get_user_ret(cpu)->int:
            rsp = panda.arch.get_reg(cpu, 4)
            stack_end = rsp - (rsp&0xfff) + 0xfd8
            user_ret = panda.virtual_memory_read(cpu, stack_end, 8)
            user_ret = u64(user_ret)
            return user_ret
        def get_fp(cpu, pc):
            while True:
                if pc in self.fp_info:
                    fp = self.fp_info[pc]
                    reg = fp[0:3]
                    offset = fp[3:]
                    offset = int(offset)
                    return reg, offset
                pc -= 1
        def addr_2_name(pc):
            for i in range(0x1000):
                if (pc - i) in self.addr2name:
                    return self.addr2name[pc-i], i
            return "notFind", 0         
        def backtrace(cpu, pc):
            if "--backtrace" not in sys.argv:
                return
            fname, foff = addr_2_name(pc)
            print(f"0x{pc:x} -> {fname}+{foff}")
            os.system(f"cat ../output/fpinfo | grep {pc:x} | grep rsp > ../output/tmpfile")
            f = open("../output/tmpfile", "r")
            con = f.read()
            off = con[con.find("rsp+")+4:]
            off = off[:off.find(" ")]
            #print("off ==", off)
            off = int(off)
            rsp = panda.arch.get_reg(cpu, "rsp")
            while True:
                try: # considering the backtrace stack reached its bottom (the kernel stack only has 0x1000), the situation encountered was exactly an interrupt.
                    pc = panda.virtual_memory_read(cpu, rsp+off-8, 8)
                    pc = u64(pc)
                except:
                    pc = 0
                if pc <= 0xffffffff80000000:
                    break
                fname, foff = addr_2_name(pc)
                print(f"0x{pc:x} -> {fname}+{foff}")
                reg, offset = get_fp(cpu, pc)
                #print(f"reg == {reg}, offset == {offset}")
                off += offset
        os.chdir("./input")
        panda.enable_precise_pc()
        panda.run_replay(snap)
        os.chdir("..")
        f = open("output/noise_info.json", "w")
        f.write(json.dumps(self.res))
        f = open("output/other_noise_info.json", "w")
        f.write(json.dumps(self.other_res))
        f = open("./output/goal_idxs", "w")
        f.write(json.dumps(self.goal_idxs))                         
class Analysis:
    def __init__(self):
        pass
    def encode(self, operations:list)->str:
        res = ''
        for x in operations:
            res += x
        return res
    def most(self, noise_info)->list:
        count = {}
        max_cnt = 0
        res = None
        for operations in noise_info:
            code = self.encode(operations)
            if code in count:
                count[code] += 1
            else:
                count[code] = 1
            if count[code] > max_cnt:
                max_cnt = count[code]
                res = operations
        #print(f"most operations : {res}")
        return res
    def frequency(self, noise_info:list):  
        record = {} # str_for_operations -> times
        time = 0
        for operations in noise_info:
            code = self.encode(operations)
            if code in record:
                record[code].append(time)
            else:
                record[code] = [time]
            time += 1
        for r in record:
            print(f"{r} -> {record[r]}")
            if len(record[r]) == 1 and record[r][0] == 0:
                print(f"{r} only first")
            elif len(record[r]) == 1 :
                print(f"{r} only once")
            else:
                dis = record[r][1] - record[r][0]
                equal_dis = True
                for i in range(1, len(record[r])-1, 1):
                    if record[r][i+1] - record[r][i] != dis:
                        equal_dis = False
                        break
                if equal_dis :
                    print(f"{r} : stable frequency at {dis}")
    def most_goal_idx(self, goal_idxs:list)->int:
        cnt = {}
        max_cnt = 0
        res = None
        for idx in goal_idxs:
            if idx in cnt:
                cnt[idx] += 1
            else :
                cnt[idx] = 1
            if max_cnt < cnt[idx]:
                max_cnt = cnt[idx]
                res = idx
        return res
    def analysis(self):
        f = open("output/noise_info.json", "r")
        noise_info = json.loads(f.read())
        f = open("output/other_noise_info.json", "r")
        other_noise_info = json.loads(f.read())
        most_op = self.most(noise_info)
        print(f"most_op is {most_op}")
        #print(f"if_first_same : {self.encode(noise_info[0]) == self.encode(most_op)}")
        self.frequency(noise_info)
        try:
            f = open("./output/syscalls", "r")
            syscalls = json.loads(f.read())
        except:
            syscalls = []
        syscalls.append(most_op) 
        f = open("./output/syscalls", "w")
        f.write(json.dumps(syscalls))
        f = open("./output/goal_idxs", "r")
        goal_idxs = json.loads(f.read())
        goal_idx = self.most_goal_idx(goal_idxs)
        try:
            f = open("./output/syscall_goal_idxs", "r")
            syscall_goal_idxs = json.loads(f.read())
        except:
            syscall_goal_idxs = []
        syscall_goal_idxs.append(goal_idx)
        f = open("./output/syscall_goal_idxs", "w")
        f.write(json.dumps(syscall_goal_idxs))

        green(f"most_op is {most_op}")
        green(f"goal op idx is {goal_idx}")

        return most_op, goal_idx
    def real_alloc_times(self, ops:list, goal_idxs:list)->int:  # only guarantee that the structure will not be released within a single system call
        res = 0
        for i in range(len(ops)):# ops is a list of many syscalls
            if goal_idxs[i] == -1:
                continue
            if_free_same = False
            for op in ops[i]:# ops[i] is a list of strings: ['a@kmalloc-512', 'a@kmalloc-96', 'a@kmalloc-128', 'a@kmalloc-512', 'f@kmalloc-512@3', 'f@kmalloc-96@1', 'f@kmalloc-512@0']
                if op[0] == 'a':
                    continue
                free_idx = op.split("@")[2]
                free_idx = int(free_idx)
                if free_idx == goal_idxs[i]:
                    if_free_same = True
                    break
            if if_free_same == False:
                res += 1
        return res
    def real_free_times(self, ops:list, goal_idxs:list)->int:
        # ONLY HALF  maybe no use
        res = 0
        for i in range(len(ops)): # ops is a list of many syscalls.
            for op in ops[i]: # ops[i] is a list of strings: ['a@kmalloc-512', 'a@kmalloc-96', 'a@kmalloc-128', 'a@kmalloc-512', 'f@kmalloc-512@3', 'f@kmalloc-96@1', 'f@kmalloc-512@0']
                print(op[0])
        return res

import multiprocessing

def parse_one_obj_alloc(obj_name:str, queue): # Analyze the alloc allocation sequence of an object from beginning to end.
    path = "./obj/"+obj_name+"/"
    # Generate alloc test code
    pp = PreParse(obj_name)
    con = pp.alloc_code(20)
    pp.save(con)
    # Take a snapshot
    p = prepare()
    p.snap()
    # Run a snapshot to capture the sequence
    f = open(path+"alloc_addr", "r")
    alloc_addr = json.loads(f.read())
    n = noise()
    n.parse(os.path.abspath(os.getcwd())+"/input/test", "poc", alloc_addr)
    # Analyze sequence
    a = Analysis()
    alloc_op, alloc_idx = a.analysis()
    print(f"alloc_op is {alloc_op}, alloc_idx == {alloc_idx}")
    queue.put(alloc_op)
    queue.put(alloc_idx)

def parse_one_obj_free(obj_name:str, queue): # Analyze the free allocation sequence of an object from beginning to end.
    path = "./obj/"+obj_name+"/"
    # Generate free test code
    pp = PreParse(obj_name)
    con = pp.free_code(20)
    pp.save(con)
    # Take a snapshot
    p = prepare()
    p.snap()
    
    # Run a snapshot to capture the sequence
    f = open(path+"free_addr", "r")
    free_addr = json.loads(f.read())
    n = noise()
    n.parse(os.path.abspath(os.getcwd())+"/input/test", "poc", free_addr)
    # Analyze sequence
    a = Analysis()
    free_op, free_idx = a.analysis()
    print(f"free_op is {free_op}, free_idx == {free_idx}")
    queue.put(free_op)
    queue.put(free_idx)
        
def clean():
    os.system("rm ./output/*")

def parse_one_obj(obj_name:str):
    queue = multiprocessing.Queue()
    p1 = multiprocessing.Process(target=parse_one_obj_alloc, args=(obj_name, queue))
    p1.start()
    p1.join()
    alloc_op = queue.get()
    alloc_idx = queue.get()
    p2 = multiprocessing.Process(target=parse_one_obj_free, args=(obj_name, queue))
    p2.start()
    p2.join()
    free_op = queue.get()
    free_idx = queue.get()
    light_blue(f"alloc_op is {alloc_op}, alloc_idx == {alloc_idx}")
    light_blue(f"free_op is {free_op}, free_idx == {free_idx}")
    f = open("./obj/"+obj_name+"/obj_info.json", "w")
    con = {}
    con['alloc_op'] = alloc_op
    con['alloc_idx'] = alloc_idx
    con['free_op'] = free_op
    con['free_idx'] = free_idx
    f.write(json.dumps(con))
    return alloc_op, alloc_idx, free_op, free_idx

def parse_all_obj():
    res = []
    for obj_name in os.listdir("./obj"):
        record = {}
        record['name'] = obj_name
        #print(obj_name)
        alloc_op, alloc_idx, free_op, free_idx = parse_one_obj(obj_name)
        record['alloc_op'] = alloc_op
        record['alloc_idx'] = alloc_idx
        record['free_op'] = free_op
        record['free_idx'] = free_idx
        res.append(record)
    print('\n')
    for record in res:
        light_blue("="*60)
        green(f"obj_name : {record['name']}")
        green(f"alloc_op is {record['alloc_op']}, alloc_idx == {record['alloc_idx']}")
        green(f"free_op is {record['free_op']}, free_idx == {record['free_idx']}")
        green('')
    return res

def check_useful_alloc(goal_addrs:list, poc_path="./input/exp.c")->int:
    os.system(f"cp {poc_path} ./input/exp.c")
    p = prepare()
    p.snap()
    n = noise()
    n.parse("./input/test", "poc", goal_addrs)
    print(n.log_for_goal_objs)
    print(n.log_for_all_obj)
    res = 0
    for x in n.log_for_goal_objs:
        if x.split("@")[0] == "a":
            acache = x.split("@")[1]
            aobj = x.split("@")[2]
            aidx = x.split("@")[3]
            print(f"aobj : {aobj}")
            if_free_aobj = False
            for idx in range(int(aidx), len(n.log_for_all_obj), 1):
                xx = n.log_for_all_obj[idx]
                if xx.split("@")[0] == 'a':
                    continue
                fcache = xx.split("@")[1]
                fobj = xx.split("@")[2]
                fidx = xx.split("@")[3]
                if fobj == aobj:
                    if_free_aobj = True
                    print(f"fobj == {fobj}")
                    break
            if if_free_aobj == False:
                res += 1
    print(f"real alloc times is {res}")
    return res, len(n.log_for_goal_objs), len(n.log_for_all_obj)
def check_useful_alloc_obj(objname:str)->int: 
    path = "./obj/"+objname+"/"
    f = open(path+"alloc_addr", "r")
    alloc_addr = json.loads(f.read())
    f = open(path+"free_addr", "r")
    free_addr = json.loads(f.read())
    check_useful_alloc(alloc_addr+free_addr)
def get_active_alloc_obj(log_for_goal_objs:list, log_for_all_obj:list)->list:
    res = []
    for x in log_for_goal_objs:
        if x.split("@")[0] == "a":
            acache = x.split("@")[1]
            aobj = x.split("@")[2]
            aidx = x.split("@")[3]
            if_free_aobj = False
            for idx in range(int(aidx), len(log_for_all_obj), 1):
                xx = log_for_all_obj[idx]
                if xx.split("@")[0] == 'a':
                    continue
                fcache = xx.split("@")[1]
                fobj = xx.split("@")[2]
                fidx = xx.split("@")[3]
                if fobj == aobj:
                    if_free_aobj = True
                    print(f"fobj == {fobj}")
                    break
            if if_free_aobj == False:
                res.append(x)
    return res
def check_useful_free(goal_addrs:list, goal_alloc_op_nums:int, alloc_op_nums:int, poc_path="./input/exp.c")->int:
    os.system(f"cp {poc_path} ./input/exp.c")
    p = prepare()
    p.snap()
    n = noise()
    n.parse("./input/test", "poc", goal_addrs)
    
    actvie_alloc_objs = get_active_alloc_obj(n.log_for_goal_objs[0:goal_alloc_op_nums], n.log_for_all_obj[0:alloc_op_nums])

    my_goal_ops = n.log_for_goal_objs[goal_alloc_op_nums:]

    print(actvie_alloc_objs)
    print(my_goal_ops)

    res = 0
    for x in my_goal_ops:
        if x.split("@")[0] == 'a':
            continue
        cache = x.split("@")[1]
        obj = x.split("@")[2]
        for xx in actvie_alloc_objs:
            aobj = xx.split("@")[2]
            if obj == aobj:
                print(f"real free obj {obj}")
                res += 1


    print(f"useful_free_times == {res}")
    return res
def check_useful_free_obj(objname:str)->int: 
    path = "./obj/"+objname+"/"
    f = open(path+"alloc_addr", "r")
    alloc_addr = json.loads(f.read())
    f = open(path+"free_addr", "r")
    free_addr = json.loads(f.read())
    #print(alloc_addr+free_addr)
    check_useful_free(alloc_addr+free_addr)


def test():
    #alloc_times, alloc_op_nums = check_useful_alloc([18446744071582416587, 18446744071582417105], "/mnt/hgfs/slake/exps/msg_msg_alloc.c")
    free_times = check_useful_free([18446744071582416587, 18446744071582417105], 20, "/mnt/hgfs/slake/exps/msg_msg_free.c")
    #check_useful_free_obj("msg_msg")
    pass

def main():
    if "-p" in sys.argv or "--prepare" in sys.argv:
        p = prepare()
        p.snap()
    if "-n1" in sys.argv:
        n = noise()
        n.prepare()
    if "-n2" in sys.argv or "--parse" in sys.argv:
        n = noise()
        n.parse(os.path.abspath(os.getcwd())+"/input/test", "poc")
    if "-a" in sys.argv:
        a = Analysis()
        a.analysis()
    if "--clean" in sys.argv:
        clean()
    if "-t" in sys.argv: 
        test()  
    if "--one" in sys.argv:
        for i in range(len(sys.argv)-1):
            if sys.argv[i] == "--one":
                parse_one_obj(sys.argv[i+1])
    if "--all" in sys.argv:
        parse_all_obj()
    if "-cuao" in sys.argv or "--check_useful_alloc_obj" in sys.argv:
        for i in range(len(sys.argv)-1):
            if sys.argv[i] == "-cuao" or sys.argv[i] == "--check_useful_alloc_obj":
                check_useful_alloc_obj(sys.argv[i+1])
    if "-cufo" in sys.argv or "--check_useful_free_obj" in sys.argv:
        for i in range(len(sys.argv)-1):
            if sys.argv[i] == "-cufo" or sys.argv[i] == "--check_useful_free_obj":
                check_useful_free_obj(sys.argv[i+1])

    
import time

if __name__ == "__main__":
    sec1 = time.time()

    main()

    sec2 = time.time()
    print(f"use time : {sec2-sec1} seconds")
