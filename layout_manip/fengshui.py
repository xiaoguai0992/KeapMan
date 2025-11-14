from order import *
from parse_exp import *

sizes = [8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096]

class heap_fengshui:
    def __init__(self):
        self.use_caches = {}
    def load_obj_info(self):
        pass
        '''
        primitive -> [xxx, xxx, xxx]
        primitive -> [xxx, xxx, xxx]
        '''
    def choice_spray_obj(self):
        pass
    def parse_input(self):
        pass
    def solve_one_syscall(self, syscall_ops:list):
        before = []
        end = []
        sys_ops = cancel_f_a_ops(syscall_ops)    
        for _, ops in sys_ops.items():
            for opcode in ops:
                #print(opcode)
                op, cache, addr = opcode.split("@")
                if cache not in self.use_caches:
                    continue
                if op == 'a':
                    before = [f"free_slot_{cache}({addr})"] + before
                if op == 'f':
                    if addr == '-2':
                        continue
                    else:
                        end = [f"alloc_slot_{cache}({addr})"] + end
        return before, end
    def fengshui(self, reqs:list):
        '''
        syscall [op@cache@addr, op@cache@addr],
        syscall [op@cache@addr, op@cache@addr],
        '''
        res = []
        sys_idx = 0
        for req in reqs:
            before, end = self.solve_one_syscall(req)
            res += before + [f"syscall_{sys_idx}"] + end
            sys_idx += 1
        
        return res
    def generate(self):
        '''
        
        '''
        pass
    def main(self):
        pass


         
if __name__ == '__main__':
    obj_reqs = [
        "net_device@4096@0@3",
        "msg_msg@4096@1@0",
        "msg_msgseg@32@1@1",
        "shm_file_data@32@2@0"

    ]
    loc_reqs = [ 
        "adjacent(0, 1)",
        "adjacent(2, 3)"
    ]
    '''
    obj_reqs = [
        "net_device@kmalloc-4k@0@0",
        "msg_msg@kmalloc-4k@1@0",
        "msg_msgseg@kmalloc-32@1@0",
        "shm_file_data@kmalloc-32@2@0"

    ]
    loc_reqs = [ 
        "adjacent(0, 1)",
        "adjacent(2, 3)"
    ]

    '''
    pe = ParseExp(obj_reqs, loc_reqs)
    pe.main()
    hf = heap_fengshui()
    hf.use_caches = pe.use_caches
    fengshui_res = hf.fengshui(pe.result)
    for x in fengshui_res:
        print(x)
