from noise import *
from order import *

class ParseExp:
    def __init__(self, obj_reqs, loc_reqs):
        self.obj_reqs = obj_reqs
        self.loc_reqs = loc_reqs
    def load_exp_info(self):
        p = prepare()
        p.snap()
        n = noise()
        n.parse("./input/test", "poc")
        #print(n.log_for_goal_objs)
        #print(n.log_for_all_obj)
        #print(n.res)
        # Cut logic
        result = []
        index = 0
        for group in n.full_res:
            count = len(group)
            sliced = n.log_for_all_obj[index:index + count]
            result.append(sliced)
            index += count
        self.exp_info = result
    def get_slab(self, address:str, cache:str)->int:
        address = int(address, 16)
        slab_pages = {
            "kmalloc-8":1,
            "kmalloc-16":1,
            "kmalloc-32":1,
            "kmalloc-64":1,
            "kmalloc-96":1,
            "kmalloc-128":1,
            "kmalloc-192":1,
            "kmalloc-256":1,
            "kmalloc-512":1,
            "kmalloc-1k":2,
            "kmalloc-2k":4,
            "kmalloc-4k":8
        }
        if cache not in slab_pages:
            return 0
        a = slab_pages[cache] * 0x1000 - 1
        a = ~a
        res = address & a
        print(f"address:{address:x}, cache {cache}, slab : {res:x}")
        return res

    def parse_location(self):
        self.use_caches = {}
        pattern = re.compile(r"(adjacent|overlap)\((\d+),\s*(\d+)\)")
        for constraint in self.loc_reqs:
            match = pattern.match(constraint)
            if match:
                relation, x, y = match.groups()
                x = int(x)
                y = int(y)
                _, cache1, sys_idx1, obj_idx1 = self.obj_reqs[x].split("@")
                _, cache2, sys_idx2, obj_idx2 = self.obj_reqs[y].split("@")
                sys_idx1 = int(sys_idx1)
                obj_idx1 = int(obj_idx1)
                sys_idx2 = int(sys_idx2)
                obj_idx2 = int(obj_idx2)
                if "--by_cahce" in sys.argv or "-bc" in sys.argv:
                    prim1 = self.get_prim_by_cache(cache1, sys_idx1, obj_idx1)
                    prim2 = self.get_prim_by_cache(cache2, sys_idx2, obj_idx2)
                else:
                    prim1 = self.exp_info[sys_idx1][obj_idx1]
                    prim2 = self.exp_info[sys_idx2][obj_idx2]
                op1, cache1, address1, _ = prim1.split("@")
                op2, cache2, address2, _ = prim2.split("@")
                if cache1 != cache2:
                    raise ValueError(f"{cache1} not same as {cache2}")
                    return NULL
                if cache1 not in self.use_caches:
                    self.use_caches[cache1] = [constraint]
                else:
                    self.use_caches[cache1].append(constraint)
            else:
                raise ValueError(f"Invalid constraint format: {constraint}")
        order_solver = ConstraintSolver()
        self.addr_map = {}
        self.obj_locations = {}
        slabs = {}
        for cache, reqs in self.use_caches.items():
            #print(f"{cache} -> {reqs}")
            positions = order_solver.parse_constraints(reqs)
            for objidx, loc in positions.items():
                self.obj_locations[objidx] = f"{cache}@{str(loc)}"
                _, cache_name, sys_idx, obj_idx = self.obj_reqs[objidx].split("@")
                sys_idx = int(sys_idx)
                obj_idx = int(obj_idx)
                if "--by_cahce" in sys.argv or "-bc" in sys.argv:
                    prim = self.get_prim_by_cache(cache_name, sys_idx, obj_idx)
                else:
                    prim = self.exp_info[sys_idx][obj_idx]
                _, _, address, _ = prim.split("@")
                self.addr_map[f"{sys_idx}@{address}"] = f"{cache}@{str(loc)}"
                slabs[self.get_slab(address, cache)] = 1
                #print(f"{sys_idx}@{address} -> {cache}@{str(loc)}")
        for syscall in self.exp_info:
            for opcode in syscall:
                op, cache, address, _ = opcode.split("@")
                if op == 'a':
                    slabs[self.get_slab(address, cache)] = 1
        sys_idx = -1
        for syscall in self.exp_info:
            sys_idx += 1
            for opcode in syscall:
                op, cache, address, _ = opcode.split("@")
                if f"{sys_idx}@{address}" in self.addr_map:
                    continue
                if op == 'a':
                    self.addr_map[f"{sys_idx}@{address}"] = f"{cache}@-1" 
                else: # op is f
                    # f"{sys_idx}@{address}" must not in self.addr_map 
                    if self.get_slab(address, cache) in slabs:
                        self.addr_map[f"{sys_idx}@{address}"] = f"{cache}@-1"
                    else:
                        self.addr_map[f"{sys_idx}@{address}"] = f"{cache}@-2"
        #print(self.obj_locations)
        #print(self.addr_map)
        #pause()
    def get_prim_by_cache(self, cache:str, sys_idx:int, obj_idx:int)->str:
        idx = -1
        for prim in self.exp_info[sys_idx]:
            _, cache_name, _, _ = prim.split("@")
            if cache_name == cache:
                idx += 1
                if idx == obj_idx:
                    return prim
        print(f"{cache}, {sys_idx}, {obj_idx}, {self.exp_info[sys_idx]}")
    def extract_result(self):
        #print(self.exp_info)
        #print(self.addr_map)
        self.result = []
        syscall_idx = -1
        for syscall in self.exp_info:
            one_result = []
            syscall_idx += 1
            for opcode in syscall:
                op, cache, address, _ = opcode.split("@")
                addr = self.addr_map[f"{syscall_idx}@{address}"]
                addridx = addr.split("@")[1]
                one_result.append(f"{op}@{cache}@{addridx}")
            self.result.append(one_result)
        #print(self.result)
        for syscall in self.result:
            print(syscall)
            print('')
            
    def main(self):
        self.load_exp_info()
        for x in self.exp_info:
            print('='*60)
            print(x)
        self.parse_location()
        self.extract_result()
    

from collections import defaultdict, deque

def cancel_f_a_ops(syscall_ops):
    cache_ops = defaultdict(list)

    # Step 1: Group by cache
    for op in syscall_ops:
        action, cache, addr = op.split('@')
        cache_ops[cache].append((action, addr))

    result = {}
    
    # Step 2: Perform a cache elimination operation on each cache.
    for cache, ops in cache_ops.items():
        free_queue = deque()
        final_ops = []

        for action, addr in ops:
            #print("cache :", cache, "ops ->", ops)
            if addr == '-2':
                continue
            if action == 'f':
                free_queue.append((action, addr))
            elif action == 'a':
                if free_queue:
                    # eliminate one f
                    free_queue.pop()
                else:
                    final_ops.append((action, addr))
        
        # The remaining f that could not be eliminated are added to the result.
        final_ops =  final_ops + list(free_queue)

        # Formatting restored to string
        result[cache] = [f'{action}@{cache}@{addr}' for action, addr in final_ops]

    return result
    
if __name__ == '__main__':
    obj_reqs = [
        "watch_filter@96@0@2",
    ]
    loc_reqs = [
        "overlap(0, 0)",
    ]
    #pe = ParseExp(obj_reqs, loc_reqs)
    
    #pe.main()
    

    
