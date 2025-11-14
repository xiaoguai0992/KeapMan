from noise import *
import sys
import json
import os

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("missing dirpath")
        exit()
    dirpath = sys.argv[1]
    if os.path.exists(dirpath) == False:
        print(f"bad dirpath {dirpath}")
        exit()
    print(f"dirpath is {dirpath}")
    f = open(dirpath+"/free_config.json", "r")
    free_config = json.loads(f.read())
    if os.path.exists(free_config['testcase']) == False:
        print(f"bad testcase_path {free_config['testcase']}")
        exit()
    f = open(dirpath+"/alloc_times.json")
    alloc_times_info = json.loads(f.read())
    goal_alloc_op_nums = alloc_times_info['goal_alloc_op_nums']
    alloc_op_nums = alloc_times_info['alloc_op_nums']
    free_times = check_useful_free(free_config['goal_addrs'], goal_alloc_op_nums, alloc_op_nums, free_config['testcase'])
    res = {}
    res['times'] = free_times
    f = open(dirpath+"/free_times.json", "w")
    f.write(json.dumps(res))
