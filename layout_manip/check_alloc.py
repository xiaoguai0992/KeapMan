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
    f = open(dirpath+"/alloc_config.json", "r")
    alloc_config = json.loads(f.read())
    if os.path.exists(alloc_config['testcase']) == False:
        print(f"bad testcase_path {alloc_config['testcase']}")
        exit()
    #print(alloc_config)
    alloc_times, goal_alloc_op_nums, alloc_op_nums = check_useful_alloc(alloc_config['goal_addrs'], alloc_config['testcase'])
    res = {}
    res['times'] = alloc_times
    res['goal_alloc_op_nums'] = goal_alloc_op_nums
    res['alloc_op_nums'] = alloc_op_nums
    f = open(dirpath+"/alloc_times.json", "w")
    f.write(json.dumps(res))

