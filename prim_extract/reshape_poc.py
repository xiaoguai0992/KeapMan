import os
import re
import sys
import json
import copy

from config import Config

vname_id = 0
def new_vname():
    global vname_id
    vname_id += 1
    return 'ptr'+str(vname_id)

involved_syscall = set()

with open(os.path.join(Config.workspace_dir, 'syscall_decl.json'), 'r') as f:
    syscall_decl = json.load(f)

def syscall_def_replacer(match):
    global involved_syscall
    syscall_name = match.group(1)
    involved_syscall.add(syscall_name)
    return f'syscall_{syscall_name}('

def reshape(src_lines):
    # parse allocated mem regions
    allocated_range = []
    line_mapping = [0] * (len(src_lines) + 1)
    for i in range(len(line_mapping)):
        line_mapping[i] = i

    for i, line in enumerate(src_lines):
        line = line.strip()
        if line.startswith('syscall(__NR_mmap'):
            line = line.replace('syscall(', ',')
            line = line.replace(')', ',')
            line = line.split(',')
            line = [l.strip() for l in line if l.strip() != '']

            digits = re.match(r'0x[0-9a-fA-F]+', line[1]).group()
            start_addr = int(digits, 16)
            digits = re.match(r'0x[0-9a-fA-F]+', line[2]).group()
            length = int(digits, 16)
            vname = new_vname()
            allocated_range.append((start_addr, start_addr+length, vname, i))
            continue
        matches = re.findall(r'0x[0-9a-fA-F]+(?:[uU]?[lL]{0,2}|[lL]{1,2}[uU]?)?', src_lines[i])
        for match in matches:
            digits = re.match(r'0x[0-9a-fA-F]+', match).group()
            value = int(digits, 16)
            for start, end, vname, _ in allocated_range:
                if value >= start and value < end:
                    offset = value - start
                    src_lines[i] = src_lines[i].replace(match, f'({vname}+{offset})')

    for start, __, vname, i in allocated_range:
        define = f'\tchar *{vname} = (char *){src_lines[i].strip()};\n'
        src_lines[i] = define

    added_variable = copy.deepcopy(src_lines)

    for i, line in enumerate(src_lines):
        pattern = r'syscall\s*\(\s*__NR_(\w+)\s*,'
        src_lines[i] = re.sub(pattern, syscall_def_replacer, src_lines[i])

    line_off = 0
    for syscall_name in involved_syscall:
        decl = syscall_decl[syscall_name]
        decl = 'extern ' + decl + ';\n'
        src_lines.insert(0, decl)
        line_off += 1

    for i in range(len(line_mapping)):
        line_mapping[i] += line_off

    return added_variable, src_lines, allocated_range, line_mapping

if __name__ == '__main__':
    if len(sys.argv) < 2:
        raise AttributeError("usage: python3 reshape.py <path_to_src.c>")
    c_path = sys.argv[1]
    c_dir, c_file = os.path.split(c_path)
    with open(c_path, 'r') as f:
        lines = f.readlines()
    variable_only, afterlines, memrange, line_mapping = reshape(lines)

    fname, ext = os.path.splitext(c_file)
    reshaped_file = fname + '.reshape' + ext
    with open(os.path.join(c_dir, reshaped_file), 'w') as f:
        f.writelines(afterlines)

    primitive_file = fname + '.prim' + ext
    with open(os.path.join(c_dir, primitive_file), 'w') as f:
        f.writelines(variable_only)

    with open(os.path.join(c_dir, 'reshape_info'), 'w') as f:
        for start, end, ptrname, _ in memrange:
            f.write(f'{start} {end} {ptrname}\n')

    with open(os.path.join(c_dir, 'reshape_mapping.txt'), 'w') as f:
        f.write(str(line_mapping))

