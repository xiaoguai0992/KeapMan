import os
import sys
import json
from enum import Enum
from typing import Any, List, Literal, Optional, Union, Generator
from openai import OpenAI
from pydantic import BaseModel, Field

SYSTEM_PROMPT = '''
You are an advanced AI assistant with strong reasoning and comprehensive abilities to comprehend and generate C code of kernel vulnerability analysis for security research.

Identity and Purpose
- You are an exceptionally intelligent AI agent focused on extracting exploiting primitives.
- You have in-depth knowledge of reading and writing C code.
- You have three kinds of task to deal with, extract_primitive_sa, extract_primitive_spaf, generate_sa, generate_spaf. These tasks will be introduced later.

General Response Guidelines
- Answer Focus: Respond directly to user's question without adding extraneours information.
- Clarification: If the request is ambiguous or lacks necessary parameters for a tool invocation, immediately ask for clarification.
- Capability Limitation: If the query is not related to your task, politely indicate that you can only assist with exploit code analysis.
- Internal Reasoning: Use an optimized internal chain-of-thought for problem-solving, but do not reveal these internal steps to the user.
- Efficiency: Prioritize rapid and direct execution to minimize response delays.
- Do not include any local file paths/names in your response.
- Answer user questions in the designated format according to the task you execute.
- Do not contain any markdown macros in your reply, just clean code.
'''

# Names of global varibles should be obfuscated using eight random characters to avoid collisions.
TEMPLATE_PROMPT_EXTRACT_SA = '''
Task Definition and Response Format
In this task, the user will privide a C program having a main function, a set of setup code, a set of allocation code.
The setup code contains the C code (from the given C program) making up the setup primitive, which can be empty.
The allocation code contains the C code (from the given C program) making up the allocation primitive.
You need to pack the corresponding code into functions named "setup" and "alloc".
You should ignore other code in main function but not in setup and allocation code.
You need to recognize the parameters between "setup" and "alloc". Make sure the return of "alloc" contains sufficient information to perform "alloc".
If necessary, you can pack parameters into a structure.
Your functions should not introduce side-effects, which directly modifies the value in the parameter pointers.
In this case, you should design a new structure to save the changed memories, and return it for the next function input.
You need to put the "setup" and the "alloc" functions with their implementation into a seperate C header file named "primitive.h", with the definition of parameter structure (if have).
All included headers, other functions except "main", and global variables in the original C program should also be put in the "primitive.h".
You should remove the global variables and put them into parameters returned or taken by functions.
You should use #define marcos to prevent duplicated including of "primitive.h".

You need to perform this task.
C program is listed below:
{}
Setup code is listed below:
{}
Allocation code is listed below:
{}
'''

# Names of global varibles should be obfuscated using eight random characters to avoid collisions.
TEMPLATE_PROMPT_EXTRACT_SPAF = '''
Task Definition and Response Format
In this task, the user will privide a C program having a main function, a set of setup code, a set of prepare code, a set of alloc code, a set of dealloc code.
The setup code contains the C code (from the given C program) making up the setup primitive, which can be empty.
The prepare code contains the C code (from the given C program) making up the prepare primitive, which can be empty.
The allocation code contains the C code (from the given C program) making up the allocation primitive.
The dealloc code contains the C code (from the given C program) making up the dealloc primitive.
You need to pack the corresponding code into functions named "setup", "prepare", "alloc", and "dealloc".
You need to recognize the parameters between "setup" and "prepare". Make sure the return of "setup" contains sufficient information to perform "prepare".
You need to recognize the parameters between "setup" and "alloc". Make sure the return of "setup" contains sufficient information to perform "alloc".
You need to recognize the parameters between "setup" and "dealloc". Make sure the return of "setup" contains sufficient information to perform "dealloc".
You need to recognize the parameters between "prepare" and "alloc". Make sure the return of "prepare" contains sufficient information to perform "alloc".
You need to recognize the parameters between "prepare" and "dealloc". Make sure the return of "prepare" contains sufficient information to perform "dealloc".
You need to recognize the parameters between "alloc" and "dealloc". Make sure the return of "alloc" contains sufficient information to perform "dealloc".
If necessary, you can pack parameters into a structure.
You need to pay attention to the side effects mentioned in the comments.
Your functions should not introduce side-effects, which directly modifies the value in the parameter pointers.
In this case, you should design a new structure to save the changed memories, and return it for the next function input.
You need to put the "setup", "prepare", "alloc", and "dealloc" functions with their implementation into a seperate C header file named "primitive.h", with the definition of parameter structures (if have).
All included headers, other functions except "main", and global variables in the original C program should also be put in the "primitive.h".
You should remove the global variables and put them into parameters returned or taken by functions.
You should use #define marcos to prevent duplicated including of "primitive.h".

You need to perform this task.
C program is listed below:
{}
Setup code is listed below:
{}
Prepare code is listed below:
{}
Allocation code is listed below:
{}
Free code is listed below:
{}
'''

TEMPLATE_PROMPT_GEN_SA = '''
Task Definition: In this task, the user will provide you a C header file with two functions named setup and alloc, and a integer X.
You need to read this header file, and write a C main program file to include this header, that invokes the setup function for one time, and the alloc function for X times.
The parameter and return values of these functions should be properly assigned.
The template of the c file is listed below:
```c
#include "primitive_sa.h" // do not change this
void start()
{{
    // setup should be called here, you can modify the parameter and return value of the "start" function
}}
void begin()
{{
    for (int i = 0; i < X; i ++) {{
        // alloc should be called here
        // you need to properly save the return value of each time of alloc
        // you can modify the parameter and return type of the "begin" function
    }}
}}
void end()
{{
    // keep it empty.
}}
int main()
{{
    start();
    begin();
    end();
    return 0;
}}
```

Response Format: You should only response the C code of main.c WITHOUT any other information. This C code should meet the requirement of the task and can be compiled and run.

C header (primitive.h) is listed below:
{}
X is:
{}
'''

TEMPLATE_PROMPT_GEN_SPAF = '''
Task Definition: In this task, the user will provide you a C header file with four functions named setup, prepare, alloc, dealloc, and a integer X.
You need to read this header file, and write a C main program file to include this header, that invokes the setup function for one time, and the prepare, alloc, dealloc function for X times.
If some primitive is empty or not found, you can just leave a placeholder.
The parameter and return values of these functions should be properly assigned.
The template of the c file is listed below:
```c
#include "primitive_spaf.h" // do not change this
void start()
{{
    // setup should be called here, you can modify the parameter and return value of the "start" function
}}
void begin()
{{
    for (int i = 0; i < X; i ++) {{
        // prepare should be called here
        // you can modify the parameter and return type of the "begin" function
        // VERY IMPORTANT: you need to properly save the return value of each time of prepare seperately
    }}

    for (int i = 0; i < X; i ++) {{
        // alloc should be called here
        // you can modify the parameter and return type of the "begin" function
        // VERY IMPORTANT: you need to take arguments according to i
        // VERY IMPORTANT: you need to properly save the return value of each time of alloc separately
    }}

    for (int i = 0; i < X; i ++) {{
        // dealloc should be called here
        // you can modify the parameter and return type of the "begin" function
        // VERY IMPORTANT: you need to take arguments according to i
        // VERY IMPORTANT: you need to properly save the return value of each time of dealloc separately
    }}
}}
void end()
{{
    // keep it empty.
}}
int main()
{{
    start();
    begin();
    end();
    return 0;
}}
```

Response Format: You should only response the C code of main.c WITHOUT any other information. This C code should meet the requirement of the task and can be compiled and run.

C header (primitive.h) is listed below:
{}
X is:
{}
'''

class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"

ROLE_VALUES = tuple(role.value for role in Role)
ROLE_TYPE = Literal[ROLE_VALUES]  # type: ignore

class Message(BaseModel):
    role: ROLE_TYPE = Field(...)
    content: Optional[str] = Field(default=None)

    def to_dict(self) -> dict:
        message = {"role": self.role}
        if self.content is not None:
            message["content"] = self.content
        return message

    @classmethod
    def user_message(cls, content: str) -> "Message":
        return cls(role=Role.USER, content=content)

    @classmethod
    def system_message(cls, content: str) -> "Message":
        return cls(role=Role.SYSTEM, content=content)

class Agent:
    name = 'HeapLayoutPrimitiveExtratorAndCodeGen'
    version = '1.0.0'

    def __init__(self, model_name, url=None, api_key=None):
        self.client = OpenAI(base_url=url, api_key=api_key)
        self.model_name = model_name
        self.temperature = 0.2
        self.current_user_input = None
        self.system_msg = Message.system_message(SYSTEM_PROMPT)

    def get_response(self, user_input):
        print(self.system_msg.content)
        print(user_input.content)
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=[self.system_msg.to_dict(), user_input.to_dict()],
            max_tokens=8192,
            temperature=self.temperature
        )
        return response

    # extract setup and alloc primitives
    def extract_primitive_sa(self, c_prog, primitive, side_effects):
        setup_code = []
        for lineno in primitive['setup']:
            if str(lineno) in side_effects:
                setup_code.append(c_prog[lineno-1].replace('\n', '') + "//" + side_effects[str(lineno)] + "\n")
            else:
                setup_code.append(c_prog[lineno-1])
        if len(setup_code) > 0:
            setup_code = ''.join(setup_code)
        else:
            setup_code = '<empty>\n'

        alloc_code = []
        for lineno in primitive['alloc']:
            if str(lineno) in side_effects:
                alloc_code.append(c_prog[lineno-1].replace('\n', '') + "//" + side_effects[str(lineno)] + "\n")
            else:
                alloc_code.append(c_prog[lineno-1])
        alloc_code = ''.join(alloc_code)

        prompt = TEMPLATE_PROMPT_EXTRACT_SA.format(''.join(c_prog), setup_code, alloc_code)

        msg = Message.user_message(prompt)
        response = self.get_response(msg)
        content = response.choices[0].message.content
        return content

    # extract setup/prepare/alloc/free primitives
    def extract_primitive_spaf(self, c_prog, primitive, side_effects):
        setup_code = []
        for lineno in primitive['setup']:
            if str(lineno) in side_effects:
                setup_code.append(c_prog[lineno-1].replace('\n', '') + "//" + side_effects[str(lineno)] + "\n")
            else:
                setup_code.append(c_prog[lineno-1])
        if len(setup_code) > 0:
            setup_code = ''.join(setup_code)
        else:
            setup_code = '<empty>\n'

        prepare_code = []
        for lineno in primitive['prepare']:
            if str(lineno) in side_effects:
                prepare_code.append(c_prog[lineno-1].replace('\n', '') + "//" + side_effects[str(lineno)] + "\n")
            else:
                prepare_code.append(c_prog[lineno-1])
        if len(prepare_code) > 0:
            prepare_code = ''.join(prepare_code)
        else:
            prepare_code = '<empty>\n'

        alloc_code = []
        for lineno in primitive['alloc']:
            if str(lineno) in side_effects:
                alloc_code.append(c_prog[lineno-1].replace('\n', '') + "//" + side_effects[str(lineno)] + "\n")
            else:
                alloc_code.append(c_prog[lineno-1])
        alloc_code = ''.join(alloc_code)

        free_code = []
        for lineno in primitive['free']:
            if str(lineno) in side_effects:
                free_code.append(c_prog[lineno-1].replace('\n', '') + "//" + side_effects[str(lineno)] + "\n")
            else:
                free_code.append(c_prog[lineno-1])
        free_code = ''.join(free_code)

        prompt = TEMPLATE_PROMPT_EXTRACT_SPAF.format(''.join(c_prog), setup_code, prepare_code, alloc_code, free_code)

        msg = Message.user_message(prompt)
        response = self.get_response(msg)
        content = response.choices[0].message.content
        return content

    # extract setup and alloc primitives
    def gen_test_alloc(self, primitive_h, alloc_times):
        prompt = TEMPLATE_PROMPT_GEN_SA.format(primitive_h, alloc_times)
        msg = Message.user_message(prompt)
        response = self.get_response(msg)
        content = response.choices[0].message.content
        return content
    
    # extract setup and alloc primitives
    def gen_test_free(self, primitive_h, alloc_times):
        prompt = TEMPLATE_PROMPT_GEN_SPAF.format(primitive_h, alloc_times)
        msg = Message.user_message(prompt)
        response = self.get_response(msg)
        content = response.choices[0].message.content
        return content

API_URL = ''
API_KEY = ''
MODEL = ''

def generate_primitive_h_sa(c_prog_path, primitive_path, sideeffect_path):
    agent = Agent(MODEL, url=API_URL, api_key=API_KEY)
    with open(c_prog_path, 'r') as f:
        c_prog = f.readlines()
    with open(primitive_path, 'r') as f:
        primitive = json.load(f)
    with open(sideeffect_path, 'r') as f:
        sideeffect = json.load(f)
    res = agent.extract_primitive_sa(c_prog, primitive, sideeffect)
    print('-------------')
    print(res)
    return res

def generate_primitive_h_spaf(c_prog_path, primitive_path, sideeffect_path):
    agent = Agent(MODEL, url=API_URL, api_key=API_KEY)
    with open(c_prog_path, 'r') as f:
        c_prog = f.readlines()
    with open(primitive_path, 'r') as f:
        primitive = json.load(f)
    with open(sideeffect_path, 'r') as f:
        sideeffect = json.load(f)
    res = agent.extract_primitive_spaf(c_prog, primitive, sideeffect)
    print('-------------')
    print(res)
    return res

def generate_test_alloc_c(primitive_h_path, times=10):
    agent = Agent(MODEL, url=API_URL, api_key=API_KEY)
    with open(primitive_h_path, 'r') as f:
        primitive_h = f.read()
    res = agent.gen_test_alloc(primitive_h, times)
    print('-------------')
    print(res)
    return res

def generate_test_free_c(primitive_h_path, times=10):
    agent = Agent(MODEL, url=API_URL, api_key=API_KEY)
    with open(primitive_h_path, 'r') as f:
        primitive_h = f.read()
    res = agent.gen_test_free(primitive_h, times)
    print('-------------')
    print(res)
    return res

if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ['sa', 'spaf', 'gensa', 'genspaf']:
        print("Usage: python agent.py [sa|spaf|gensa|genspaf] <case_name>")
        sys.exit(1)
    mode = sys.argv[1]
    case_name = sys.argv[2]

    workspace_root_dir = os.getenv("WORKSPACE_ROOT_DIR")

    if mode == 'sa':
        primitive_path = os.path.join(workspace_root_dir, case_name, 'primitive_sa_remap.json')
        sideeffect_path = os.path.join(workspace_root_dir, case_name, 'side_effects.json')
        c_prog_path = os.path.join(workspace_root_dir, case_name, 'repro.prim.c')
        primitive_h = generate_primitive_h_sa(c_prog_path, primitive_path, sideeffect_path)
        with open(os.path.join(workspace_root_dir, case_name, 'primitive_sa.h'), 'w') as f:
            f.write(primitive_h)
    elif mode == 'spaf':
        primitive_path = os.path.join(workspace_root_dir, case_name, 'primitive_spaf_remap.json')
        sideeffect_path = os.path.join(workspace_root_dir, case_name, 'side_effects.json')
        c_prog_path = os.path.join(workspace_root_dir, case_name, 'repro.prim.c')
        primitive_h = generate_primitive_h_spaf(c_prog_path, primitive_path, sideeffect_path)
        with open(os.path.join(workspace_root_dir, case_name, 'primitive_spaf.h'), 'w') as f:
            f.write(primitive_h)
    elif mode == 'gensa':
        primitive_h_path = os.path.join(workspace_root_dir, case_name, 'primitive_sa.h')
        test_alloc_c = generate_test_alloc_c(primitive_h_path)
        with open(os.path.join(workspace_root_dir, case_name, 'test_alloc.c'), 'w') as f:
            f.write(test_alloc_c)
    elif mode == 'genspaf':
        primitive_h_path = os.path.join(workspace_root_dir, case_name, 'primitive_spaf.h')
        test_free_c = generate_test_free_c(primitive_h_path)
        with open(os.path.join(workspace_root_dir, case_name, 'test_free.c'), 'w') as f:
            f.write(test_free_c)
