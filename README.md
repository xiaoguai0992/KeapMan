# KeapMan

## Description

This is the repository of "KeapMan: Facilitating Automatic Heap Layout Manipulation for Linux Kernel Exploits by Planned Adaptive Tuning".

## Project Structure

```shell
├── Dockerfile
├── env
├── examples
│   ├── CVE-2021-42008_ELOISE
│   ├── dataset_obj
│   ├── objmeasure
├── layout_manip
├── prim_extract
└── README.md
```

## Environment Setup

We provide a dockerfile to setup an environment for this artifact.

```shell
docker build . -t keapman
docker run -it --name keapmanc
```

In the container, 

1. create a directory and put the code in it.

```shell
# in container
mkdir /work
```

```shell
# on host
docker cp <path_to_your_cloned_KeapMan> keapmanc:/work/
```

2. prepare the folders, sources, and filesystem images.

```shell
# in container
mkdir -p /work/files
cd /work/files

# download linux source, checkout to the version you need, and prepare your .config
git clone https://github.com/torvalds/linux.git
git reset --hard 8357f6fb3d9a02ac55f0d758b9c79b4647c18bcb # for example

# create working directories
mkdir linux-bc
mkdir workspace

# setup environment variables, if needed, change the path in it on your own
source /work/KeapMan/env

# generate syscall_defs.json
python3 /work/KeapMan/prim_extract/extract_syscall_defs.py

# build filesystem image
# we follow the guidance from Syzkaller to build an image
# and reset its root password as 'root' for convenience of automation

# compile your kernel into binary
cd /work/files/linux
make -j32

# compile your kernel into bc
# we recommond to use wllvm
# and provide a script KeapMan/prim_extract/static_analysis/get_bc.py to extract the bitcode files
```

3. Set your LLM api key in KeapMan/prim\_extract/agent.py

```python
API_URL = ''
API_KEY = ''
MODEL = ''
```

4. copy your compiled bzImage and vmlinux into the following directory
```shell
/work/KeapMan/examples/CVE-2021-42008_ELOISE/input/ # both bzImage and vmlinux
/work/KeapMan/examples/CVE-2021-42008_ELOISE/sym/   # only vmlinux
/work/KeapMan/examples/objmeasure/input/            # both bzImage and vmlinux
/work/KeapMan/examples/objmeasure/sym/              # only vmlinux
```

## Primitive Extraction

### Dataset Format

Each obj that needs to be extracted should contain：

1. repro.c: A C POC conforming to the Syzkaller generation format, containing the allocation and deallocation operations for the target object. If manually constructed, ensure the program is linear (without loops) and modify system calls to the form syscall(__NR_open, ...).

2. commit: The kernel version (commit ID) corresponding to this repro.c file.

3. config: The kernel configuration corresponding to this repro.c file.

4. extapi.c: This file models the syscalls required for the allocation/deallocation of this object, used to handle memory side effects during static analysis. For example, if one syscall writes a value to user memory, and another syscall needs to use that value, this modeling is needed to analyze the dependency between the two syscalls.

5. sites.json: format as follow:

   ```json
   {
       "alloc": "security/selinux/xfrm.c:92 selinux_xfrm_alloc_user",
       "free": "security/selinux/xfrm.c:130 selinux_xfrm_state_free"
   }
   ```

   Here, "alloc" represents the allocation point of the object. The first part is the source file path and line number, and the second part is the function name (it must be the function name on the binary image; functions in the code may disappear in the binary image due to inlining).

### Usage

1. Configure case_id in config.py (usually you can use the type name of obj).

2. Running `python3 step1_prepare.py` will create a folder named `case_id` in the path corresponding to the workspace in the configuration file, which will serve as the working directory. It will also perform some pre-analysis.

    ```shell
    python3 step1_prepare.py # in /work/KeapMan/prim_extract
    ```

3. Run python3 step2_gen_sa.py <syscall_num>. The system will generate an alloc primitive consisting of syscall_num syscalls, and the alloc primitives preceding it, located in the file primitive_sa_remap.json in the working directory, identified by line numbers.

    ```shell
    python3 step2_gen_sa.py 1 # in /work/KeapMan/prim_extract
    ```

4. Run `python3 agent.py sa <case_id>` to allow the large model to automatically encapsulate the `setup` and `alloc` functions and parameters based on the line numbers in `primitive_sa_remap.json`. After completion, check `primitive_sa.h` in the working directory. If it is not pure code, delete the non-code parts (such as markdown symbols). Later, the LLM output can be stabilized by improving the prompt words, but for now, do it manually.

    ```shell
    python3 agent.py sa pipe_buffer # in /work/KeapMan/prim_extract
    ```

5. Run `python3 agent.py gensa <case_id>` to allow the large model to automatically generate a C POC that calls `setup` once and `alloc` ten times based on the contents of `primitive_sa.h`. This POC will be used for subsequent testing of the primitives' correctness.

    ```shell
    python3 agent.py gensa pipe_buffer # in /work/KeapMan/prim_extract
    ```

    After this step, you may need to manually make some minor adjustments to the code generated by the large model to ensure that it can be compiled correctly.(/path/to/your/workspace/pipe_buffer/primitive_sa.h)

6. Run `python3 step3_test_sa.py`. The system will automatically test the number of times the current primitive is assigned. If the number of primitive assignments is proportional to the number of times it is called, it means that the primitive partitioning is correct (the current experiment is relatively simple, just checking whether the numbers are equal, which can be improved).

    ```shell
    python3 step3_test_sa.py # in /work/KeapMan/prim_extract
    ```

7. If the primitives are not partitioned correctly, return to step 3, increase syscall_num and try partitioning the primitives again. Generally, syscall_num is initially set to 1, and then each syscall is added up one by one. Repeat steps until the correct allocation primitives are obtained.

8. After successfully extracting the allocation primitives, run `python3 step4_gen_spaf.py <syscall_num>`, where `syscall_num` refers to the number of syscalls that the free primitives need to include. Similar to the allocation primitives, the analysis results of the free primitives are in `primitive_spaf_remap.json`.

    ```shell
    python3 step4_gen_spaf.py 2 # in /work/KeapMan/prim_extract
    ```

9. Similar to 3-7, running `python3 agent.py spaf <case_id>` allows the large model to split the setup, prepare, allocate, and free primitives. Then, it checks the code format of `primitive_spaf.h` for correctness. Next, it runs `python3 agent.py genspaf <case_id>` to generate the PoC for the number of tests. Finally, it runs `python3 step5_test_spaf.py` to check if the primitives are correct, i.e., whether the number of frees equals the number of allocations. If this fails, it returns to step h, increasing `syscall_num` until the correct free primitive is generated.

    ```shell
    python3 agent.py spaf pipe_buffer # in /work/KeapMan/prim_extract
    ```

## Layout Manipulation

### Setup

To run this tool, you need to have the dynamic taint analysis tool PANDA and its Python package installed beforehand.
https://github.com/panda-re/panda

To solve your own case, you need to copy the input and sym directories in the examples (examples/work) directory to your working directory.
And put the compiled kernel bzImage and vmlinux into the input directory.

Please refer to the fengshui.py file for specific input format.

### Format the PoC

Put your original PoC into the input directory, where you need to define two functions, begin() and end().
The code between begin() and end() is regarded as where the layout manipulation will execute.
Also pay attention to the compile.sh file in the input directory and modify the corresponding compilation commands to suit your PoC.

By default, memory operation sequences are measured in the granularity of syscall.
To measure a primitive with multiple syscalls, you can define two functions, prim_in and prim_out, in your POC to mark the entry and exit of the primitive:

```c
void prim_in(){
    ;
}
void prim_out(){
    ;
}
int main(){
    // ...
    begin();
    prim_in();
    // your primitive ...
    prim_out();
    end();
}
```

### Primitive Capability Measurement

Enter your working directory and run the following command: (you can test in )

```shell
python3 $KEAPMAN_PATH/layout_manip/noise.py -p -n1 -n2
```

### Primitive Sequence Solving

Run the following command in your workdir.

```shell
python3 $KEAPMAN_PATH/layout_manip/fengshui.py
```

### Running Example 

We take the ELOISE method of CVE-2021-42008 as an example. You can run the following command to test the effect:

```shell
# run in CVE-2021-42008_ELOISE

# measure primitive capability
python3 $KEAPMAN_PATH/layout_manip/noise.py -p -n2

# solving primitive sequence
python3 $KEAPMAN_PATH/layout_manip/fengshui.py
```

The final output might look like this:
```C
free_slot_kmalloc-4k(-1)
free_slot_kmalloc-4k(0)
syscall_0
alloc_slot_kmalloc-32(-1)
free_slot_kmalloc-32(0)
free_slot_kmalloc-4k(1)
syscall_1
free_slot_kmalloc-32(1)
syscall_2
```

Where syscall_i can represent either a syscall or a primitive you define yourself.
Numbers greater than or equal to 0 represent the relative positions within the slabs of each cache.
While -1 represents selecting an additional chunk for the noise.

Note: If you find that your terminal loses its echo after running some code, you can use the "reset" command to restore it.
