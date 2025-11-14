

#define _GNU_SOURCE

#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PRIMITIVE_H
#define PRIMITIVE_H

typedef struct {
    char *ptr1;
    char *ptr2;
    char *ptr3;
} setup_params;

setup_params setup() {
    char *ptr1 = (char *)syscall(__NR_mmap, 0x1ffff000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
    char *ptr2 = (char *)syscall(__NR_mmap, 0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
    char *ptr3 = (char *)syscall(__NR_mmap, 0x21000000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
    setup_params params = {ptr1, ptr2, ptr3};
    return params;
}

typedef struct {
    uint64_t r0;
    uint64_t r1;
} alloc_result;

alloc_result alloc(setup_params params) {
    intptr_t res = 0;
    res = syscall(__NR_pipe2, (params.ptr2 + 64), 0ul);
    alloc_result result;
    result.r0 = 0xffffffffffffffff;
    result.r1 = 0xffffffffffffffff;
    if (res != -1) {
        result.r0 = *(uint32_t*)(params.ptr2 + 64);
        result.r1 = *(uint32_t*)(params.ptr2 + 68);
    }
    syscall(__NR_fcntl, result.r0, 0x407ul, 9ul);
    return result;
}

#endif
