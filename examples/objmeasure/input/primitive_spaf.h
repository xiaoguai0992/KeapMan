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

struct SetupResult {
    intptr_t shm_id;
};

struct AllocResult {
    void *shm_addr;
};

struct SetupResult setup(void) {
    char *ptr1 = (char *)syscall(__NR_mmap, 0x1ffff000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
    char *ptr2 = (char *)syscall(__NR_mmap, 0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
    char *ptr3 = (char *)syscall(__NR_mmap, 0x21000000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
    intptr_t res = 0;
    res = syscall(__NR_shmget, 0ul, 0x2000ul, 0ul);
    struct SetupResult result = {.shm_id = res};
    return result;
}

struct SetupResult prepare(struct SetupResult setup_result) {
    return setup_result;
}

struct AllocResult alloc(struct SetupResult setup_result) {
    intptr_t res = 0;
    res = syscall(__NR_shmat, setup_result.shm_id, 0ul, 0ul);
    struct AllocResult result = {.shm_addr = (void *)res};
    return result;
}

void free_primitive(struct AllocResult alloc_result) {
    syscall(__NR_shmdt, alloc_result.shm_addr);
}

#endif // PRIMITIVE_H
