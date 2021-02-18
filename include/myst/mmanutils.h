// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_MMANUTILS_H
#define _MYST_MMANUTILS_H

#include <myst/mman.h>
#include <sys/types.h>

int myst_setup_mman(void* data, size_t size);

int myst_teardown_mman(void);

void* myst_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset);

int myst_munmap(void* addr, size_t length);

long myst_syscall_brk(void* addr);

void* myst_mremap(
    void* old_address,
    size_t old_size,
    size_t new_size,
    int flags,
    void* new_address);

int myst_get_total_ram(size_t* size);

int myst_get_free_ram(size_t* size);

int myst_register_process_mapping(pid_t pid, void* addr, size_t size);

int myst_release_process_mappings(pid_t pid);

int myst_msync(void* addr, size_t length, int flags);

int myst_mman_close_notify(int fd);

#endif /* _MYST_MMANUTILS_H */
