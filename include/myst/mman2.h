// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_MMAN2_H
#define _MYST_MMAN2_H

#include <stddef.h>
#include <sys/types.h>

int myst_mman2_init(void* data, size_t size);

int myst_mman2_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset,
    void** ptr);

int myst_mman2_munmap(void* addr, size_t length);

void* myst_mman2_mremap(
    void* old_address,
    size_t old_size,
    size_t new_size,
    int flags,
    void* new_address);

int myst_mman2_mprotect(void* addr, size_t len, int prot);

#endif /* _MYST_MMAN2_H */
