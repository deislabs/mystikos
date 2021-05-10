// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_MMAN2_H
#define _MYST_MMAN2_H

#include <stddef.h>
#include <sys/types.h>

int myst_mman2_init(void* data, size_t size);

void myst_mman2_release(void);

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

size_t myst_mman2_get_usable_size(void);

size_t myst_mman2_count_free_bits(void);

size_t myst_mman2_count_used_bits(void);

#endif /* _MYST_MMAN2_H */
