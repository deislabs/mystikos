// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_POSIXSHMMAN_H
#define _MYST_POSIXSHMMAN_H

#include <myst/buf.h>
#include <myst/fs.h>
#include <myst/mmanutils.h>

int shmfs_setup();

int shmfs_teardown();

typedef struct shared_mapping shared_mapping_t;

bool myst_is_posix_shm_file_handle(int fd, int flags);

bool myst_is_address_within_shmem(
    const void* addr,
    const size_t len,
    shared_mapping_t** sm_out);

/* register regular file or anonymous MAP_SHARED mapping */
int myst_shmem_register_mapping(
    int fd,
    void* addr,
    size_t length,
    size_t offset);

long myst_posix_shm_handle_mmap(
    int fd,
    void* addr,
    size_t length,
    off_t offset,
    int flags);

int myst_shmem_handle_munmap(void* addr, size_t length, bool* is_shmem);

int myst_shmem_handle_release_mappings(pid_t pid);

int myst_shmem_share_mappings(pid_t childpid);

bool myst_shmem_can_mremap(
    shared_mapping_t* sm,
    void* old_addr,
    size_t old_size);

void myst_shmem_mremap_update(
    shared_mapping_t* sm,
    void* new_addr,
    size_t new_size);

bool myst_shmem_can_mprotect(shared_mapping_t* sm, void* addr, size_t length);

/*
Return value:
0 - if no shared memory region corresponding to entire range.
1 - if shared memory region found without partial overlap.
<0 - if shared memory region found but with partial overlap.
*/
int myst_addr_within_process_owned_shmem(
    const void* addr,
    const size_t length,
    pid_t pid,
    shared_mapping_t** sm_out);

#endif /* _MYST_POSIXSHMMAN_H */
