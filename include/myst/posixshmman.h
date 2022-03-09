// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_POSIXSHMMAN_H
#define _MYST_POSIXSHMMAN_H

#include <myst/buf.h>
#include <myst/fs.h>
#include <myst/mmanutils.h>

int shmfs_setup();

int shmfs_teardown();

bool myst_is_posix_shm_file_handle(int fd, int flags);

bool myst_is_address_within_shmem(const void* addr, const size_t len);

int myst_shmem_register_mapping(int fd, void* addr, size_t length);

long myst_posix_shm_handle_mmap(
    int fd,
    void* addr,
    size_t length,
    off_t offset,
    int flags);

int myst_shmem_handle_munmap(void* addr, size_t length, bool* is_shmem);

int myst_posix_shm_handle_release_mappings(pid_t pid);

int myst_posix_shm_share_mappings(pid_t childpid);

long myst_mman_file_handle_get(int fd, mman_file_handle_t** file_handle_out);

void myst_mman_file_handle_put(mman_file_handle_t* file_handle);

#endif /* _MYST_POSIXSHMMAN_H */
