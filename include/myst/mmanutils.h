// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_MMANUTILS_H
#define _MYST_MMANUTILS_H

#include <myst/buf.h>
#include <myst/fs.h>
#include <myst/list.h>
#include <myst/mman.h>
#include <myst/refstr.h>
#include <sys/mman.h>
#include <sys/types.h>

#define MYST_FDMAPPING_USED 0x1ca0597f

typedef struct mman_file_handle
{
    myst_list_node_t base;
    myst_fs_t* fs;
    myst_file_t* file;
    ino_t inode;
    int npages; // # of pages sharing this mapping
} mman_file_handle_t;

/*
defines a file-page to memory-page mapping
The mapping entries in the fdmappings vector are populated at mmap, and cleaned
up at munmap.
*/
typedef struct myst_fdmapping
{
    uint32_t used;   /* whether entry is used */
    uint64_t offset; /* offset of page within backing file */
    size_t filesz;   /* size of file at mmap() time */
    mman_file_handle_t* mman_file_handle;
} myst_fdmapping_t;

int myst_setup_mman(void* data, size_t size);

int myst_teardown_mman(void);

long myst_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset);

int myst_munmap(void* addr, size_t length);

int myst_munmap_and_pids_clear_atomic(void* addr, size_t length);

long myst_syscall_brk(void* addr);

void* myst_mremap(
    void* old_address,
    size_t old_size,
    size_t new_size,
    int flags,
    void* new_address);

int myst_mprotect(const void* addr, const size_t len, const int prot);

int myst_get_total_ram(size_t* size);

int myst_get_free_ram(size_t* size);

int myst_release_process_mappings(pid_t pid);

int myst_msync(void* addr, size_t length, int flags);

typedef struct myst_mman_stats
{
    size_t brk_size;
    size_t map_size;
    size_t free_size;
    size_t used_size;
    size_t total_size;
} myst_mman_stats_t;

void myst_mman_stats(myst_mman_stats_t* buf);

int proc_pid_maps_vcallback(
    myst_file_t* self,
    myst_buf_t* vbuf,
    const char* entrypath);

/* marks all pages in the mapping as owned by the given process */
int myst_mman_pids_set(const void* addr, size_t length, pid_t pid);

/* return the length in bytes that are owned by the given process */
ssize_t myst_mman_pids_test(const void* addr, size_t length, pid_t pid);

bool myst_is_bad_addr(const void* addr, size_t size, int prot);

#define myst_is_bad_addr_read(addr, size) \
    (myst_is_bad_addr(addr, size, PROT_READ))

#define myst_is_bad_addr_write(addr, size) \
    (myst_is_bad_addr(addr, size, PROT_WRITE))

#define myst_is_bad_addr_read_write(addr, size) \
    (myst_is_bad_addr(addr, size, PROT_READ | PROT_WRITE))

typedef enum
{
    NONE,
    PRIVATE,
    SHARED
} map_type_t;

/* checks if process owns memory range [addr,addr+length). By default checks
 * both private and shared mappings. Can be configured to just check private
 * mappings with `private_only` flag. */
map_type_t myst_process_owns_mem_range(
    const void* addr,
    size_t length,
    bool private_only);

void myst_mman_lock(void);

void myst_mman_unlock(void);

bool mman_file_handle_eq(mman_file_handle_t* f1, mman_file_handle_t* f2);

long myst_mman_file_handle_get(int fd, mman_file_handle_t** file_handle_out);

void myst_mman_file_handle_put(mman_file_handle_t* file_handle);

size_t myst_mman_backing_file_size(mman_file_handle_t* file_handle);

const char* myst_mman_prot_to_string(int prot);
const char* myst_mman_flags_to_string(int flags);

/* return 0 if all memory in this range has the given protection */
int myst_maccess(const void* addr, size_t length, int prot);

#endif /* _MYST_MMANUTILS_H */
