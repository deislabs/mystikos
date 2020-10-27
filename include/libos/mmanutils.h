#ifndef _LIBOS_MMANUTILS_H
#define _LIBOS_MMANUTILS_H

#include <libos/mman.h>
#include <sys/types.h>

int libos_setup_mman(void* data, size_t size);

int libos_teardown_mman(void);

void* libos_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset);

int libos_munmap(void* addr, size_t length);

long libos_syscall_brk(void* addr);

void* libos_mremap(
    void* old_address,
    size_t old_size,
    size_t new_size,
    int flags,
    void* new_address);

int libos_get_total_ram(size_t* size);

int libos_get_free_ram(size_t* size);

#endif /* _LIBOS_MMANUTILS_H */
