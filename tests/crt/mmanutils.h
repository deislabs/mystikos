#ifndef _OEL_MMANUTILS_H
#define _OEL_MMANUTILS_H

#include <oel/mman.h>
#include <sys/types.h>

extern oel_mman_t g_oel_mman;

int oel_setup_mman(oel_mman_t* mman, size_t size);

int oel_teardown_mman(oel_mman_t* mman);

void* oel_mmap(
    void *addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset);

#endif /* _OEL_MMANUTILS_H */
