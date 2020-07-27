#ifndef _OEL_MMANUTILS_H
#define _OEL_MMANUTILS_H

#include <oel/mman.h>
#include <sys/types.h>

int oel_setup_mman(size_t size);

int oel_teardown_mman(void);

void* oel_mmap(
    void *addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset);

#endif /* _OEL_MMANUTILS_H */
