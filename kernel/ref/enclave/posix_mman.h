#ifndef _POSIX_MMAN_H
#define _POSIX_MMAN_H

#include <sys/mman.h>
#include <stddef.h>

void* posix_brk(void* new_brk);

int posix_mprotect(void* addr, size_t len, int prot);

#endif /* _POSIX_MMAN_H */
