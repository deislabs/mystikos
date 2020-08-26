#ifndef _LIBOS_SETJMP_H
#define _LIBOS_SETJMP_H

#include <libos/types.h>

typedef struct libos_jmpbuf
{
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rip;
    uint64_t rbx;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
} libos_jmpbuf_t;

__attribute__((returns_twice))
int libos_setjmp(libos_jmpbuf_t* env);

void libos_longjmp(libos_jmpbuf_t* env, int val);

#endif /* _LIBOS_SETJMP_H */
