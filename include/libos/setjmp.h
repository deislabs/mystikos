#ifndef _LIBOS_SETJMP_H
#define _LIBOS_SETJMP_H

#include <libos/types.h>

typedef struct libos_jmp_buf
{
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rip;
    uint64_t rbx;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
} libos_jmp_buf_t;

__attribute__((returns_twice))
int libos_setjmp(libos_jmp_buf_t* env);

void libos_longjmp(libos_jmp_buf_t* env, int val);

void libos_jump(libos_jmp_buf_t* env);

#endif /* _LIBOS_SETJMP_H */
