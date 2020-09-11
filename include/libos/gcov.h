#ifndef _LIBOS_GCOV_H
#define _LIBOS_GCOV_H

#include <libos/libc.h>
#include <stdio.h>

void gcov_set_stderr(FILE* stream);

void gcov_set_libc(libc_t* libc);

#endif /* _LIBOS_GCOV_H */
