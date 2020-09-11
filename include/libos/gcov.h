#ifndef _LIBOS_GCOV_H
#define _LIBOS_GCOV_H

#include <libos/libc.h>
#include <stdio.h>

int gcov_init_libc(libc_t* libc, FILE* stderr_stream);

#endif /* _LIBOS_GCOV_H */
