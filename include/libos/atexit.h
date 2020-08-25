#ifndef _LIBOS_ATEXIT_H
#define _LIBOS_ATEXIT_H

#include <libos/types.h>

int libos_atexit(void (*function)(void*), void* arg);

void libos_call_atexit_functions(void);

#endif /* _LIBOS_ATEXIT_H */
