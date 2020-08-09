#ifndef _POSIX_TRACE_H
#define _POSIX_TRACE_H

#include "posix_io.h"

#define TRACE \
    do \
    { \
        posix_printf("TRACE: %s(%u): %s()\n", \
            __FILE__, __LINE__, __FUNCTION__); \
    } \
    while (0)

void posix_print_backtrace(void);

void posix_set_trace(uint32_t value);

#endif /* _POSIX_TRACE_H */
