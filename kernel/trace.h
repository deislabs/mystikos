#ifndef _LIBOS_TRACE_H
#define _LIBOS_TRACE_H

#include <stdio.h>

#define TRACE printf("TRACE: %s(%u): %s\n", __FILE__, __LINE__, __FUNCTION__)

#endif /* _LIBOS_TRACE_H */
