#ifndef _LIBOS_TRACE_H
#define _LIBOS_TRACE_H

#include <libos/trace.h>
#include <stdbool.h>

void libos_set_trace(bool flag);

bool libos_get_trace(void);

#endif /* _LIBOS_TRACE_H */
