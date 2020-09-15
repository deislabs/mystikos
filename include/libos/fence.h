#ifndef _LIBOS_FENCE_H
#define _LIBOS_FENCE_H

#include <libos/types.h>

#define libos_fence() __builtin_ia32_lfence()

#endif /* _LIBOS_FENCE_H */
