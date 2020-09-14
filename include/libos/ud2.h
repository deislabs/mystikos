#ifndef _LIBOS_UD2_H
#define _LIBOS_UD2_H

#include <libos/defs.h>

/* force undefined instruction crash */
LIBOS_INLINE void libos_ud2(void)
{
    __asm__ volatile("ud2" ::);
}

#endif /* _LIBOS_UD2_H */
