#ifndef _LIBOS_FSGS_H
#define _LIBOS_FSGS_H

#include <libos/types.h>

const void* libos_get_fs(void);

void libos_set_fs(const void* p);

const void* libos_get_gs(void);

void libos_set_gs(const void* p);

#endif /* _LIBOS_FSGS_H */
