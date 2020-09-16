#ifndef _LIBOS_FSGS_H
#define _LIBOS_FSGS_H

#include <libos/types.h>

void* libos_get_fsbase(void);

void libos_set_fsbase(void* p);

void* libos_get_gsbase(void);

void libos_set_gsbase(void* p);

#endif /* _LIBOS_FSGS_H */
