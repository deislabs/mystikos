#ifndef _LIBOS_FSBASE_H
#define _LIBOS_FSBASE_H

#include <libos/types.h>

const void* libos_get_fs_base(void);

void libos_set_fs_base(const void* p);

#endif /* _LIBOS_FSBASE_H */
