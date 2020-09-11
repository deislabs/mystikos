#ifndef _LIBOS_OPTIONS_H
#define _LIBOS_OPTIONS_H

#include <stdbool.h>

bool libos_get_real_syscalls(void);

void libos_set_real_syscalls(bool flag);

bool libos_get_export_rootfs(void);

void libos_set_export_rootfs(bool flag);

#endif /* _LIBOS_OPTIONS_H */
