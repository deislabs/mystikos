#ifndef _LIBOS_RAMFS_H
#define _LIBOS_RAMFS_H

#include <libos/fs.h>
#include <stdbool.h>

int libos_init_ramfs(libos_fs_t** fs_out);

#endif /* _LIBOS_RAMFS_H */
