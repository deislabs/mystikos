#ifndef _OEL_RAMFS_H
#define _OEL_RAMFS_H

#include <oel/fs.h>
#include <stdbool.h>

int oel_init_ramfs(bool rdonly, oel_fs_t** fs_out);

#endif /* _OEL_RAMFS_H */
