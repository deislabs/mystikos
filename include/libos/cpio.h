// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _LIBOS_CPIO_H
#define _LIBOS_CPIO_H

#include <libos/types.h>

/*
**==============================================================================
**
** To create a CPIO archive from the current directory on Linux:
**
**     $ find . | cpio --create --format='newc' > ../archive
**
** To unpack an archive on Linux:
**
**     $ cpio -i < ../archive
**
**==============================================================================
*/

#define LIBOS_CPIO_PATH_MAX 256

#define LIBOS_CPIO_FLAG_READ 0
#define LIBOS_CPIO_FLAG_CREATE 1

#define LIBOS_CPIO_MODE_IFMT 00170000
#define LIBOS_CPIO_MODE_IFSOCK 0140000
#define LIBOS_CPIO_MODE_IFLNK 0120000
#define LIBOS_CPIO_MODE_IFREG 0100000
#define LIBOS_CPIO_MODE_IFBLK 0060000
#define LIBOS_CPIO_MODE_IFDIR 0040000
#define LIBOS_CPIO_MODE_IFCHR 0020000
#define LIBOS_CPIO_MODE_IFIFO 0010000
#define LIBOS_CPIO_MODE_ISUID 0004000
#define LIBOS_CPIO_MODE_ISGID 0002000
#define LIBOS_CPIO_MODE_ISVTX 0001000

#define LIBOS_CPIO_MODE_IRWXU 00700
#define LIBOS_CPIO_MODE_IRUSR 00400
#define LIBOS_CPIO_MODE_IWUSR 00200
#define LIBOS_CPIO_MODE_IXUSR 00100

#define LIBOS_CPIO_MODE_IRWXG 00070
#define LIBOS_CPIO_MODE_IRGRP 00040
#define LIBOS_CPIO_MODE_IWGRP 00020
#define LIBOS_CPIO_MODE_IXGRP 00010

#define LIBOS_CPIO_MODE_IRWXO 00007
#define LIBOS_CPIO_MODE_IROTH 00004
#define LIBOS_CPIO_MODE_IWOTH 00002
#define LIBOS_CPIO_MODE_IXOTH 00001

typedef struct _libos_cpio libos_cpio_t;

typedef struct _libos_cpio_entry
{
    size_t size;
    uint32_t mode;
    char name[LIBOS_CPIO_PATH_MAX];
} libos_cpio_entry_t;

libos_cpio_t* libos_cpio_open(const char* path, uint32_t flags);

int libos_cpio_close(libos_cpio_t* cpio);

int libos_cpio_read_entry(libos_cpio_t* cpio, libos_cpio_entry_t* entry_out);

ssize_t libos_cpio_read_data(libos_cpio_t* cpio, void* data, size_t size);

int libos_cpio_write_entry(libos_cpio_t* cpio, const libos_cpio_entry_t* entry);

ssize_t libos_cpio_write_data(
    libos_cpio_t* cpio,
    const void* data,
    size_t size);

int libos_cpio_pack(const char* source, const char* target);

int libos_cpio_unpack(const char* source, const char* target);

#endif /* _LIBOS_CPIO_H */
