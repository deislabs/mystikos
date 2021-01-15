// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_CPIO_H
#define _MYST_CPIO_H

#include <stdbool.h>
#include <string.h>

#include <myst/defs.h>
#include <myst/types.h>

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

#define MYST_CPIO_MAGIC_INITIALIZER { '0', '7', '0', '7', '0', '1' }

#define MYST_CPIO_PATH_MAX 256

#define MYST_CPIO_FLAG_READ 0
#define MYST_CPIO_FLAG_CREATE 1

#define MYST_CPIO_MODE_IFMT 00170000
#define MYST_CPIO_MODE_IFSOCK 0140000
#define MYST_CPIO_MODE_IFLNK 0120000
#define MYST_CPIO_MODE_IFREG 0100000
#define MYST_CPIO_MODE_IFBLK 0060000
#define MYST_CPIO_MODE_IFDIR 0040000
#define MYST_CPIO_MODE_IFCHR 0020000
#define MYST_CPIO_MODE_IFIFO 0010000
#define MYST_CPIO_MODE_ISUID 0004000
#define MYST_CPIO_MODE_ISGID 0002000
#define MYST_CPIO_MODE_ISVTX 0001000

#define MYST_CPIO_MODE_IRWXU 00700
#define MYST_CPIO_MODE_IRUSR 00400
#define MYST_CPIO_MODE_IWUSR 00200
#define MYST_CPIO_MODE_IXUSR 00100

#define MYST_CPIO_MODE_IRWXG 00070
#define MYST_CPIO_MODE_IRGRP 00040
#define MYST_CPIO_MODE_IWGRP 00020
#define MYST_CPIO_MODE_IXGRP 00010

#define MYST_CPIO_MODE_IRWXO 00007
#define MYST_CPIO_MODE_IROTH 00004
#define MYST_CPIO_MODE_IWOTH 00002
#define MYST_CPIO_MODE_IXOTH 00001

typedef struct _myst_cpio myst_cpio_t;

typedef struct _myst_cpio_entry
{
    size_t size;
    uint32_t mode;
    char name[MYST_CPIO_PATH_MAX];
} myst_cpio_entry_t;

myst_cpio_t* myst_cpio_open(const char* path, uint32_t flags);

int myst_cpio_close(myst_cpio_t* cpio);

int myst_cpio_read_entry(myst_cpio_t* cpio, myst_cpio_entry_t* entry_out);

ssize_t myst_cpio_read_data(myst_cpio_t* cpio, void* data, size_t size);

int myst_cpio_write_entry(myst_cpio_t* cpio, const myst_cpio_entry_t* entry);

ssize_t myst_cpio_write_data(
    myst_cpio_t* cpio,
    const void* data,
    size_t size);

int myst_cpio_pack(const char* source, const char* target);

int myst_cpio_unpack(const char* source, const char* target);

int myst_cpio_next_entry(
    const void* data,
    size_t size,
    size_t* pos,
    myst_cpio_entry_t* entry,
    const void** file_data);

typedef int (*myst_cpio_create_file_function_t)(
    const char* path,
    const void* file_data,
    size_t file_size);

int myst_cpio_mem_unpack(
    const void* cpio_data,
    size_t cpio_size,
    const char* target,
    myst_cpio_create_file_function_t create_file);

/* Test for CPIO magic string: "070701"; return 0 or ENOTSUP */
int myst_cpio_test(const char* path);

MYST_INLINE bool myst_is_cpio_archive(const void* data, size_t size)
{
    uint8_t m[] = MYST_CPIO_MAGIC_INITIALIZER;
    return data && (size > sizeof(m)) && memcmp(data, m, sizeof(m)) == 0;
}

#endif /* _MYST_CPIO_H */
