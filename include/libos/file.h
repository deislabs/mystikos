// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_FILE_H
#define _LIBOS_FILE_H

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

int libos_getdents64(int fd, struct dirent* dirp, size_t count);

int libos_mkdirhier(const char* pathname, mode_t mode);

int libos_load_file(const char* path, void** data, size_t* size);

int libos_write_file(const char* path, const void* data, size_t size);

int libos_write_file_fd(int fd, const void* data, size_t size);

ssize_t libos_writen(int fd, const void* data, size_t size);

int libos_copy_file(const char* oldpath, const char* newpath);

#endif /* _LIBOS_FILE_H */
