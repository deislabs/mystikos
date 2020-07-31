// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_FILE_H
#define _LIBOS_FILE_H

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int libos_open(const char* pathname, int flags, mode_t mode);

int libos_close(int fd);

ssize_t libos_read(int fd, void* buf, size_t count);

ssize_t libos_write(int fd, const void* buf, size_t count);

#endif /* _LIBOS_FILE_H */
