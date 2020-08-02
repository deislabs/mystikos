// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_FILE_H
#define _LIBOS_FILE_H

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <dirent.h>

int libos_creat(const char* pathname, mode_t mode);

int libos_open(const char* pathname, int flags, mode_t mode);

off_t libos_lseek(int fd, off_t offset, int whence);

int libos_close(int fd);

ssize_t libos_read(int fd, void* buf, size_t count);

ssize_t libos_write(int fd, const void* buf, size_t count);

ssize_t libos_readv(int fd, struct iovec* iov, int iovcnt);

ssize_t libos_writev(int fd, const struct iovec* iov, int iovcnt);

int libos_stat(const char* pathname, struct stat* statbuf);

int libos_fstat(int fd, struct stat* statbuf);

int libos_mkdir(const char* pathname, mode_t mode);

int libos_rmdir(const char* pathname);

int libos_getdents64(int fd, struct dirent* dirp, size_t count);

DIR* libos_opendir(const char* name);

struct dirent* libos_readdir(DIR* dir);

int libos_closedir(DIR* dir);

int libos_link(const char* oldpath, const char* newpath);

int libos_unlink(const char* pathname);

int libos_access(const char* pathname, int mode);

#endif /* _LIBOS_FILE_H */
