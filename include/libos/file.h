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

ssize_t libos_readv(int fd, const struct iovec* iov, int iovcnt);

ssize_t libos_writev(int fd, const struct iovec* iov, int iovcnt);

int libos_stat(const char* pathname, struct stat* statbuf);

int libos_lstat(const char* pathname, struct stat* statbuf);

int libos_fstat(int fd, struct stat* statbuf);

int libos_mkdir(const char* pathname, mode_t mode);

int libos_rmdir(const char* pathname);

int libos_getdents64(int fd, struct dirent* dirp, size_t count);

int libos_opendir(const char* name, DIR** dirp);

int libos_readdir(DIR* dir, struct dirent** entp);

int libos_closedir(DIR* dir);

int libos_link(const char* oldpath, const char* newpath);

int libos_unlink(const char* pathname);

int libos_access(const char* pathname, int mode);

int libos_rename(const char* oldpath, const char* newpath);

int libos_truncate(const char* path, off_t length);

int libos_ftruncate(int fd, off_t length);

ssize_t libos_readlink(const char* pathname, char* buf, size_t bufsiz);

int libos_symlink(const char* target, const char* linkpath);

int libos_mkdirhier(const char* pathname, mode_t mode);

int libos_load_file(const char* path, void** data, size_t* size);

int libos_write_file(const char* path, const void* data, size_t size);

int libos_write_file_fd(int fd, const void* data, size_t size);

#endif /* _LIBOS_FILE_H */
