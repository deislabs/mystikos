// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_FILE_H
#define _MYST_FILE_H

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

int myst_getdents64(int fd, struct dirent* dirp, size_t count);

int myst_mkdirhier(const char* pathname, mode_t mode);

int myst_load_file(const char* path, void** data, size_t* size);

int myst_write_file(const char* path, const void* data, size_t size);

int myst_write_file_fd(int fd, const void* data, size_t size);

int myst_copy_file(const char* oldpath, const char* newpath);

int myst_copy_file_fd(char* oldpath, int newfd);

int myst_chown_sudo_user(const char* path);

int myst_validate_file_path(const char* path);

#endif /* _MYST_FILE_H */
