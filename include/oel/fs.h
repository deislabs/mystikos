#ifndef _OEL_FS_H
#define _OEL_FS_H

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <dirent.h>

typedef struct oel_fs oel_fs_t;

typedef struct oel_file oel_file_t;

struct oel_fs
{
    int (*fs_release)(oel_fs_t* fs);

    int (*fs_creat)(oel_fs_t* fs, const char* pathname, mode_t mode);

    int (*fs_open)(
        oel_fs_t* fs,
        const char* pathname,
        int flags,
        mode_t mode,
        oel_file_t** file);

    off_t (*fs_lseek)(oel_fs_t* fs, int fd, off_t offset, int whence);

    ssize_t (*fs_read)(
        oel_fs_t* fs,
        oel_file_t* file,
        void* buf,
        size_t count);

    ssize_t (*fs_write)(
        oel_fs_t* fs,
        oel_file_t* file,
        const void* buf,
        size_t count);

    ssize_t (*fs_readv)(
        oel_fs_t* fs,
        int fd,
        const struct iovec* iov,
        int iovcnt);

    ssize_t (*fs_writev)(
        oel_fs_t* fs,
        int fd,
        const struct iovec* iov,
        int iovcnt);

    int (*fs_close)(oel_fs_t* fs, oel_file_t* file);

    int (*fs_stat)(oel_fs_t* fs, const char* pathname, struct stat* statbuf);

    int (*fs_fstat)(oel_fs_t* fs, int fd, struct stat* statbuf);

    int (*fs_link)(oel_fs_t* fs, const char* oldpath, const char* newpath);

    int (*fs_rename)(oel_fs_t* fs, const char* oldpath, const char* newpath);

    int (*fs_truncate)(oel_fs_t* fs, const char* path, off_t length);

    int (*fs_ftruncate)(oel_fs_t* fs, int fd, off_t length);

    int (*fs_mkdir)(oel_fs_t* fs, const char* pathname, mode_t mode);

    int (*fs_rmdir)(oel_fs_t* fs, const char* pathname);

    int (*fs_opendir)(oel_fs_t* fs, const char* name, DIR** dirp);

    int (*fs_readdir)(oel_fs_t* fs, DIR* dirp, struct dirent** direntp);

    int (*fs_closedir)(oel_fs_t* fs, DIR* dirp);
};

#endif /* _OEL_FS_H */
