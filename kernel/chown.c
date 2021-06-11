// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <myst/eraise.h>
#include <myst/kernel.h>
#include <myst/mount.h>
#include <myst/paths.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/thread.h>

static int _path_checks(const char* pathname)
{
    int ret = 0;

    if (!pathname)
        return -EINVAL;

    if (pathname == (void*)0xffffffffffffffff)
        ERAISE(-EFAULT);

    if (*pathname == '\0')
        ERAISE(-ENOENT);

    if (strlen(myst_basename(pathname)) > NAME_MAX)
        ERAISE(-ENAMETOOLONG);

done:
    return ret;
}

static int _non_root_chown_checks(
    myst_thread_t* thread,
    uid_t owner,
    gid_t group,
    struct stat* statbuf)
{
    int ret = 0;

    /* file should be owned by the thread */
    if (statbuf->st_uid != thread->euid)
        ERAISE(-EPERM);

    /* owner should be -1 or user ID of file */
    if (!(owner == (uid_t)-1 || owner == statbuf->st_uid))
        ERAISE(-EPERM);

    /* group should either be thread's egid or one of the supplementary gids
     */
    if (group != (gid_t)-1 && check_thread_group_membership(group) != 0)
        ERAISE(-EPERM);
done:
    return ret;
}

long myst_syscall_chown(const char* pathname, uid_t owner, gid_t group)
{
    long ret = 0;
    myst_fs_t* fs;
    myst_thread_t* thread = myst_thread_self();
    struct locals
    {
        char suffix[PATH_MAX];
        struct stat statbuf;
    }* locals = NULL;

    ECHECK(_path_checks(pathname));

    if (((owner != (uid_t)-1) &&
         (myst_valid_uid_against_passwd_file(owner) < 0)) ||
        ((group != (gid_t)-1) &&
         (myst_valid_gid_against_group_file(group) < 0)))
    {
        ret = -EINVAL;
    }

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));

    /* if thread's euid is root (TODO: or has CAP_CHOWN capability) */
    if (thread->euid == 0)
    {
        ECHECK((*fs->fs_chown)(fs, locals->suffix, owner, group));
    }
    /* non-privileged thread case */
    else
    {
        ECHECK((*fs->fs_stat)(fs, locals->suffix, &locals->statbuf));
        ECHECK(_non_root_chown_checks(thread, owner, group, &locals->statbuf));
        ECHECK(fs->fs_chown(fs, locals->suffix, owner, group));
    }

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_fchown(int fd, uid_t owner, gid_t group)
{
    long ret = 0;
    myst_file_t* file = NULL;
    myst_fs_t* fs = NULL;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_thread_t* thread = myst_thread_self();
    struct locals
    {
        char suffix[PATH_MAX];
        struct stat statbuf;
    }* locals = NULL;

    if (fd < 0)
        return -EINVAL;

    if (((owner != (uid_t)-1) &&
         (myst_valid_uid_against_passwd_file(owner) < 0)) ||
        ((group != (gid_t)-1) &&
         (myst_valid_gid_against_group_file(group) < 0)))
    {
        ret = -EINVAL;
    }

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_fdtable_get_file(fdtable, fd, &fs, &file));

    /* if thread's euid is root (TODO: or has CAP_CHOWN capability) */
    if (thread->euid == 0)
    {
        ECHECK((*fs->fs_fchown)(fs, file, owner, group));
    }
    /* non-privileged thread case */
    else
    {
        ECHECK((*fs->fs_fstat)(fs, file, &locals->statbuf));
        ECHECK(_non_root_chown_checks(thread, owner, group, &locals->statbuf));
        ECHECK((*fs->fs_fchown)(fs, file, owner, group));
    }
done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_lchown(const char* pathname, uid_t owner, gid_t group)
{
    long ret = 0;
    myst_fs_t* fs;
    myst_thread_t* thread = myst_thread_self();
    struct locals
    {
        char suffix[PATH_MAX];
        struct stat statbuf;
    }* locals = NULL;

    ECHECK(_path_checks(pathname));

    if (((owner != (uid_t)-1) &&
         (myst_valid_uid_against_passwd_file(owner) < 0)) ||
        ((group != (gid_t)-1) &&
         (myst_valid_gid_against_group_file(group) < 0)))
    {
        ret = -EINVAL;
    }

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));

    /* if thread's euid is root (TODO: or has CAP_CHOWN capability) */
    if (thread->euid == 0)
    {
        ECHECK((*fs->fs_lchown)(fs, locals->suffix, owner, group));
    }
    /* non-privileged thread case */
    else
    {
        ECHECK(fs->fs_lstat(fs, locals->suffix, &locals->statbuf));
        ECHECK(_non_root_chown_checks(thread, owner, group, &locals->statbuf));
        ECHECK(fs->fs_lchown(fs, locals->suffix, owner, group));
    }

done:

    if (locals)
        free(locals);

    return ret;
}

int resolve_at_path(
    int dirfd,
    const char* pathname,
    int flags,
    char* resolved_path,
    size_t resolved_path_size)
{
    int ret = 0;

    /* If pathname is absolute, then ignore dirfd */
    if (*pathname == '/' || dirfd == AT_FDCWD)
    {
        myst_strlcpy(resolved_path, pathname, strlen(pathname) + 1);
    }
    else if (*pathname == '\0')
    {
        if (!(flags & AT_EMPTY_PATH))
            ERAISE(-ENOENT);

        if (dirfd < 0)
            ERAISE(-EBADF);

        if (flags & AT_SYMLINK_NOFOLLOW)
        {
            myst_fdtable_t* fdtable = myst_fdtable_current();
            myst_fs_t* fs;
            myst_file_t* file;

            ECHECK(myst_fdtable_get_file(fdtable, dirfd, &fs, &file));
            ECHECK((*fs->fs_realpath)(
                fs, file, resolved_path, resolved_path_size));
        }
        else
        {
            *resolved_path = '\0';
        }
    }
    else
    {
        ECHECK(get_absolute_path_from_dirfd(
            dirfd, pathname, resolved_path, resolved_path_size));
    }

done:
    return ret;
}

long myst_syscall_fchownat(
    int dirfd,
    const char* pathname,
    uid_t owner,
    gid_t group,
    int flags)
{
    long ret = 0;
    struct locals
    {
        char resolved_path[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!pathname)
        ERAISE(-EINVAL);

    if ((flags & ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)) != 0)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(resolve_at_path(
        dirfd,
        pathname,
        flags,
        locals->resolved_path,
        sizeof(locals->resolved_path)));

    if (*locals->resolved_path == '\0')
    {
        ECHECK(myst_syscall_fchown(dirfd, owner, group));
    }
    else
    {
        if (flags & AT_SYMLINK_NOFOLLOW)
        {
            ECHECK(myst_syscall_lchown(locals->resolved_path, owner, group));
        }
        else
        {
            ECHECK(myst_syscall_chown(locals->resolved_path, owner, group));
        }
    }

done:

    if (locals)
        free(locals);

    return ret;
}
