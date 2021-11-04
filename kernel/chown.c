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

    /* if not root, check target uid/gid validity */
    if (thread->euid != 0)
    {
        if (((owner != (uid_t)-1) &&
             (myst_valid_uid_against_passwd_file(owner) < 0)) ||
            ((group != (gid_t)-1) &&
             (myst_valid_gid_against_group_file(group) < 0)))
        {
            ret = -EINVAL;
        }
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

    /* if not root, check target uid/gid validity */
    if (thread->euid != 0)
    {
        if (((owner != (uid_t)-1) &&
             (myst_valid_uid_against_passwd_file(owner) < 0)) ||
            ((group != (gid_t)-1) &&
             (myst_valid_gid_against_group_file(group) < 0)))
        {
            ret = -EINVAL;
        }
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

    /* if not root, check target uid/gid validity */
    if (thread->euid != 0)
    {
        if (((owner != (uid_t)-1) &&
             (myst_valid_uid_against_passwd_file(owner) < 0)) ||
            ((group != (gid_t)-1) &&
             (myst_valid_gid_against_group_file(group) < 0)))
        {
            ret = -EINVAL;
        }
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

long myst_syscall_fchownat(
    int dirfd,
    const char* pathname,
    uid_t owner,
    gid_t group,
    int flags)
{
    long ret = 0;
    char* abspath = NULL;

    if (!pathname)
        ERAISE(-EINVAL);

    if ((flags & ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)) != 0)
        ERAISE(-EINVAL);

    if (*pathname == '\0' && (flags & AT_EMPTY_PATH) && dirfd != AT_FDCWD)
    {
        ECHECK(myst_syscall_fchown(dirfd, owner, group));
    }
    else
    {
        ECHECK(myst_get_absolute_path_from_dirfd(
            dirfd, pathname, flags, &abspath, FB_PATH_NOT_EMPTY));

        if (flags & AT_SYMLINK_NOFOLLOW)
        {
            ECHECK(myst_syscall_lchown(abspath, owner, group));
        }
        else
        {
            ECHECK(myst_syscall_chown(abspath, owner, group));
        }
    }

done:

    if (abspath != pathname)
        free(abspath);

    return ret;
}
