// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <myst/kernel.h>
#include <myst/syscall.h>
#include <myst/thread.h>

/* Currently only supports a single mapping which is typically from enclave root
 * identity to the host application identity when executed. */
static myst_host_enc_id_mapping host_enc_id_mapping;

void myst_set_host_uid_gid_mapping(myst_host_enc_id_mapping id_mapping)
{
    host_enc_id_mapping = id_mapping;
}

uid_t myst_enc_uid_to_host(uid_t euid)
{
    if (euid == host_enc_id_mapping.enc_uid)
        return host_enc_id_mapping.host_uid;
    else
        return euid;
}
gid_t myst_enc_gid_to_host(gid_t egid)
{
    if (egid == host_enc_id_mapping.enc_gid)
        return host_enc_id_mapping.host_gid;
    else
        return egid;
}

/* success return 1, fail to read file return -1, not valid user return 0 */
/* username:password:UID:GID:comment:home directory:default shell */
static long myst_valid_uid_against_passwd_file(uid_t uid)
{
    int ret;
    int fd = -1;
    struct stat file_stat;
    off_t file_length;
    char* buffer = NULL;
    gid_t save_egid;
    uid_t save_euid;
    myst_thread_t* thread = myst_thread_self();

    save_egid = thread->egid;
    save_euid = thread->euid;

    /* Need to have permission to open password file to validate it */
    thread->euid = 0;
    thread->egid = 0;

    // root succeeds
    if (uid == 0)
    {
        ret = 1;
        goto done;
    }

    /* errors reading file return -1 */
    ret = -1;

    /* get file length */
    if (myst_syscall_stat("/etc/passwd", &file_stat) != 0)
        goto done;

    file_length = file_stat.st_size;

    buffer = malloc(file_length + 1);
    if (buffer == NULL)
        goto done;
    buffer[file_length] = '\0';

    fd = myst_syscall_open("/etc/passwd", O_RDONLY, 0);
    if (fd == -1)
        goto done;

    /* read into buffer */
    if (myst_syscall_read(fd, buffer, file_length) != file_length)
        goto done;

    /* Failures from now are not found errors */
    ret = 0;

    char* start_line = buffer;
    while (start_line)
    {
        char* username = start_line;
        char* password = strchr(username, ':');
        if ((password == NULL) || (*password != ':'))
        {
            goto done;
        }
        *password = '\0';
        password++;
        char* uid_str = strchr(password, ':');
        if ((uid_str == NULL) || (*uid_str != ':'))
        {
            goto done;
        }
        *uid_str = '\0';
        uid_str++;
        char* gid_str = strchr(uid_str, ':');
        if ((gid_str == NULL) || (*gid_str != ':'))
        {
            goto done;
        }
        *gid_str = '\0';
        gid_str++;
        char* comment = strchr(gid_str, ':');
        if ((comment == NULL) || (*comment != ':'))
        {
            goto done;
        }
        *comment = '\0';
        comment++;
        char* homedir = strchr(comment, ':');
        if ((homedir == NULL) || (*homedir != ':'))
        {
            goto done;
        }
        *homedir = '\0';
        homedir++;
        char* shell = strchr(homedir, ':');
        if ((shell == NULL) || (*shell != ':'))
        {
            goto done;
        }
        *shell = '\0';
        shell++;
        start_line = strchr(shell, '\n');

        // need to handle end of line and end of file properly */
        if ((start_line != NULL) && (*start_line == '\n'))
        {
            *start_line = '\0';
            start_line++;
        }
        else
        {
            /* we must be at end of file */
            start_line = NULL;
        }

        if (uid == (uid_t)atoi(uid_str))
        {
            ret = 1;
            goto done;
        }
    }

done:
    if (fd != -1)
        myst_syscall_close(fd);

    thread->egid = save_egid;
    thread->euid = save_euid;

    if (buffer)
    {
        memset(buffer, 0, file_length);
        free(buffer);
    }
    return ret;
}

/* success return 1, fail to read file return -1, not valid user return 0 */
/* group name:password:GID:list of users */
static long myst_valid_gid_against_group_file(gid_t gid)
{
    int ret;
    int fd = -1;
    struct stat file_stat;
    off_t file_length;
    char* buffer = NULL;
    gid_t save_egid;
    uid_t save_euid;
    myst_thread_t* thread = myst_thread_self();

    save_egid = thread->egid;
    save_euid = thread->euid;

    /* Need to have permission to open group file to validate it */
    thread->euid = 0;
    thread->egid = 0;

    // root succeeds
    if (gid == 0)
    {
        ret = 1;
        goto done;
    }

    /* errors reading file return -1 */
    ret = -1;

    /* get file length */
    if (myst_syscall_stat("/etc/passwd", &file_stat) != 0)
        goto done;

    file_length = file_stat.st_size;

    buffer = malloc(file_length + 1);
    if (buffer == NULL)
        goto done;
    buffer[file_length] = '\0';

    fd = myst_syscall_open("/etc/passwd", O_RDONLY, 0);
    if (fd == -1)
        goto done;

    /* read into buffer */
    if (myst_syscall_read(fd, buffer, file_length) != file_length)
        goto done;

    /* Failures from now are not found errors */
    ret = 0;

    char* start_line = buffer;
    while (start_line)
    {
        char* group_name = start_line;
        char* password = strchr(group_name, ':');
        if ((password == NULL) || (*password != ':'))
        {
            goto done;
        }
        *password = '\0';
        password++;
        char* gid_str = strchr(password, ':');
        if ((gid_str == NULL) || (*gid_str != ':'))
        {
            goto done;
        }
        *gid_str = '\0';
        gid_str++;
        char* list_users = strchr(gid_str, ':');
        if ((list_users == NULL) || (*list_users != ':'))
        {
            goto done;
        }
        *list_users = '\0';
        list_users++;
        start_line = strchr(list_users, '\n');

        // need to handle end of line and end of file properly */
        if ((start_line != NULL) && (*start_line == '\n'))
        {
            *start_line = '\0';
            start_line++;
        }
        else
        {
            /* we must be at end of file */
            start_line = NULL;
        }

        if (gid == (uid_t)atoi(gid_str))
        {
            ret = 1;
            goto done;
        }
    }

done:
    if (fd != -1)
        myst_syscall_close(fd);

    thread->egid = save_egid;
    thread->euid = save_euid;

    if (buffer)
    {
        memset(buffer, 0, file_length);
        free(buffer);
    }
    return ret;
}

long myst_syscall_getuid()
{
    myst_thread_t* thread = myst_thread_self();
    return thread->uid;
}

long myst_syscall_setuid(uid_t uid)
{
    long ret = 0;
    myst_thread_t* thread = myst_thread_self();

    /* EINVAL if not valid uid */
    if (myst_valid_uid_against_passwd_file(uid) <= 0)
    {
        ret = -EINVAL;
    }
    /* handle if euid is root (TODO: or CAP_SETUID is set), set all UIDs
     * to specified uid */
    else if (thread->euid == 0)
    {
        thread->uid = uid;
        thread->euid = uid;
        thread->savuid = uid;
        thread->fsuid = uid;
    }
    /* if uid does not match real uid or saved uid return EPERM (TODO:
     * or CAP_SETUID is set, but that was handled in previous clause)*/
    else if ((uid != thread->uid) && (uid != thread->savuid))
    {
        ret = -EPERM;
    }
    /* TODO: EAGAIN if uid != real uid and number of processes already
     * running as uid is exceeded (RLIMIT_NPROC) */
    /* Otherwise we set the effective and filesystem UID.  */
    else
    {
        thread->euid = uid;
        thread->fsuid = uid;
    }

    return ret;
}

long myst_syscall_getgid()
{
    myst_thread_t* thread = myst_thread_self();
    return thread->gid;
}

long myst_syscall_setgid(gid_t gid)
{
    long ret = 0;
    myst_thread_t* thread = myst_thread_self();

    /* EINVAL if not valid uid */
    if (myst_valid_gid_against_group_file(gid) <= 0)
    {
        ret = -EINVAL;
    }
    /* handle if egid is root (TODO: or CAP_SETGID is set), set all gids
     * to specified gid */
    else if (thread->egid == 0)
    {
        thread->gid = gid;
        thread->egid = gid;
        thread->savgid = gid;
        thread->fsgid = gid;
    }
    /* if gid does not match real gid or saved gid return EPERM (TODO:
     * or CAP_SETGID is set, but that was handled in previous clause)*/
    else if ((gid != thread->gid) && (gid != thread->savgid))
    {
        ret = -EPERM;
    }
    else
    {
        thread->egid = gid;
        thread->fsgid = gid;
    }

    return ret;
}

uid_t myst_syscall_geteuid()
{
    myst_thread_t* thread = myst_thread_self();
    return thread->euid;
}

gid_t myst_syscall_getegid()
{
    myst_thread_t* thread = myst_thread_self();
    return thread->egid;
}

long myst_syscall_setreuid(uid_t ruid, uid_t euid)
{
    uid_t sav_uid = -1;
    long ret = 0;
    myst_thread_t* thread = myst_thread_self();

    /* thread sav_uid is set to new euid (if not -1) if ruid is being
     * set (not -1) or euid is different from thread uid */
    if ((euid != (uid_t)-1) && ((ruid != (uid_t)-1) || (thread->uid != euid)))
    {
        sav_uid = euid;
    }

    /* ** global ** If ruid and or euid are -1, they are not set */
    /* If nothing is changing succeed */
    if (((euid == (uid_t)-1) && (ruid == (uid_t)-1)) ||
        ((ruid == thread->uid) && (euid == thread->euid)))
    {
        ret = 0;
    }
    /* if ruid or euid is not valid (ignoring -1) return EINVAL */
    else if (
        ((ruid != (uid_t)-1) &&
         (myst_valid_uid_against_passwd_file(ruid) <= 0)) ||
        ((euid != (uid_t)-1) &&
         (myst_valid_uid_against_passwd_file(euid) <= 0)))
    {
        /* for some reason the LTP tests are expecting a different error to that
         * which is documented for the syscall itself. Instead of returning
         * EINVAL in this situation the test is expecting permissions problems
         */
        ret = -EPERM;
        //        ret = -EINVAL;
    }
    /* TODO: else if thread uid is not equal to ruid and setting would
     * exceed RLIMIT_NPROC return EAGAIN */
    /* else If root (TODO: or CAP_SETUID) set thread uid and euid if not
     * -1 */
    else if (thread->euid == 0)
    {
        if (ruid != (uid_t)-1)
            thread->uid = ruid;
        if (euid != (uid_t)-1)
            thread->euid = euid;
    }
    /* else if swapping threads euid and uid */
    else if ((thread->uid == euid) && (thread->euid == ruid))
    {
        thread->uid = ruid;
        thread->euid = euid;
    }
    /* else if setting one to the value of the other */
    else if (
        ((ruid == (uid_t)-1) ||
         ((ruid != (uid_t)-1) &&
          ((ruid == thread->euid) || (ruid == thread->savuid)))) &&
        ((euid == (uid_t)-1) ||
         ((euid != (uid_t)-1) &&
          ((euid == thread->uid) || (euid == thread->savuid)))))
    {
        if (ruid != (uid_t)-1)
            thread->uid = ruid;
        if (euid != (uid_t)-1)
            thread->euid = euid;
    }
/* else if setting euid to value of the saved uid */
#if 0
    else if (thread->savuid == euid)
    {
        thread->euid = euid;
    }
#endif
    /* else return EPERM */
    else
    {
        ret = -EPERM;
    }

    if ((sav_uid != (uid_t)-1) && (ret == 0))
        thread->savuid = sav_uid;

    return ret;
}

long myst_syscall_setregid(gid_t rgid, gid_t egid)
{
    gid_t sav_gid = -1;
    long ret = 0;
    myst_thread_t* thread = myst_thread_self();

    /* thread sav_gid is set to new egid (if not -1) if rgid is being
     * set (not -1) or egid is different from thread gid */
    if ((egid != (gid_t)-1) && ((rgid != (gid_t)-1) || (thread->gid != egid)))
    {
        sav_gid = egid;
    }

    /* ** global ** If ruid and or euid are -1, they are not set */
    /* If nothing is changing succeed */
    if (((egid == (gid_t)-1) && (rgid == (gid_t)-1)) ||
        ((rgid == thread->gid) && (egid == thread->egid)))
    {
        ret = 0;
    }
    /* if ruid or euid is not valid (ignoring -1) return EINVAL */
    else if (
        ((rgid != (gid_t)-1) &&
         (myst_valid_gid_against_group_file(rgid) <= 0)) ||
        ((egid != (gid_t)-1) && (myst_valid_gid_against_group_file(egid) <= 0)))
    {
        /* for some reason the LTP tests are expecting a different error to that
         * which is documented for the syscall itself. Instead of returning
         * EINVAL in this situation the test is expecting permissions problems
         */
        ret = -EPERM;
        //        ret = -EINVAL;
    }
    /* else If root (TODO: or CAP_SETUID) set thread gid and guid if not
     * -1 */
    else if (thread->euid == 0)
    {
        if (rgid != (gid_t)-1)
            thread->gid = rgid;
        if (egid != (gid_t)-1)
            thread->egid = egid;
    }
    /* else if swapping threads egid and gid */
    else if ((thread->gid == egid) && (thread->egid == rgid))
    {
        thread->gid = rgid;
        thread->egid = egid;
    }
    /* else if setting one to the value of the other */
    else if (
        ((rgid == (gid_t)-1) ||
         ((rgid != (gid_t)-1) &&
          ((rgid == thread->euid) || (rgid == thread->savgid)))) &&
        ((egid == (gid_t)-1) ||
         ((egid != (gid_t)-1) &&
          ((egid == thread->gid) || (egid == thread->savgid)))))
    {
        if (rgid != (gid_t)-1)
            thread->gid = rgid;
        if (egid != (gid_t)-1)
            thread->egid = egid;
    }
/* else if setting euid to value of the saved gid */
#if 0
    else if (thread->savgid == egid)
    {
        thread->egid = egid;
    }
#endif
    /* else return EPERM */
    else
    {
        ret = -EPERM;
    }

    if ((sav_gid != (gid_t)-1) && (ret == 0))
        thread->savgid = sav_gid;

    return ret;
}

long myst_syscall_setresuid(uid_t ruid, uid_t euid, uid_t savuid)
{
    long ret = 0;
    myst_thread_t* thread = myst_thread_self();

    /* ** global ** If ruid and or euid are -1, they are not set */
    /* if ruid or euid is not valid (ignoring -1) return EINVAL */
    if (((ruid != (uid_t)-1) &&
         (myst_valid_uid_against_passwd_file(ruid) <= 0)) ||
        ((euid != (uid_t)-1) &&
         (myst_valid_uid_against_passwd_file(euid) <= 0)) ||
        ((savuid != (uid_t)-1) &&
         (myst_valid_uid_against_passwd_file(savuid) <= 0)))
    {
        ret = -EINVAL;
    }
    /* TODO: else if thread uid is not equal to ruid and setting would
     * exceed RLIMIT_NPROC return EAGAIN */
    /* else If root (TODO: or CAP_SETUID) set thread uid, euid and
     * savuid if not -1 */
    else if (thread->euid == 0)
    {
        if (ruid != (uid_t)-1)
            thread->uid = ruid;
        if (euid != (uid_t)-1)
            thread->euid = euid;
        if (savuid != (uid_t)-1)
            thread->savuid = savuid;
    }
    /* else if setting one to the value of the to one of the other */
    else if (
        ((ruid == (uid_t)-1) || (thread->euid == ruid) ||
         (thread->savuid == ruid)) &&
        ((euid == (uid_t)-1) || (thread->uid == euid) ||
         (thread->savuid == euid)) &&
        ((savuid == (uid_t)-1) || (thread->uid == savuid) ||
         (thread->euid == savuid)))
    {
        if (ruid != (uid_t)-1)
            thread->uid = ruid;
        if (euid != (uid_t)-1)
            thread->euid = euid;
        if (savuid != (uid_t)-1)
            thread->savuid = savuid;
    }
    /* else return EPERM */
    else
    {
        ret = -EPERM;
    }

    /* fsuid is always set to euid if set */
    if ((euid != (uid_t)-1) && (ret == 0))
        thread->fsuid = euid;

    return ret;
}

long myst_syscall_getresuid(uid_t* ruid, uid_t* euid, uid_t* savuid)
{
    long ret = 0;

    myst_thread_t* thread = myst_thread_self();

    *ruid = thread->uid;
    *euid = thread->euid;
    *savuid = thread->savuid;

    return ret;
}

long myst_syscall_setresgid(gid_t rgid, gid_t egid, gid_t savgid)
{
    long ret = 0;
    myst_thread_t* thread = myst_thread_self();

    /* ** global ** If rgid and or egid are -1, they are not set */
    /* if rgid or egid is not valid (ignoring -1) return EINVAL */
    if (((rgid != (gid_t)-1) &&
         (myst_valid_gid_against_group_file(rgid) <= 0)) ||
        ((egid != (gid_t)-1) &&
         (myst_valid_gid_against_group_file(egid) <= 0)) ||
        ((savgid != (gid_t)-1) &&
         (myst_valid_gid_against_group_file(savgid) <= 0)))
    {
        ret = -EINVAL;
    }
    /* TODO: else if thread gid is not equal to rgid and setting would
     * exceed RLIMIT_NPROC return EAGAIN */
    /* else If root (TODO: or CAP_SETUID) set thread gid, egid and
     * savgid if not -1 */
    else if (thread->euid == 0)
    {
        if (rgid != (gid_t)-1)
            thread->gid = rgid;
        if (egid != (gid_t)-1)
            thread->egid = egid;
        if (savgid != (gid_t)-1)
            thread->savgid = savgid;
    }
    /* else if setting one to the value of the to one of the other */
    else if (
        ((rgid == (gid_t)-1) || (thread->egid == rgid) ||
         (thread->savgid == rgid)) &&
        ((egid == (gid_t)-1) || (thread->gid == egid) ||
         (thread->savgid == egid)) &&
        ((savgid == (gid_t)-1) || (thread->gid == savgid) ||
         (thread->egid == savgid)))
    {
        if (rgid != (gid_t)-1)
            thread->gid = rgid;
        if (egid != (gid_t)-1)
            thread->egid = egid;
        if (savgid != (gid_t)-1)
            thread->savgid = savgid;
    }
    /* else return EPERM */
    else
    {
        ret = -EPERM;
    }

    /* fsgid is always set to egid if set */
    if ((egid != (gid_t)-1) && (ret == 0))
        thread->fsgid = egid;

    return ret;
}

long myst_syscall_getresgid(gid_t* rgid, gid_t* egid, gid_t* savgid)
{
    long ret = 0;
    myst_thread_t* thread = myst_thread_self();

    *rgid = thread->gid;
    *egid = thread->egid;
    *savgid = thread->savgid;

    return ret;
}

long myst_syscall_setfsuid(uid_t fsuid)
{
    myst_thread_t* thread = myst_thread_self();
    long ret = thread->fsuid;

    /* function always returns the previous fsuid. This is a known issue in the
     * linux kernel */

    /* If fsuid is valid AND ... */
    if (myst_valid_uid_against_passwd_file(fsuid) == 1)
    {
        /*thread euid is root (or capability is CAO_SETUID) */
        if (thread->euid == 0)
        {
            thread->fsuid = fsuid;
        }
        /* fsuid matches one of the other uids */
        else if (
            (fsuid == thread->uid) || (fsuid == thread->euid) ||
            (fsuid == thread->savuid))
        {
            thread->fsuid = fsuid;
        }
    }

    return ret;
}

long myst_syscall_setfsgid(gid_t fsgid)
{
    myst_thread_t* thread = myst_thread_self();
    long ret = thread->fsgid;

    /* function always returns the previous fsuid. This is a known issue
     * in the linux kernel */

    /* If fsgid is valid AND ... */
    if (myst_valid_gid_against_group_file(fsgid) == 1)
    {
        /* thread euid is root (or capability is CAP_SETUID) */
        if (thread->euid == 0)
        {
            thread->fsgid = fsgid;
        }
        /* fsgid matches one of the other gids */
        else if (
            (fsgid == thread->gid) || (fsgid == thread->egid) ||
            (fsgid == thread->savgid))
        {
            thread->fsgid = fsgid;
        }
    }

    return ret;
}

long myst_syscall_getgroups(int size, gid_t list[])
{
    myst_thread_t* thread = myst_thread_self();

    /* if size if 0 return number of supguid */
    if (size == 0)
        return thread->num_supgid;

    /* validate parameters */
    if ((thread->num_supgid > (size_t)size) || (size < 0))
        return -EINVAL;

    if (size && (list == NULL))
    {
        return -EFAULT;
    }

    memcpy(list, thread->supgid, thread->num_supgid * sizeof(gid_t));

    return thread->num_supgid;
}

long myst_syscall_setgroups(size_t size, const gid_t* list)
{
    myst_thread_t* thread = myst_thread_self();

    /* validate params */
    if (size > NGROUPS_MAX)
        return -EINVAL;

    /* if euid is root (or capability is CAP_SETUID) */
    if (thread->euid == 0)
    {
        thread->num_supgid = size;
        if (size && list)
            memcpy(thread->supgid, list, size * sizeof(gid_t));
    }
    else
        return -EPERM;

    return 0;
}
