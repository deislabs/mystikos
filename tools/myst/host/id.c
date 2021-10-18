#include <syscall.h>

#include <myst/eraise.h>
#include <myst/id.h>

long myst_change_identity(
    uid_t euid,
    gid_t egid,
    myst_resuid_t* resuid,
    myst_resgid_t* resgid)
{
    long ret = 0;

    if (resuid)
        *resuid = (myst_resuid_t)MYST_RESUID_INITIALIZER;

    if (resgid)
        *resgid = (myst_resgid_t)MYST_RESGID_INITIALIZER;

    if (euid < 0 || egid < 0 || !resuid || !resgid)
        ERAISE(-EINVAL);

    if (syscall(SYS_getresuid, &resuid->ruid, &resuid->euid, &resuid->suid) !=
        0)
    {
        ERAISE(-errno);
    }

    if (syscall(SYS_getresgid, &resgid->rgid, &resgid->egid, &resgid->sgid) !=
        0)
    {
        ERAISE(-errno);
    }

    if (syscall(SYS_setresgid, -1, egid, -1) != 0)
        ERAISE(-errno);

    if (syscall(SYS_setresuid, -1, euid, -1) != 0)
        ERAISE(-errno);

done:

    if (ret < 0)
    {
        myst_restore_identity(resuid, resgid);

        if (resuid)
            *resuid = (myst_resuid_t)MYST_RESUID_INITIALIZER;

        if (resgid)
            *resgid = (myst_resgid_t)MYST_RESGID_INITIALIZER;
    }

    return ret;
}

long myst_restore_identity(
    const myst_resuid_t* resuid,
    const myst_resgid_t* resgid)
{
    long ret = 0;

    if (!resuid || !resgid)
        ERAISE(-EINVAL);

    if (resgid->rgid >= 0 && resgid->egid >= 0 && resgid->sgid >= 0 &&
        syscall(SYS_setresgid, resgid->rgid, resgid->egid, resgid->sgid) != 0)
    {
        ERAISE(-errno);
    }

    if (resuid->ruid >= 0 && resuid->euid >= 0 && resuid->suid >= 0 &&
        syscall(SYS_setresuid, resuid->ruid, resuid->euid, resuid->suid) != 0)
    {
        ERAISE(-errno);
    }

done:
    return ret;
}
