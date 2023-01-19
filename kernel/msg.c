// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <myst/eraise.h>
#include <myst/fdtable.h>
#include <myst/msg.h>
#include <myst/syscall.h>
#include <myst/times.h>

long myst_syscall_sendmsg(int sockfd, const struct msghdr* msg, int flags)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_sendmsg)(sd, sock, msg, flags);

done:
    return ret;
}

long myst_syscall_recvmsg(int sockfd, struct msghdr* msg, int flags)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_recvmsg)(sd, sock, msg, flags);

done:
    return ret;
}

long myst_syscall_sendmmsg(
    int sockfd,
    struct mmsghdr* msgvec,
    unsigned int vlen,
    int flags)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;
    unsigned int cnt;

    if (!msgvec && vlen)
        ERAISE(-EFAULT);

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));

    for (cnt = 0; cnt < vlen; cnt++)
    {
        ret = (*sd->sd_sendmsg)(sd, sock, &msgvec[cnt].msg_hdr, flags);
        if (ret < 0)
            break;
        msgvec[cnt].msg_len = ret;
    }
    // Only return err when zero msg was sent
    ret = cnt ? (long)cnt : ret;

done:
    return ret;
}

long myst_syscall_recvmmsg(
    int sockfd,
    struct mmsghdr* msgvec,
    unsigned int vlen,
    int flags,
    struct timespec* timeout)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;
    struct timespec start;
    struct timespec now;
    long expire = 0;
    unsigned int cnt = 0;

    if (!msgvec && vlen)
        ERAISE(-EFAULT);

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));

    if (timeout)
    {
        if (!is_timespec_valid(timeout))
            ERAISE(-EINVAL);

        expire = timespec_to_nanos(timeout);
        myst_syscall_clock_gettime(CLOCK_MONOTONIC, &start);
    }
    for (cnt = 0; cnt < vlen; cnt++)
    {
        // The MSG_WAITFORONE flag is only recognizable by recvmmsg
        ret = (*sd->sd_recvmsg)(
            sd, sock, &msgvec[cnt].msg_hdr, flags & ~MSG_WAITFORONE);
        if (ret < 0)
            break;
        msgvec[cnt].msg_len = ret;
        // Turns on MSG_DONTWAIT after the first message has been
        // received.
        if (cnt == 1 && flags & MSG_WAITFORONE)
            flags |= MSG_DONTWAIT;
        if (timeout)
        {
            myst_syscall_clock_gettime(CLOCK_MONOTONIC, &now);
            long lapsed = myst_lapsed_nsecs(&start, &now);
            if (lapsed >= expire)
                break;
        }
    }
    // Only return err when zero msg was received
    ret = cnt ? (long)cnt : ret;

done:
    return ret;
}
