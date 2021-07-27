// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_MSG_H
#define _MYST_MSG_H

#include <sys/socket.h>

long myst_syscall_sendmsg(int sockfd, const struct msghdr* msg, int flags);
long myst_syscall_recvmsg(int sockfd, struct msghdr* msg, int flags);
long myst_syscall_sendmmsg(
    int sockfd,
    struct mmsghdr* msgvec,
    unsigned int vlen,
    int flags);
long myst_syscall_recvmmsg(
    int sockfd,
    struct mmsghdr* msgvec,
    unsigned int vlen,
    int flags,
    struct timespec* timeout);

#endif /* _MYST_MSG_H */
