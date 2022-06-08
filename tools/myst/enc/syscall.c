#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>

#include <myst/eraise.h>
#include <myst/iov.h>
#include <myst/syscall.h>
#include <myst/tcall.h>
#include "myst_t.h"

#define RETURN(EXPR) return ((EXPR) == OE_OK ? ret : -EINVAL)

// Force downsizing of ocall output lengths to prevent reading past the end
// of the caller's buffer. See issue #83. This breaks API compatibility in
// some cases. If such a case is encountered, undefine this macro termporarily
// to diagnose the issue.
#define DOWNSIZE_OCALL_OUTPUT_LENGTHS

// Open Enclave uses a pre-allocated 16-kilobyte "ocall buffer" to transfer
// parameters to host memory. If that buffer is too small to accommodate the
// parameters, memory is obtained with oe_host_malloc() and later released with
// oe_host_free(), thereby incurring two extra ocalls. So attempting to perform
// one read ocall, results in three ocalls. To avoid this overhead, we must
// limit the buffer size to ensure the "ocall buffer" will be sufficient.
// This buffer size is used by the read-write family of functions.
#define MAX_BUFFER_SIZE 8192

static long _fstat(int fd, struct stat* statbuf);

static int _cap_size(int fd, size_t* size)
{
    int ret = 0;

    if (*size > MAX_BUFFER_SIZE)
    {
#if 0
        struct stat statbuf;

        if (_fstat(fd, &statbuf) != 0)
            ERAISE(-errno);

        if (S_ISSOCK(statbuf.st_mode))
            *size = MAX_BUFFER_SIZE;
#else
        *size = MAX_BUFFER_SIZE;
#endif
    }

done:
    return ret;
}

static long _read(
    int fd,
    void* buf,
    size_t count,
    typeof(myst_read_ocall) ocall)
{
    long ret = 0;
    long retval;

    if (fd < 0 || (!buf && count) || count > SSIZE_MAX)
    {
        ret = -EINVAL;
        goto done;
    }

    ECHECK(_cap_size(fd, &count));

    if (ocall(&retval, fd, buf, count) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    if (retval < 0)
    {
        ret = retval;
        goto done;
    }

    /* guard against host setting the return value greater than count */
    if (retval > (ssize_t)count)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}

static long _write(
    int fd,
    const void* buf,
    size_t count,
    typeof(myst_write_ocall) ocall)
{
    long ret = 0;
    long retval;

    if (fd < 0 || (!buf && count) || count > SSIZE_MAX)
    {
        ret = -EINVAL;
        goto done;
    }

    ECHECK(_cap_size(fd, &count));

    if (ocall(&retval, fd, buf, count) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    if (retval < 0)
    {
        ret = retval;
        goto done;
    }

    /* guard against host returning a size bigger than buffer */
    if (retval > (ssize_t)count)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}

static long _nanosleep(const struct timespec* req, struct timespec* rem)
{
    long ret;
    RETURN(myst_nanosleep_ocall(&ret, req, rem));
}

static long _close(int fd)
{
    long ret;
    RETURN(myst_close_ocall(&ret, fd));
}

static long _fcntl(int fd, int cmd, long arg)
{
    long ret = 0;
    long retval;

    switch (cmd)
    {
        /* supported */
        case F_GETFD:
        case F_SETFD:
        case F_GETFL:
        case F_SETFL:
        case F_GETSIG:
        case F_SETSIG:
        case F_GETOWN:
        case F_SETOWN:
        case F_GETPIPE_SZ:
        case F_SETPIPE_SZ:
        {
            if (myst_fcntl_ocall(&retval, fd, cmd, arg) != OE_OK)
            {
                ret = -EINVAL;
                goto done;
            }

            ret = retval;
            goto done;
        }
        case F_SETLKW:
        {
            const struct flock* flock = (const struct flock*)arg;

            if (myst_fcntl_setlkw_ocall(&retval, fd, flock) != OE_OK)
            {
                ret = -EINVAL;
                goto done;
            }

            ret = retval;
            goto done;
        }
        /* unsupported */
        default:
        {
            ret = -ENOTSUP;
            goto done;
        }
    }

done:
    return ret;
}

static long _bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{
    long ret;
    RETURN(myst_bind_ocall(&ret, sockfd, addr, addrlen));
}

static long _connect(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen,
    typeof(myst_connect_ocall) ocall)
{
    long ret;
    RETURN(ocall(&ret, sockfd, addr, addrlen));
}

static long _recvfrom(
    int sockfd,
    void* buf,
    size_t len,
    int flags,
    struct sockaddr* src_addr,
    socklen_t* addrlen,
    typeof(myst_recvfrom_ocall) ocall)
{
    long ret = 0;
    socklen_t n;
    long retval;

    if (sockfd < 0 || (!buf && len) || len > SSIZE_MAX)
    {
        ret = -EINVAL;
        goto done;
    }

    ECHECK(_cap_size(sockfd, &len));

    n = addrlen ? *addrlen : 0;

    if (ocall(&retval, sockfd, buf, len, flags, src_addr, &n, n) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    /* return any error */
    if (retval < 0)
    {
        ret = retval;
        goto done;
    }

    /* guard against the host returning too large a size */
    if (src_addr && addrlen)
    {
        /* if n is bigger than max size address */
        if (n > sizeof(struct sockaddr_storage))
        {
            ret = -EINVAL;
            goto done;
        }

        /* note: n may legitimately be bigger due to truncation */
        *addrlen = n;
    }

    /* guard against host returning a size larger than the buffer */
    if ((size_t)retval > len)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}

static long _sendto(
    int sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct sockaddr* dest_addr,
    socklen_t addrlen,
    typeof(myst_sendto_ocall) ocall)
{
    long ret = 0;
    long retval;
    oe_result_t oeret;

    if (sockfd < 0 || (!buf && len) || len > SSIZE_MAX)
    {
        ret = -EINVAL;
        goto done;
    }

    ECHECK(_cap_size(sockfd, &len));

    if ((oeret = ocall(&retval, sockfd, buf, len, flags, dest_addr, addrlen)) !=
        OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    if (retval < 0)
    {
        ret = retval;
        goto done;
    }

    /* guard against host returning a size bigger than buffer */
    if (retval > (ssize_t)len)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}

static long _socket(int domain, int type, int protocol)
{
    long ret;
    RETURN(myst_socket_ocall(&ret, domain, type, protocol));
}

static long _accept4(
    int sockfd,
    struct sockaddr* addr,
    socklen_t* addrlen,
    int flags,
    typeof(myst_accept4_ocall) ocall)
{
    long ret = 0;
    long retval;
    socklen_t n = (addr && addrlen) ? *addrlen : 0;

    if (ocall(&retval, sockfd, addr, &n, n, flags) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    if (retval < 0)
    {
        ret = retval;
        goto done;
    }

    /* guard against the host returning too large a size */
    if (addr && addrlen)
    {
        if (n > sizeof(struct sockaddr_storage))
        {
            ret = -EINVAL;
            goto done;
        }

#ifdef DOWNSIZE_OCALL_OUTPUT_LENGTHS
        if (n > *addrlen)
            n = *addrlen;
#endif

        /* note: n may legitimately be bigger due to truncation */
        *addrlen = n;
    }

    ret = retval;

done:
    return ret;
}

static long _sendmsg(
    int sockfd,
    const struct msghdr* msg,
    int flags,
    typeof(myst_sendmsg_ocall) ocall)
{
    long ret = 0;
    long retval = 0;
    oe_result_t oeret;

    if (sockfd < 0 || !msg)
    {
        ret = -EINVAL;
        goto done;
    }

    /* The kernel pre-flattens the IO vector into a single iov[] element */
    if (msg->msg_iovlen != 1)
    {
        ret = -EINVAL;
        goto done;
    }

    /* repeat operation when recvmsg() returns a short count */
    {
        const uint8_t* buf = msg->msg_iov[0].iov_base;
        size_t len = msg->msg_iov[0].iov_len;
        size_t count = 0;

        while (len > 0)
        {
            size_t cap = len;
            ECHECK(_cap_size(sockfd, &cap));

            if ((oeret = ocall(
                     &retval,
                     sockfd,
                     msg->msg_name,
                     msg->msg_namelen,
                     buf,
                     cap,
                     msg->msg_control,
                     msg->msg_controllen,
                     msg->msg_flags,
                     flags)) != OE_OK)
            {
                ret = -EINVAL;
                goto done;
            }

            if (retval <= 0)
            {
                if (count > 0)
                    retval = count;

                break;
            }

            buf += retval;
            len -= retval;
            count += retval;
        }

        /* if all bytes were written */
        if (len == 0)
            retval = count;
    }

    if (retval < 0)
    {
        ret = retval;
        goto done;
    }

    /* guard against host returning a size bigger than buffer */
    if ((size_t)retval > msg->msg_iov[0].iov_len)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:

    return ret;
}

static long _recvmsg(
    int sockfd,
    struct msghdr* msg,
    int flags,
    typeof(myst_recvmsg_ocall) ocall)
{
    long ret = 0;
    long retval;
    void* buf = NULL;
    ssize_t len = 0;
    socklen_t namelen;
    socklen_t controllen;

    if (sockfd < 0 || !msg)
    {
        ret = -EINVAL;
        goto done;
    }

    if ((len = myst_iov_len(msg->msg_iov, msg->msg_iovlen)) < 0)
    {
        ret = len;
        goto done;
    }

    if (len > SSIZE_MAX)
    {
        ret = -EINVAL;
        goto done;
    }

    ECHECK(_cap_size(sockfd, &len));

    if (len && !(buf = malloc((size_t)len)))
    {
        ret = -EINVAL;
        goto done;
    }

    namelen = msg->msg_namelen;
    controllen = msg->msg_controllen;

    if (ocall(
            &retval,
            sockfd,
            msg->msg_name,
            namelen,
            &namelen,
            buf,
            (size_t)len,
            msg->msg_control,
            controllen,
            &controllen,
            &msg->msg_flags,
            flags) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    if (retval < 0)
    {
        ret = retval;
        goto done;
    }

    /* guard against the host returning too large a size */
    {
        if (namelen > sizeof(struct sockaddr_storage))
        {
            ret = -EINVAL;
            goto done;
        }

#ifdef DOWNSIZE_OCALL_OUTPUT_LENGTHS
        if (namelen > msg->msg_namelen)
            namelen = msg->msg_namelen;
#endif

        /* note: namelen may legitimately be bigger due to truncation */
        msg->msg_namelen = msg->msg_name ? namelen : 0;
    }

    /* guard against host returning too large a value for msg_controllen */
    {
#ifdef DOWNSIZE_OCALL_OUTPUT_LENGTHS
        if (controllen > msg->msg_controllen)
        {
            controllen = msg->msg_controllen;
            msg->msg_flags |= MSG_CTRUNC;
        }
#endif

        /* note: controllen may legitimately be bigger due to truncation */
        msg->msg_controllen = msg->msg_control ? controllen : 0;
    }

    /* guard against host returning a size larger than the buffer */
    if (retval > len)
    {
        // ATTN: this implementation fails if returned length is greater than
        // buffer length, although this is legal according to the recvmsg()
        // documentation.
        ret = -EINVAL;
        goto done;
    }

    {
        long r;
        const struct iovec* iov = msg->msg_iov;
        int iovlen = msg->msg_iovlen;

        /* scatter the single buffer onto multiple iovec buffers */
        if ((r = myst_iov_scatter(iov, iovlen, buf, (size_t)retval)) < 0)
        {
            ret = r;
            goto done;
        }
    }

    ret = retval;

done:

    if (buf)
        free(buf);

    return ret;
}

static long _shutdown(int sockfd, int how)
{
    long ret;
    RETURN(myst_shutdown_ocall(&ret, sockfd, how));
}

static long _listen(int sockfd, int backlog)
{
    long ret;
    RETURN(myst_listen_ocall(&ret, sockfd, backlog));
}

static long _getsockname(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
    long ret = 0;
    long retval;
    socklen_t n;

    if (sockfd < 0)
    {
        ret = -EBADF;
        goto done;
    }

    if (!addr || !addrlen || *addrlen < 0)
    {
        ret = -EINVAL;
        goto done;
    }

    n = *addrlen;

    if (myst_getsockname_ocall(&retval, sockfd, addr, &n, n) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    if (retval < 0)
    {
        ret = retval;
        goto done;
    }

    /* guard against the host returning too large a size */
    {
        if (n > sizeof(struct sockaddr_storage))
        {
            ret = -EINVAL;
            goto done;
        }

#ifdef DOWNSIZE_OCALL_OUTPUT_LENGTHS
        /* note: n may legitimately be bigger due to truncation */
        if (n > *addrlen)
            n = *addrlen;
#endif

        *addrlen = n;
    }

    ret = retval;

done:
    return ret;
}

static long _getpeername(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
    long ret = 0;
    long retval;
    socklen_t n;

    if (sockfd < 0 || !addr || !addrlen)
    {
        ret = -EINVAL;
        goto done;
    }

    n = *addrlen;

    if (myst_getpeername_ocall(&retval, sockfd, addr, &n, n) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    if (retval < 0)
    {
        *addrlen = 0;
        ret = retval;
        goto done;
    }

    /* guard against the host returning too large a size */
    {
        if (n > sizeof(struct sockaddr_storage))
        {
            ret = -EINVAL;
            goto done;
        }

#ifdef DOWNSIZE_OCALL_OUTPUT_LENGTHS
        if (n > *addrlen)
            n = *addrlen;
#endif

        /* note: n may legitimately be bigger due to truncation */
        *addrlen = n;
    }

    ret = retval;

done:
    return ret;
}

static long _socketpair(int domain, int type, int protocol, int sv[2])
{
    long ret;
    RETURN(myst_socketpair_ocall(&ret, domain, type, protocol, sv));
}

static long _setsockopt(
    int sockfd,
    int level,
    int optname,
    const void* optval,
    socklen_t optlen)
{
    long ret;
    RETURN(myst_setsockopt_ocall(&ret, sockfd, level, optname, optval, optlen));
}

static long _getsockopt(
    int sockfd,
    int level,
    int optname,
    void* optval,
    socklen_t* optlen)
{
    long ret = 0;
    long retval;
    socklen_t n;

    if (sockfd < 0 || !optval || !optlen)
    {
        ret = -EINVAL;
        goto done;
    }

    n = *optlen;

    if (myst_getsockopt_ocall(&retval, sockfd, level, optname, optval, &n, n) !=
        OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    if (retval < 0)
    {
        ret = retval;
        goto done;
    }

    /* guard against host returning a size larger than the buffer */
    if (n > *optlen)
    {
        ret = -EINVAL;
        goto done;
    }

    *optlen = n;

    ret = retval;

done:
    return ret;
}

static long _ioctl(int fd, unsigned long request, void* argp)
{
    long ret = 0;
    size_t argp_size = 0;

    switch (request)
    {
        case FIOCLEX:  /* set close-on-exec */
        case FIONCLEX: /* clear close-on-exc */
        {
            break;
        }
        case FIONREAD: /* get number read */
        case FIONBIO:  /* set or clear non-blocking I/O */
        {
            if (argp)
                argp_size = sizeof(int);
            break;
        }
        case SIOCGIFINDEX:
        case SIOCGIFNAME:
        {
            if (argp)
                argp_size = sizeof(struct ifreq);
            break;
        }

        default:
        {
            /* unsupported ioctl */
            return -ENOTSUP;
        }
    }

    RETURN(myst_ioctl_ocall(&ret, fd, request, argp, argp_size));
}

static long _fstat(int fd, struct stat* statbuf)
{
    long ret = 0;
    long retval;

    if (fd < 0 || !statbuf)
    {
        ret = -EINVAL;
        goto done;
    }

    if (myst_fstat_ocall(&retval, fd, (struct myst_stat*)statbuf) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}

static long _sched_yield(void)
{
    long ret = 0;
    long retval;

    if (myst_sched_yield_ocall(&retval) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}

static long _sched_getparam(pid_t pid, struct myst_sched_param* param)
{
    long ret = 0;
    long retval;

    if (myst_sched_getparam_ocall(&retval, pid, param) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}

static long _fchmod(int fd, mode_t mode, uid_t host_euid, gid_t host_egid)
{
    long ret = 0;
    long retval;

    if (myst_fchmod_ocall(&retval, fd, mode, host_euid, host_egid) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}

/* The OCALL based implementaiton is only used for "target" event such as socket
 * event. "kernel" event, or "internal" event synchronization is handled inside
 */
static long _poll(struct pollfd* fds, nfds_t nfds, int timeout)
{
    long ret = 0;
    long retval;
    struct pollfd buf[256]; /* use this buffer if large enough */
    struct pollfd* copy;    /* pointer to buf or heap-allocated memory */

    if (!fds && nfds > 0)
    {
        ret = -EFAULT;
        goto done;
    }

    /* make copy of fds[] to prevent modification of fd and events fields */
    if (fds)
    {
        size_t size;

        /* find the size of fds[] in bytes and check for overflow */
        if (__builtin_mul_overflow(nfds, sizeof(struct pollfd), &size))
        {
            ret = -EINVAL;
            goto done;
        }

        /* use local buffer if possible to avoid unecessary heap allocation */
        if (size <= sizeof(buf))
        {
            /* size could be zero but that is acceptable */
            copy = buf;
        }
        else if (!(copy = malloc(size)))
        {
            ret = -ENOMEM;
            goto done;
        }

        if (size)
            memcpy(copy, fds, size);
    }
    else
    {
        /* support null fds[] array: example: poll(NULL, 0, 1000) */
        copy = NULL;
    }

    if (myst_poll_ocall(&retval, copy, nfds, timeout) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    /* copy back the revents field and sanitize the value provided by the
     * host-side to be a subset of the events mask.
     */
    for (nfds_t i = 0; i < nfds; i++)
    {
        const short int mask = POLLERR | POLLHUP | POLLNVAL;
        fds[i].revents = copy[i].revents & (fds[i].events | mask);
    }

    /* guard against return value that is bigger than nfds */
    if (retval >= 0 && (nfds_t)retval > nfds)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:

    if (copy && copy != buf)
        free(copy);

    return ret;
}

static int _mprotect(void* addr, size_t len, int prot)
{
    int ret = 0;
    int retval;

    if (myst_mprotect_ocall(&retval, addr, len, prot) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}

#ifdef MYST_ENABLE_HOSTFS
static long _open(
    const char* pathname,
    int flags,
    mode_t mode,
    uid_t uid,
    gid_t gid)
{
    long ret = 0;
    long retval;

    if ((ret = myst_open_ocall(&retval, pathname, flags, mode, uid, gid)) !=
        OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _stat(
    const char* pathname,
    struct myst_stat* statbuf,
    uid_t uid,
    gid_t gid)
{
    long ret = 0;
    long retval;

    if (myst_stat_ocall(&retval, pathname, statbuf, uid, gid) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _lstat(
    const char* pathname,
    struct myst_stat* statbuf,
    uid_t host_uid,
    gid_t host_gid)
{
    long ret = 0;
    long retval;

    if (myst_lstat_ocall(&retval, pathname, statbuf, host_uid, host_gid) !=
        OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _access(const char* pathname, int mode)
{
    long ret = 0;
    long retval;

    if (myst_access_ocall(&retval, pathname, mode) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _dup(int oldfd)
{
    long ret = 0;
    long retval;

    if (myst_dup_ocall(&retval, oldfd) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _pread64(int fd, void* buf, size_t count, off_t offset)
{
    long ret = 0;
    long retval;

    if (fd < 0 || (!buf && count) || count > SSIZE_MAX)
    {
        ret = -EINVAL;
        goto done;
    }

    ECHECK(_cap_size(fd, &count));

    if (myst_pread64_ocall(&retval, fd, buf, count, offset) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    if (retval < 0)
    {
        ret = retval;
        goto done;
    }

    /* guard against host setting the return value greater than count */
    if (retval > (ssize_t)count)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _pwrite64(int fd, const void* buf, size_t count, off_t offset)
{
    long ret = 0;
    long retval;

    if (fd < 0 || (!buf && count) || count > SSIZE_MAX)
    {
        ret = -EINVAL;
        goto done;
    }

    ECHECK(_cap_size(fd, &count));

    if (myst_pwrite64_ocall(&retval, fd, buf, count, offset) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    if (retval < 0)
    {
        ret = retval;
        goto done;
    }

    /* guard against host returning a size bigger than buffer */
    if (retval > (ssize_t)count)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _link(const char* oldpath, const char* newpath)
{
    long ret = 0;
    long retval;

    if (!oldpath || !newpath)
    {
        ret = -EINVAL;
        goto done;
    }

    if (myst_link_ocall(&retval, oldpath, newpath) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _linkat(
    int olddirfd,
    const char* oldpath,
    int newdirfd,
    const char* newpath,
    int flags)
{
    long ret = 0;
    long retval;

    if (!oldpath || !newpath)
    {
        ret = -EINVAL;
        goto done;
    }

    if (myst_linkat_ocall(
            &retval, olddirfd, oldpath, newdirfd, newpath, flags) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _unlink(const char* pathname)
{
    long ret = 0;
    long retval;

    if (!pathname)
    {
        ret = -EINVAL;
        goto done;
    }

    if (myst_unlink_ocall(&retval, pathname) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _mkdir(
    const char* pathname,
    mode_t mode,
    uid_t host_euid,
    gid_t host_egid)
{
    long ret = 0;
    long retval;

    if (!pathname)
    {
        ret = -EINVAL;
        goto done;
    }

    if (myst_mkdir_ocall(&retval, pathname, mode, host_euid, host_egid) !=
        OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _rmdir(const char* pathname, uid_t host_euid, gid_t host_egid)
{
    long ret = 0;
    long retval;

    if (!pathname)
    {
        ret = -EINVAL;
        goto done;
    }

    if (myst_rmdir_ocall(&retval, pathname, host_euid, host_egid) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _getdents64(
    unsigned int fd,
    struct myst_linux_dirent64* dirp,
    unsigned int count)
{
    long ret = 0;
    long retval;

    if (fd >= INT_MAX || (dirp && !count))
    {
        ret = -EINVAL;
        goto done;
    }

    if (myst_getdents64_ocall(&retval, fd, dirp, count) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    if (retval < 0)
    {
        ret = retval;
        goto done;
    }

    /* guard against host returning a size bigger than the buffer */
    if (retval > count)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _rename(const char* oldpath, const char* newpath)
{
    long ret = 0;
    long retval;

    if (!oldpath || !newpath)
    {
        ret = -EINVAL;
        goto done;
    }

    if (myst_rename_ocall(&retval, oldpath, newpath) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _truncate(const char* path, off_t length)
{
    long ret = 0;
    long retval;

    if (!path)
    {
        ret = -EINVAL;
        goto done;
    }

    if (myst_truncate_ocall(&retval, path, length) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _ftruncate(int fd, off_t length)
{
    long ret = 0;
    long retval;

    if (fd < 0)
    {
        ret = -EINVAL;
        goto done;
    }

    if (myst_ftruncate_ocall(&retval, fd, length) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _symlink(
    const char* target,
    const char* linkpath,
    uid_t host_uid,
    gid_t host_gid)
{
    long ret = 0;
    long retval;

    if (!target || !linkpath)
    {
        ret = -EINVAL;
        goto done;
    }

    if (myst_symlink_ocall(&retval, target, linkpath, host_uid, host_gid) !=
        OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _readlink(const char* pathname, char* buf, size_t bufsiz)
{
    long ret = 0;
    long retval;

    if (!pathname || (buf && !bufsiz))
    {
        ret = -EINVAL;
        goto done;
    }

    if (myst_readlink_ocall(&retval, pathname, buf, bufsiz) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    if (retval < 0)
    {
        ret = retval;
        goto done;
    }

    if ((size_t)retval > bufsiz)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _statfs(const char* pathname, struct myst_statfs* buf)
{
    long ret = 0;
    long retval;

    if (myst_statfs_ocall(&retval, pathname, buf) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _fstatfs(int fd, struct myst_statfs* buf)
{
    long ret = 0;
    long retval;

    if (myst_fstatfs_ocall(&retval, fd, buf) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static off_t _lseek(int fd, off_t offset, int whence)
{
    long ret = 0;
    long retval;

    if (myst_lseek_ocall(&retval, fd, offset, whence) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _utimensat(
    int dirfd,
    const char* pathname,
    const struct timespec times[2],
    int flags,
    uid_t uid,
    gid_t gid)
{
    long ret = 0;
    long retval;

    if (myst_utimensat_ocall(
            &retval, dirfd, pathname, times, flags, uid, gid) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

static long _sched_setaffinity(
    pid_t pid,
    size_t cpusetsize,
    const cpu_set_t* mask)
{
    long ret;
    /* On success, the raw sched_setaffinity() system call returns the size (in
     * bytes) of the cpumask_t data type that is used internally by the kernel
     * to represent the CPU set bit mask.
     */
    RETURN(myst_sched_setaffinity_ocall(&ret, pid, cpusetsize, (void*)mask));
}

static long _sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t* mask)
{
    long ret;
    if (myst_sched_getaffinity_ocall(&ret, pid, cpusetsize, (void*)mask) !=
        OE_OK)
    {
        return -EINVAL;
    }
    /* On success, the raw sched_getaffinity() system call returns the number of
     * bytes placed copied into the mask buffer; this will be the minimum of
     * cpusetsize and the size (in bytes) of the cpumask_t data type that is
     * used internally by the kernel to represent the CPU set bit mask. Guard
     * against host setting the return value greater than cpusetsize.
     */
    if (ret > (ssize_t)cpusetsize)
    {
        ret = -EINVAL;
    }
    return ret;
}

struct getcpu_cache;

static long _getcpu(unsigned* cpu, unsigned* node)
{
    long ret;
    RETURN(myst_getcpu_ocall(&ret, cpu, node));
}

#ifdef MYST_ENABLE_HOSTFS
static long _chown(
    const char* pathname,
    uid_t owner,
    gid_t group,
    uid_t host_euid,
    gid_t host_egid)
{
    long ret = 0;
    long retval;

    if (myst_chown_ocall(
            &retval, pathname, owner, group, host_euid, host_egid) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _fchown(
    int fd,
    uid_t owner,
    gid_t group,
    uid_t host_euid,
    gid_t host_egid)
{
    long ret = 0;
    long retval;

    if (myst_fchown_ocall(&retval, fd, owner, group, host_euid, host_egid) !=
        OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _lchown(
    const char* pathname,
    uid_t owner,
    gid_t group,
    uid_t host_euid,
    gid_t host_egid)
{
    long ret = 0;
    long retval;

    if (myst_lchown_ocall(
            &retval, pathname, owner, group, host_euid, host_egid) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _chmod(
    const char* pathname,
    mode_t mode,
    uid_t host_euid,
    gid_t host_egid)
{
    long ret = 0;
    long retval;

    if (myst_chmod_ocall(&retval, pathname, mode, host_euid, host_egid) !=
        OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _fdatasync(int fd)
{
    long ret = 0;
    long retval;

    if (myst_fdatasync_ocall(&retval, fd) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

#ifdef MYST_ENABLE_HOSTFS
static long _fsync(int fd)
{
    long ret = 0;
    long retval;

    if (myst_fsync_ocall(&retval, fd) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
#endif

static int _pipe2(int pipefd[2], int flags)
{
    int ret = 0;
    long retval;

    if (!pipefd)
    {
        ret = -EINVAL;
        goto done;
    }

    if (myst_pipe2_ocall(&retval, pipefd, flags) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}

static long _epoll_create1(int flags)
{
    long ret = 0;
    long retval;

    if (myst_epoll_create1_ocall(&retval, flags) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}

static long _epoll_wait(
    int epfd,
    struct epoll_event* events,
    size_t maxevents,
    int timeout)
{
    long ret = 0;
    long retval;

    if (epfd < 0 || !events || maxevents == 0)
    {
        ret = -EINVAL;
        goto done;
    }

    if (myst_epoll_wait_ocall(&retval, epfd, events, maxevents, timeout) !=
        OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    /* check for error */
    if (retval < 0)
    {
        ret = retval;
        goto done;
    }

    /* guard against possible read past end of buffer */
    if ((size_t)retval > maxevents)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}

static long _epoll_ctl(
    int epfd,
    int op,
    int fd,
    const struct epoll_event* event)
{
    long ret = 0;
    long retval;
    struct epoll_event event_buf;

    if (epfd < 0)
    {
        ret = -EINVAL;
        goto done;
    }

    if (!event)
    {
        memset(&event_buf, 0, sizeof(event_buf));
        event = &event_buf;
    }

    if (myst_epoll_ctl_ocall(&retval, epfd, op, fd, event) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}

static long _eventfd2(unsigned int initval, int flags)
{
    long ret = 0;
    long retval;

    if (myst_eventfd_ocall(&retval, initval, flags) != OE_OK)
    {
        ret = -EINVAL;
        goto done;
    }

    ret = retval;

done:
    return ret;
}

long myst_handle_tcall(long n, long params[6])
{
    const long a = params[0];
    const long b = params[1];
    const long c = params[2];
    const long d = params[3];
    const long e = params[4];
    const long f = params[5];

    switch (n)
    {
        case SYS_read:
        {
            return _read((int)a, (void*)b, (size_t)c, myst_read_ocall);
        }
        case MYST_TCALL_READ_BLOCK:
        {
            return _read((int)a, (void*)b, (size_t)c, myst_read_block_ocall);
        }
        case SYS_write:
        {
            return _write((int)a, (const void*)b, (size_t)c, myst_write_ocall);
        }
        case MYST_TCALL_WRITE_BLOCK:
        {
            return _write(
                (int)a, (const void*)b, (size_t)c, myst_write_block_ocall);
        }
        case SYS_close:
        {
            return _close((int)a);
        }
        case SYS_nanosleep:
        {
            return _nanosleep((const struct timespec*)a, (struct timespec*)b);
        }
        case SYS_fcntl:
        {
            return _fcntl((int)a, (int)b, (long)c);
        }
        case SYS_bind:
        {
            return _bind((int)a, (struct sockaddr*)b, (socklen_t)c);
        }
        case SYS_connect:
        {
            return _connect(
                (int)a, (struct sockaddr*)b, (socklen_t)c, myst_connect_ocall);
        }
        case MYST_TCALL_CONNECT_BLOCK:
        {
            return _connect(
                (int)a,
                (struct sockaddr*)b,
                (socklen_t)c,
                myst_connect_block_ocall);
        }
        case SYS_recvfrom:
        {
            return _recvfrom(
                (int)a,
                (void*)b,
                (size_t)c,
                (int)d,
                (struct sockaddr*)e,
                (socklen_t*)f,
                myst_recvfrom_ocall);
        }
        case MYST_TCALL_RECVFROM_BLOCK:
        {
            return _recvfrom(
                (int)a,
                (void*)b,
                (size_t)c,
                (int)d,
                (struct sockaddr*)e,
                (socklen_t*)f,
                myst_recvfrom_block_ocall);
        }
        case SYS_sendto:
        {
            return _sendto(
                (int)a,
                (void*)b,
                (size_t)c,
                (int)d,
                (const struct sockaddr*)e,
                (socklen_t)f,
                myst_sendto_ocall);
        }
        case MYST_TCALL_SENDTO_BLOCK:
        {
            return _sendto(
                (int)a,
                (void*)b,
                (size_t)c,
                (int)d,
                (const struct sockaddr*)e,
                (socklen_t)f,
                myst_sendto_block_ocall);
        }
        case SYS_socket:
        {
            return _socket((int)a, (int)b, (int)c);
        }
        case SYS_accept:
        {
            return _accept4(
                (int)a,
                (struct sockaddr*)b,
                (socklen_t*)c,
                (int)0,
                myst_accept4_ocall);
        }
        case SYS_accept4:
        {
            return _accept4(
                (int)a,
                (struct sockaddr*)b,
                (socklen_t*)c,
                (int)d,
                myst_accept4_ocall);
        }
        case MYST_TCALL_ACCEPT4_BLOCK:
        {
            return _accept4(
                (int)a,
                (struct sockaddr*)b,
                (socklen_t*)c,
                (int)d,
                myst_accept4_block_ocall);
        }
        case SYS_sendmsg:
        {
            return _sendmsg(
                (int)a, (const struct msghdr*)b, (int)c, myst_sendmsg_ocall);
        }
        case MYST_TCALL_SENDMSG_BLOCK:
        {
            return _sendmsg(
                (int)a,
                (const struct msghdr*)b,
                (int)c,
                myst_sendmsg_block_ocall);
        }
        case SYS_recvmsg:
        {
            return _recvmsg(
                (int)a, (struct msghdr*)b, (int)c, myst_recvmsg_ocall);
        }
        case MYST_TCALL_RECVMSG_BLOCK:
        {
            return _recvmsg(
                (int)a, (struct msghdr*)b, (int)c, myst_recvmsg_block_ocall);
        }
        case SYS_shutdown:
        {
            return _shutdown((int)a, (int)b);
        }
        case SYS_listen:
        {
            return _listen((int)a, (int)b);
        }
        case SYS_getsockname:
        {
            return _getsockname((int)a, (struct sockaddr*)b, (socklen_t*)c);
        }
        case SYS_getpeername:
        {
            return _getpeername((int)a, (struct sockaddr*)b, (socklen_t*)c);
        }
        case SYS_socketpair:
        {
            return _socketpair((int)a, (int)b, (int)c, (int*)d);
        }
        case SYS_setsockopt:
        {
            return _setsockopt(
                (int)a, (int)b, (int)c, (const void*)d, (socklen_t)e);
        }
        case SYS_getsockopt:
        {
            return _getsockopt((int)a, (int)b, (int)c, (void*)d, (socklen_t*)e);
        }
        case SYS_ioctl:
        {
            return _ioctl((int)a, (unsigned long)b, (void*)c);
        }
        case SYS_fstat:
        {
            return _fstat((int)a, (struct stat*)b);
        }
        case SYS_sched_yield:
        {
            return _sched_yield();
        }
        case SYS_sched_getparam:
        {
            return _sched_getparam((pid_t)a, (struct myst_sched_param*)b);
        }
        case SYS_fchmod:
        {
            return _fchmod((int)a, (mode_t)b, (uid_t)c, (gid_t)d);
        }
        case SYS_poll:
        {
            return _poll((struct pollfd*)a, (nfds_t)b, (int)c);
        }
        case SYS_mprotect:
        {
            return _mprotect((void*)a, (size_t)b, (int)c);
        }
#ifdef MYST_ENABLE_HOSTFS
        case SYS_open:
        {
            return _open((const char*)a, (int)b, (mode_t)c, (uid_t)d, (gid_t)e);
        }
        case SYS_stat:
        {
            return _stat(
                (const char*)a, (struct myst_stat*)b, (uid_t)c, (gid_t)d);
        }
        case SYS_lstat:
        {
            return _lstat(
                (const char*)a, (struct myst_stat*)b, (uid_t)c, (gid_t)d);
        }
        case SYS_access:
        {
            return _access((const char*)a, (int)b);
        }
        case SYS_dup:
        {
            return _dup((int)a);
        }
        case SYS_pread64:
        {
            return _pread64((int)a, (void*)b, (size_t)c, (off_t)d);
        }
        case SYS_pwrite64:
        {
            return _pwrite64((int)a, (const void*)b, (size_t)c, (off_t)d);
        }
        case SYS_link:
        {
            return _link((const char*)a, (const char*)b);
        }
        case SYS_linkat:
        {
            return _linkat(
                (int)a, (const char*)b, (int)c, (const char*)d, (int)e);
        }
        case SYS_unlink:
        {
            return _unlink((const char*)a);
        }
        case SYS_mkdir:
        {
            return _mkdir((const char*)a, (mode_t)b, (uid_t)c, (gid_t)d);
        }
        case SYS_rmdir:
        {
            return _rmdir((const char*)a, (uid_t)b, (gid_t)c);
        }
        case SYS_getdents64:
        {
            return _getdents64(
                (unsigned int)a,
                (struct myst_linux_dirent64*)b,
                (unsigned int)c);
        }
        case SYS_rename:
        {
            return _rename((const char*)a, (const char*)b);
        }
        case SYS_truncate:
        {
            return _truncate((const char*)a, (off_t)b);
        }
        case SYS_ftruncate:
        {
            return _ftruncate((int)a, (off_t)b);
        }
        case SYS_symlink:
        {
            return _symlink((const char*)a, (const char*)b, (uid_t)c, (gid_t)d);
        }
        case SYS_readlink:
        {
            return _readlink((const char*)a, (char*)b, (size_t)c);
        }
        case SYS_statfs:
        {
            return _statfs((const char*)a, (struct myst_statfs*)b);
        }
        case SYS_fstatfs:
        {
            return _fstatfs((int)a, (struct myst_statfs*)b);
        }
        case SYS_lseek:
        {
            return _lseek((int)a, b, (int)c);
        }
        case SYS_utimensat:
        {
            return _utimensat(
                (int)a,
                (const char*)b,
                (const struct timespec*)c,
                (int)d,
                (uid_t)e,
                (gid_t)f);
        }
        case SYS_chown:
        {
            return _chown(
                (const char*)a, (uid_t)b, (gid_t)c, (uid_t)d, (gid_t)e);
        }
        case SYS_fchown:
        {
            return _fchown((int)a, (uid_t)b, (gid_t)c, (uid_t)d, (gid_t)e);
        }
        case SYS_lchown:
        {
            return _lchown(
                (const char*)a, (uid_t)b, (gid_t)c, (uid_t)d, (gid_t)e);
        }
        case SYS_chmod:
        {
            return _chmod((const char*)a, (mode_t)b, (uid_t)c, (gid_t)d);
        }
        case SYS_fdatasync:
        {
            return _fdatasync((int)a);
        }
        case SYS_fsync:
        {
            return _fsync((int)a);
        }
#endif
        case SYS_sched_setaffinity:
        {
            return _sched_setaffinity((pid_t)a, (size_t)b, (const cpu_set_t*)c);
        }
        case SYS_sched_getaffinity:
        {
            return _sched_getaffinity((pid_t)a, (size_t)b, (cpu_set_t*)c);
        }
        case SYS_getcpu:
        {
            return _getcpu((unsigned*)a, (unsigned*)b);
        }
        case SYS_pipe2:
        {
            return _pipe2((int*)a, (int)b);
        }
        case SYS_epoll_create1:
        {
            return _epoll_create1((int)a);
        }
        case SYS_epoll_wait:
        {
            return _epoll_wait(
                (int)a, (struct epoll_event*)b, (size_t)c, (int)d);
        }
        case SYS_epoll_ctl:
        {
            return _epoll_ctl(
                (int)a, (int)b, (int)c, (const struct epoll_event*)d);
        }
        case SYS_eventfd2:
        {
            return _eventfd2(a, b);
        }
        default:
        {
            return -ENOTSUP;
        }
    }
}
