// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <myst/buf.h>
#include <myst/cond.h>
#include <myst/eraise.h>
#include <myst/iov.h>
#include <myst/list.h>
#include <myst/process.h>
#include <myst/sockdev.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/syslog.h>
#include <myst/tcall.h>
#include <myst/time.h>

#define MAGIC 0x137ac8153c924911

#define MAX_ACCEPTORS 64

#define SUN_PATH_SIZE sizeof(((struct sockaddr_un*)NULL)->sun_path)
#define SUN_FAMILY_SIZE sizeof(((struct sockaddr_un*)NULL)->sun_family)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"

#define BUF_SIZE ((size_t)212992)

#define DEFAULT_SO_SNDBUF ((size_t)212992)
#define DEFAULT_SO_RCVBUF ((size_t)212992)
#define MIN_SO_SNDBUF ((size_t)4096)
#define MIN_SO_RCVBUF ((size_t)4096)

//#define TRACE
#ifdef TRACE
#define T(EXPR) EXPR
#else
#define T(EXPR)
#endif

typedef enum state
{
    STATE_NONE_ENABLED,
    STATE_WR_ENABLED,
    STATE_RDWR_ENABLED,
    STATE_RD_ENABLED,
} state_t;

MYST_UNUSED
static const char* _state_names[] = {
    "STATE_NONE_ENABLED",
    "STATE_WR_ENABLED",
    "STATE_RDWR_ENABLED",
    "STATE_RD_ENABLED",
};

typedef struct acceptor
{
    myst_cond_t cond;
    myst_mutex_t mutex;
    char sun_path[SUN_PATH_SIZE];
    myst_list_t list;
} acceptor_t;

typedef struct shared
{
    /* common fields */
    uint64_t magic;      /* MAGIC */
    struct shared* peer; /* peer of this socket */
    bool nonblock;       /* whether socket is non-blocking */
    bool closed;         /* whether socket is closed */

    /* input buffer (assumed size is DEFAULT_SO_RCVBUF) */
    myst_buf_t buf;

    /* support getsockopt(SO_TYPE) */
    int so_type;

    /* support setsockopt(SO_SNDBUF/SO_RCVBUF) but ignore sizes */
    size_t so_sndbuf;
    size_t so_rcvbuf;

    /* support setsockopt(SO_REUSEADDR) but ignore for AF_LOCAL */
    uint64_t so_reuseaddr;

    /* Abstract namespace flag: indicates whether name provided at bind() time
     * is a fs independent name. sun_path starts with \0 byte for abstract
     * namespace bind addresses. Rest of the sun_path can also have null
     * characters. */
    bool abs_ns;

    /* acceptor fields */
    struct sockaddr_un bind_addr; /* set by bind() */
    acceptor_t* acceptor;         /* created by listen */

    /* host read-write event management fields */
    myst_sock_t* host_socketpair[2]; /* only used for state management */
    state_t state;                   /* read-write enablement state */

    /* synchronization between acceptor/socket and peers */
    myst_cond_t cond;
    myst_mutex_t mutex;

    _Atomic(size_t) ref_count;

    /* Initially one: incremented by dup() and decremented by close() */
    size_t dup_count;
} myst_sock_shared_t;

struct myst_sock
{
    myst_sock_t* prev; /* must align with myst_list_node_t.prev */
    myst_sock_t* next; /* must align with myst_list_node_t.next */

    myst_sock_shared_t* shared;
    bool cloexec; /* whether to close this socket on execv() */
};

static acceptor_t _acceptors[MAX_ACCEPTORS];
static size_t _num_acceptors;
static myst_mutex_t _acceptor_lock;

static size_t _min(size_t x, size_t y)
{
    return x < y ? x : y;
}

static size_t _max(size_t x, size_t y)
{
    return x > y ? x : y;
}

MYST_INLINE void _lock(myst_mutex_t* lock, bool* locked)
{
    myst_mutex_lock(lock);
    *locked = true;
}

MYST_INLINE void _unlock(myst_mutex_t* lock, bool* locked)
{
    if (*locked)
    {
        myst_mutex_unlock(lock);
        *locked = false;
    }
}

static int _lookup_acceptor(const char* sun_path, acceptor_t** acceptor_out)
{
    int ret = 0;
    acceptor_t* acceptor = NULL;

    *acceptor_out = NULL;

    myst_mutex_lock(&_acceptor_lock);

    for (size_t i = 0; i < _num_acceptors; i++)
    {
        if ((sun_path[0] != 0
                 ? strcmp(_acceptors[i].sun_path, sun_path)
                 : memcmp(_acceptors[i].sun_path, sun_path, SUN_PATH_SIZE)) ==
            0)
        {
            acceptor = &_acceptors[i];
            break;
        }
    }

    if (!acceptor)
        ERAISE(-ESRCH);

    *acceptor_out = acceptor;

done:
    myst_mutex_unlock(&_acceptor_lock);

    return ret;
}

static int _release_acceptor(acceptor_t* acceptor)
{
    int ret = 0;

    myst_mutex_lock(&_acceptor_lock);

    for (size_t i = 0; i < _num_acceptors; i++)
    {
        if (&_acceptors[i] == acceptor)
        {
            /* the last acceptor in the array is moved to the released slot, and
             * the total number of acceptors is decremented by one. We can move
             * the acceptor because direct pointers to acceptors are not shared.
             * All lookups are performed by iterating the array and comparing
             * the sun_path attribute */
            _acceptors[i] = _acceptors[_num_acceptors - 1];
            _num_acceptors--;

            myst_cond_destroy(&acceptor->cond);
            myst_mutex_destroy(&acceptor->mutex);
            memset(acceptor, 0, sizeof(acceptor_t));
            break;
        }
    }

    myst_mutex_unlock(&_acceptor_lock);

    return ret;
}

static int _create_acceptor(const char* sun_path, acceptor_t** acceptor_out)
{
    int ret = 0;
    acceptor_t* acceptor = NULL;

    *acceptor_out = NULL;

    if (strlen(sun_path) >= SUN_PATH_SIZE)
        ERAISE(-ENAMETOOLONG);

    myst_mutex_lock(&_acceptor_lock);

    if (_num_acceptors == MAX_ACCEPTORS)
        ERAISE(-ERANGE);

    acceptor = &_acceptors[_num_acceptors];
    memset(acceptor, 0, sizeof(acceptor_t));
    myst_cond_init(&acceptor->cond);   /* cannot fail when arg is non-null */
    myst_mutex_init(&acceptor->mutex); /* cannot fail when arg is non-null */
    memcpy(acceptor->sun_path, sun_path, SUN_PATH_SIZE);

    *acceptor_out = acceptor;
    acceptor = NULL;
    _num_acceptors++;

done:
    myst_mutex_unlock(&_acceptor_lock);

    return ret;
}

static int _create_uds_file(const char* path)
{
    long ret = 0;
    const int mode = 0666;
    int fd = -1;

    if ((fd = creat(path, mode)) < 0)
        ERAISE(-errno);

done:

    if (fd >= 0)
        close(fd);

    return ret;
}

MYST_INLINE struct shared* _obj(const myst_sock_t* sock)
{
    return sock->shared;
}

MYST_INLINE bool _valid_sock(const myst_sock_t* sock)
{
    return sock && _obj(sock)->magic == MAGIC;
}

MYST_INLINE void _ref_sock(myst_sock_shared_t* sock)
{
    if (sock)
        sock->ref_count++;
}

MYST_INLINE void _unref_sock(myst_sock_shared_t* sock)
{
    if (sock && --sock->ref_count == 0)
    {
        myst_cond_destroy(&sock->cond);
        myst_mutex_destroy(&sock->mutex);
        myst_buf_release(&sock->buf);

        memset(sock, 0, sizeof(struct shared));
        free(sock);
    }
}

MYST_INLINE void _free_and_unref_sock(myst_sock_t* sock)
{
    _unref_sock(sock->shared);
    memset(sock, 0, sizeof(myst_sock_t));
    free(sock);
}

/* create a host-side socket pair just for managing events */
static int _new_host_socketpair(bool nonblock, myst_sock_t* host_socketpair[2])
{
    int ret = 0;
    myst_sockdev_t* sockdev = myst_sockdev_get();
    myst_sock_t* sv[2];
    int type = SOCK_STREAM;

    if (nonblock)
        type |= SOCK_NONBLOCK;

    /* create the socket pair */
    ECHECK((sockdev->sd_socketpair)(sockdev, AF_LOCAL, type, 0, sv));

    /* make the send buffer as small as possible */
    {
        const size_t size = 1; /* will be rounded up */

        ECHECK((sockdev->sd_setsockopt)(
            sockdev, sv[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)));
        ECHECK((sockdev->sd_setsockopt)(
            sockdev, sv[1], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)));
    }

    /* make both ends of the socket pair non-blocking */
    {
        int val = 1;
        ECHECK((sockdev->sd_ioctl)(sockdev, sv[0], FIONBIO, (long)&val));
        ECHECK((sockdev->sd_ioctl)(sockdev, sv[1], FIONBIO, (long)&val));
    }

    host_socketpair[0] = sv[0];
    host_socketpair[1] = sv[1];
    sv[0] = NULL;
    sv[1] = NULL;

done:

    if (sv[0])
        (*sockdev->sd_close)(sockdev, sv[0]);

    if (sv[1])
        (*sockdev->sd_close)(sockdev, sv[1]);

    return ret;
}

static int _new_sock(
    bool nonblock,
    bool cloexec,
    int type,
    myst_sock_t** sock_out)
{
    int ret = 0;
    myst_sock_t* sock = NULL;
    T(printf(">>>> [%d] %s(): enter\n", myst_getpid(), __FUNCTION__);)
    if (!sock_out)
        ERAISE(-EINVAL);

    if (!(sock = calloc(1, sizeof(myst_sock_t))))
        ERAISE(-ENOMEM);

    if (!(sock->shared = calloc(1, sizeof(struct shared))))
        ERAISE(-ENOMEM);

    ECHECK(_new_host_socketpair(nonblock, _obj(sock)->host_socketpair));

    _obj(sock)->magic = MAGIC;
    _obj(sock)->peer = NULL;
    _obj(sock)->acceptor = NULL;
    _obj(sock)->state = STATE_WR_ENABLED;
    _obj(sock)->nonblock = nonblock;
    sock->cloexec = cloexec;
    _obj(sock)->so_sndbuf = DEFAULT_SO_SNDBUF;
    _obj(sock)->so_rcvbuf = DEFAULT_SO_RCVBUF;
    _obj(sock)->ref_count = 1;
    _obj(sock)->dup_count = 1;

    if ((type & SOCK_STREAM))
        _obj(sock)->so_type = SOCK_STREAM;
    else if ((type & SOCK_DGRAM))
        _obj(sock)->so_type = SOCK_DGRAM;

    *sock_out = sock;
    sock = NULL;

done:

    if (sock)
    {
        if (sock->shared)
            free(sock->shared);

        free(sock);
    }

    return ret;
}

/* write to the host socket until it is full */
static int _fill_host_sock(myst_sock_t* host_sock)
{
    int ret = 0;
    char* buf = NULL;
    const size_t len = 4096;
    size_t total = 0;

    if (!(buf = calloc(len, 1)))
        ERAISE(-ENOMEM);

    for (;;)
    {
        myst_sockdev_t* sockdev = myst_sockdev_get();
        ssize_t n = (*sockdev->sd_write)(sockdev, host_sock, buf, len);

        if (n == -EAGAIN)
        {
            /* host send buffer is not full */
            goto done;
        }

        ECHECK(n);
        total += n;
    }

done:

    if (buf)
        free(buf);

    return ret;
}

/* read from the host socket until it is empty */
static int _empty_host_sock(myst_sock_t* host_sock)
{
    int ret = 0;
    char* buf = NULL;
    const size_t len = 4096;
    size_t total = 0;

    if (!(buf = calloc(len, 1)))
        ERAISE(-ENOMEM);

    for (;;)
    {
        myst_sockdev_t* sockdev = myst_sockdev_get();
        ssize_t n = (*sockdev->sd_read)(sockdev, host_sock, buf, len);

        if (n == -EAGAIN)
        {
            /* host send buffer is not full */
            goto done;
        }

        ECHECK(n);
        total += n;
    }

done:

    if (buf)
        free(buf);

    return ret;
}

static void _set_state(myst_sock_shared_t* sock, bool writable, bool readable)
{
    if (writable && readable)
    {
        sock->state = STATE_RDWR_ENABLED;
    }
    else if (!writable && readable)
    {
        sock->state = STATE_RD_ENABLED;
    }
    else if (writable && !readable)
    {
        sock->state = STATE_WR_ENABLED;
    }
    else if (!writable && !readable)
    {
        sock->state = STATE_NONE_ENABLED;
    }
}

static int _do_state_transition(myst_sock_shared_t* sock)
{
    int ret = 0;
    bool peer_locked = false;
    myst_sock_shared_t* peer = sock->peer;

    T(printf(">>>> %s(sock=%p peer=%p): enter\n", __FUNCTION__, sock, peer);)

    if (!peer)
        ERAISE(-ENOTCONN);

    _lock(&peer->mutex, &peer_locked);
    const bool writable = (peer->buf.size != BUF_SIZE);
    const bool readable = (sock->buf.size > 0);

    switch (sock->state)
    {
        // STATE_WR_ENABLED    [ ][ ]
        case STATE_WR_ENABLED: /* write-empty and read-empty */
        {
            if (!writable)
            {
                ECHECK(_fill_host_sock(sock->host_socketpair[0]));
            }

            if (readable)
            {
                ECHECK(_fill_host_sock(sock->host_socketpair[1]));
            }

            _set_state(sock, writable, readable);
            break;
        }
        // STATE_RD_ENABLED    [X][X]
        case STATE_RD_ENABLED: /* write-full and read-full */
        {
            if (writable)
            {
                ECHECK(_empty_host_sock(sock->host_socketpair[1]));
            }

            if (!readable)
            {
                ECHECK(_empty_host_sock(sock->host_socketpair[0]));
            }

            _set_state(sock, writable, readable);
            break;
        }
        // STATE_RDWR_ENABLED  [ ][X]
        case STATE_RDWR_ENABLED: /* write-empty and read-full */
        {
            if (!writable)
            {
                ECHECK(_fill_host_sock(sock->host_socketpair[0]));
            }

            if (!readable)
            {
                ECHECK(_empty_host_sock(sock->host_socketpair[0]));
            }

            _set_state(sock, writable, readable);
            break;
        }
        // STATE_NONE          [X][ ]
        case STATE_NONE_ENABLED:
        {
            if (writable)
            {
                ECHECK(_empty_host_sock(sock->host_socketpair[1]));
            }

            if (readable)
            {
                ECHECK(_fill_host_sock(sock->host_socketpair[1]));
            }

            _set_state(sock, writable, readable);
            break;
        }
    }

    _unlock(&peer->mutex, &peer_locked);

done:

    if (peer)
        _unlock(&peer->mutex, &peer_locked);

    T(printf(">>>> %s(): ret=%d\n", __FUNCTION__, ret);)

    return ret;
}

static bool _supported_msg_flags(int msg_flags)
{
    const int mask = MSG_NOSIGNAL;
    return ((msg_flags & ~mask) == 0);
}

static ssize_t _send(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    const void* buf,
    size_t count,
    int flags)
{
    int ret = 0;
    bool locked = false;
    myst_sock_shared_t* peer = NULL;
    size_t nwritten = 0;

    T(printf(
          ">>>> [%d] %s(sock_shared=%p): enter: count=%zu\n",
          myst_getpid(),
          __FUNCTION__,
          sock->shared,
          count);)

    if (!dev || !_valid_sock(sock) || (!buf && count))
        ERAISE(-EINVAL);

    if (!_supported_msg_flags(flags))
    {
        MYST_ELOG("Unix-domain send flags not supported: 0x%x", flags);
        ERAISE(-ENOTSUP);
    }

    if (!_obj(sock)->peer)
        ERAISE(-ENOTCONN);

    if (count == 0)
        goto done;

    peer = _obj(sock)->peer;

    _lock(&peer->mutex, &locked);
    {
        const uint8_t* ptr = buf;
        size_t rem = count;

        while (rem > 0)
        {
            const size_t space = BUF_SIZE - peer->buf.size;
            const size_t min = _min(rem, space);
            int wait_ret = 0;

            if (min) /* if the buffer has any space */
            {
                if (myst_buf_append(&peer->buf, ptr, min) < 0)
                    ERAISE(-ENOMEM);
                rem -= min;
                ptr += min;
                nwritten += min;

                ECHECK(_do_state_transition(_obj(sock)));
                ECHECK(_do_state_transition(peer));

                /* signal the peer that there is something to read */
                myst_cond_signal(&peer->cond, FUTEX_BITSET_MATCH_ANY);
            }
            else /* the buffer is full */
            {
                if (_obj(sock)->nonblock)
                {
                    if (nwritten == 0)
                    {
                        ECHECK(_do_state_transition(_obj(sock)));
                        ECHECK(_do_state_transition(peer));
                        ERAISE(-EAGAIN);
                    }

                    break;
                }
                else
                {
                    /* break out if peer has closed */
                    if (peer->closed)
                        break;

                    /* wait for pipe to become write enabled or closed */
                    wait_ret = myst_cond_wait_no_signal_processing(
                        &peer->cond, &peer->mutex);
                }
            }

            if (wait_ret == -EINTR)
            {
                if (nwritten == 0)
                    ERAISE(-EINTR);

                break;
            }
        }
    }
    _unlock(&peer->mutex, &locked);

    ret = nwritten;

done:

    if (peer)
        _unlock(&peer->mutex, &locked);

    T(printf(">>>> %s(): ret=%d\n", __FUNCTION__, ret);)
    return ret;
}

static ssize_t _recv(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    void* buf,
    size_t count,
    int flags)
{
    int ret = 0;
    bool locked = false;
    ssize_t nread = 0;
    myst_sock_shared_t* peer;

    T(printf(
          ">>>> [%d] %s(sock=%p): enter: count=%zu\n",
          myst_getpid(),
          __FUNCTION__,
          sock->shared,
          count);)

    if (!dev || !_valid_sock(sock) || (!buf && count))
        ERAISE(-EINVAL);

    if (!_supported_msg_flags(flags))
    {
        MYST_ELOG("Unix-domain recv flags not supported: 0x%x", flags);
        ERAISE(-ENOTSUP);
    }

    if (count == 0)
        goto done;

    if (!_obj(sock)->peer)
        ERAISE(-ENOTCONN);

    peer = _obj(sock)->peer;

    _lock(&_obj(sock)->mutex, &locked);
    {
        uint8_t* ptr = buf;
        size_t rem = count;

        while (rem > 0)
        {
            size_t min = _min(rem, _obj(sock)->buf.size);
            int wait_ret = 0;

            if (min) /* there is data in the buffer */
            {
                memcpy(ptr, _obj(sock)->buf.data, min);
                if (myst_buf_remove(&_obj(sock)->buf, 0, min) < 0)
                    ERAISE(-EINVAL);
                rem -= min;
                ptr += min;
                nread += min;

                ECHECK(_do_state_transition(_obj(sock)));
                ECHECK(_do_state_transition(peer));

                /* signal that pipe is now write enabled */
                myst_cond_signal(&_obj(sock)->cond, FUTEX_BITSET_MATCH_ANY);
            }
            else /* the buffer is empty */
            {
                /* break out if peer has closed the connection */
                if (_obj(sock)->closed)
                    break;

                if (_obj(sock)->nonblock)
                {
                    if (nread == 0)
                    {
                        ECHECK(_do_state_transition(_obj(sock)));
                        ECHECK(_do_state_transition(peer));
                        ERAISE(-EAGAIN);
                    }

                    break;
                }
                else
                {
                    /* block here until pipe becomes read enabled */
                    wait_ret = myst_cond_wait_no_signal_processing(
                        &_obj(sock)->cond, &_obj(sock)->mutex);
                }
            }

            if (nread > 0)
            {
                break;
            }

            if (wait_ret == -EINTR)
                ERAISE(-EINTR);
        }
    }
    _unlock(&_obj(sock)->mutex, &locked);

    ret = nread;

done:

    _unlock(&_obj(sock)->mutex, &locked);

    T(printf(">>>> %s(): ret=%d\n", __FUNCTION__, ret);)
    return ret;
}

static int _udsdev_socket(
    myst_sockdev_t* dev,
    int domain,
    int type,
    int protocol,
    myst_sock_t** sock_out)
{
    int ret = 0;
    myst_sock_t* sock = NULL;

    if (sock_out)
        *sock_out = NULL;

    if (!dev || !sock_out)
        ERAISE(-EINVAL);

    if (domain != AF_UNIX && domain != AF_LOCAL)
        ERAISE(-ENOTSUP);

    if (!(type & SOCK_STREAM) && !(type & SOCK_DGRAM))
        ERAISE(-ENOTSUP);

    if (protocol != 0)
        ERAISE(-ENOTSUP);

    const bool nonblock = (type & SOCK_NONBLOCK);
    const bool cloexec = (type & SOCK_CLOEXEC);
    ECHECK(_new_sock(nonblock, cloexec, type, &sock));

    *sock_out = sock;
    sock = NULL;

done:

    if (sock)
        _free_and_unref_sock(sock);

    T(printf(">>>> %s(): ret=%d\n", __FUNCTION__, ret);)
    return ret;
}

static int _udsdev_bind(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    const struct sockaddr* addr,
    socklen_t addrlen)
{
    int ret = 0;
    const struct sockaddr_un* sun = (const struct sockaddr_un*)addr;
    int fd = -1;

    if (!dev || !_valid_sock(sock) || !addr || !addrlen)
        ERAISE(-EINVAL);

    if (addrlen <= MYST_OFFSETOF(struct sockaddr_un, sun_path))
        ERAISE(-EINVAL);

    if (addrlen > sizeof(struct sockaddr_un))
        ERAISE(-EINVAL);

    /* fail if socket is already bound to an address */
    if (_obj(sock)->abs_ns || *_obj(sock)->bind_addr.sun_path)
        ERAISE(-EINVAL);

    if (*sun->sun_path != '\0')
    {
        /* raise EADDRINUSE if file already exists */
        {
            struct stat statbuf;

            if (myst_syscall_stat(sun->sun_path, &statbuf) == 0)
                ERAISE(-EADDRINUSE);
        }

        /* create the UDS file (contains the connection id) */
        ECHECK(_create_uds_file(sun->sun_path));
    }
    else // abstract namespace case
    {
        /* raise EADDRINUSE if abstract namespace name already used */
        {
            acceptor_t* acceptor = NULL;
            if (!_lookup_acceptor(sun->sun_path, &acceptor))
            {
                ERAISE(-EADDRINUSE);
            }
        }
        _obj(sock)->abs_ns = true;
    }

    /* save the bind address */
    memset(&_obj(sock)->bind_addr, 0, sizeof(_obj(sock)->bind_addr));
    memcpy(&_obj(sock)->bind_addr, sun, sizeof(_obj(sock)->bind_addr));

done:

    if (fd >= 0)
        close(fd);

    return ret;
}

static int _udsdev_listen(myst_sockdev_t* dev, myst_sock_t* sock, int backlog)
{
    int ret = 0;

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* if bind() has not been called yet */
    if (!_obj(sock)->abs_ns && *_obj(sock)->bind_addr.sun_path == '\0')
        ERAISE(-EOPNOTSUPP);

    ECHECK(_create_acceptor(
        _obj(sock)->bind_addr.sun_path, &_obj(sock)->acceptor));
    (void)backlog;

done:

    return ret;
}

static int _udsdev_connect(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    const struct sockaddr* addr,
    socklen_t addrlen)
{
    int ret = 0;
    const struct sockaddr_un* sun = (const struct sockaddr_un*)addr;
    acceptor_t* acceptor = NULL;

    if (!dev || !_valid_sock(sock) || !addr)
        ERAISE(-EINVAL);

    if (sun->sun_family != AF_LOCAL)
        ERAISE(-EINVAL);

    if (addrlen <= MYST_OFFSETOF(struct sockaddr_un, sun_path))
        ERAISE(-EINVAL);

    if (addrlen > sizeof(struct sockaddr_un))
        ERAISE(-EINVAL);

    /* if this socket already has a peer */
    if (_obj(sock)->peer)
        ERAISE(-EINVAL);

    /* if this socket is already on an acceptor list */
    if (sock->next)
        ERAISE(-EINVAL);

    /* lookup the acceptor for this connection */
    if (_lookup_acceptor(sun->sun_path, &acceptor) != 0)
        ERAISE(-ECONNREFUSED);

    /* enqueue this socket on the acceptor's list */
    myst_mutex_lock(&acceptor->mutex);
    {
        /* append to acceptor's list */
        myst_list_append(&acceptor->list, (myst_list_node_t*)sock);

        /* wake the acceptor to handle this connection */
        myst_cond_signal(&acceptor->cond, FUTEX_BITSET_MATCH_ANY);
    }
    myst_mutex_unlock(&acceptor->mutex);

    /* wait for connection to be accepted */
    myst_mutex_lock(&_obj(sock)->mutex);
    {
        /* wait for acceptor to set the peer */
        while (!_obj(sock)->peer)
        {
            myst_cond_wait(&_obj(sock)->cond, &_obj(sock)->mutex);
        }
    }
    myst_mutex_unlock(&_obj(sock)->mutex);

done:

    T(printf(">>>> %s(): ret=%d\n", __FUNCTION__, ret);)
    return ret;
}

static int _udsdev_accept4(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    struct sockaddr* addr,
    socklen_t* addrlen,
    int flags,
    myst_sock_t** new_sock_out)
{
    int ret = 0;
    bool locked = false;
    myst_sock_t* sv[2] = {NULL, NULL};

    if (!dev || !_valid_sock(sock) || !new_sock_out)
        ERAISE(-EINVAL);

    /* if listen() has not been called */
    if (!_obj(sock)->acceptor)
        ERAISE(-EINVAL);

    acceptor_t* acceptor = _obj(sock)->acceptor;

    /* wait here to accept a connection */
    _lock(&acceptor->mutex, &locked);
    {
        /* wait for a connection attempt */
        while (!acceptor->list.head)
        {
            int r = myst_cond_wait(&acceptor->cond, &acceptor->mutex);

            if (r == -EINTR)
                ERAISE(r);
        }

        if (acceptor->list.head)
        {
            /* remove the socket at the head of this list */
            sv[0] = (myst_sock_t*)acceptor->list.head;
            myst_list_remove(&acceptor->list, acceptor->list.head);
        }
    }
    _unlock(&acceptor->mutex, &locked);

    /* handle the accepted connection if any */
    if (sv[0])
    {
        /* create a new socket structure */
        const bool nonblock = (flags & SOCK_NONBLOCK);
        const bool cloexec = (flags & SOCK_CLOEXEC);
        ECHECK(_new_sock(nonblock, cloexec, SOCK_STREAM, &sv[1]));

        /* tie these two socket peers together */
        _ref_sock(_obj(sv[0])->peer = _obj(sv[1]));
        _ref_sock(_obj(sv[1])->peer = _obj(sv[0]));

        /* set the address */
        if (addr && addrlen)
        {
            struct sockaddr_un* sun = (struct sockaddr_un*)addr;

            if (*addrlen >= SUN_FAMILY_SIZE)
                sun->sun_family = AF_LOCAL;

            if (*addrlen > SUN_FAMILY_SIZE)
                *addrlen = SUN_FAMILY_SIZE;
        }

        /* set the output socket and return success */
        *new_sock_out = sv[1];
    }

    /* signal the peer that the connection has been accepted */
    if (sv[0] && sv[1])
    {
        myst_mutex_lock(&_obj(sv[0])->mutex);
        myst_cond_signal(&_obj(sv[0])->cond, FUTEX_BITSET_MATCH_ANY);
        myst_mutex_unlock(&_obj(sv[0])->mutex);
    }

done:

    if (acceptor)
        _unlock(&acceptor->mutex, &locked);

    T(printf(">>>> %s(): ret=%d\n", __FUNCTION__, ret);)
    return ret;
}

static int _udsdev_getsockopt(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    int level,
    int optname,
    void* optval,
    socklen_t* optlen)
{
    int ret = 0;

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (level != SOL_SOCKET)
        ERAISE(-EINVAL);

    switch (optname)
    {
        case SO_REUSEADDR:
        {
            if (!optval || !optlen)
                ERAISE(-EINVAL);

            switch (*optlen)
            {
                case sizeof(uint8_t):
                    *(uint8_t*)optval = _obj(sock)->so_reuseaddr;
                    break;
                case sizeof(uint16_t):
                    *(uint16_t*)optval = _obj(sock)->so_reuseaddr;
                    break;
                case sizeof(uint32_t):
                    *(uint32_t*)optval = _obj(sock)->so_reuseaddr;
                    break;
                case sizeof(uint64_t):
                    *(uint64_t*)optval = _obj(sock)->so_reuseaddr;
                    break;
                default:
                {
                    ERAISE(-EINVAL);
                    break;
                }
            }

            break;
        }
        case SO_SNDBUF:
        {
            if (!optval || !optlen)
                ERAISE(-EINVAL);

            switch (*optlen)
            {
                case sizeof(uint8_t):
                    *(uint8_t*)optval = _obj(sock)->so_sndbuf;
                    break;
                case sizeof(uint16_t):
                    *(uint16_t*)optval = _obj(sock)->so_sndbuf;
                    break;
                case sizeof(uint32_t):
                    *(uint32_t*)optval = _obj(sock)->so_sndbuf;
                    break;
                case sizeof(uint64_t):
                    *(uint64_t*)optval = _obj(sock)->so_sndbuf;
                    break;
                default:
                {
                    ERAISE(-EINVAL);
                    break;
                }
            }

            break;
        }
        case SO_RCVBUF:
        {
            if (!optval || !optlen)
                ERAISE(-EINVAL);

            switch (*optlen)
            {
                case sizeof(uint8_t):
                    *(uint8_t*)optval = _obj(sock)->so_rcvbuf;
                    break;
                case sizeof(uint16_t):
                    *(uint16_t*)optval = _obj(sock)->so_rcvbuf;
                    break;
                case sizeof(uint32_t):
                    *(uint32_t*)optval = _obj(sock)->so_rcvbuf;
                    break;
                case sizeof(uint64_t):
                    *(uint64_t*)optval = _obj(sock)->so_rcvbuf;
                    break;
                default:
                {
                    ERAISE(-EINVAL);
                    break;
                }
            }

            break;
        }
        case SO_TYPE:
        {
            if (!optval || !optlen)
                ERAISE(-EINVAL);

            switch (*optlen)
            {
                case sizeof(uint8_t):
                    *(uint8_t*)optval = _obj(sock)->so_type;
                    break;
                case sizeof(uint16_t):
                    *(uint16_t*)optval = _obj(sock)->so_type;
                    break;
                case sizeof(uint32_t):
                    *(uint32_t*)optval = _obj(sock)->so_type;
                    break;
                case sizeof(uint64_t):
                    *(uint64_t*)optval = _obj(sock)->so_type;
                    break;
                default:
                {
                    ERAISE(-EINVAL);
                    break;
                }
            }

            *optlen = sizeof(int);
            break;
        }
        default:
        {
            MYST_ELOG("unsupported optname: %d\n", optname);
            ERAISE(-ENOTSUP);
        }
    }

done:
    return ret;
}

static int _udsdev_setsockopt(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    int level,
    int optname,
    const void* optval,
    socklen_t optlen)
{
    int ret = 0;

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (level != SOL_SOCKET)
        ERAISE(-EINVAL);

    switch (optname)
    {
        case SO_REUSEADDR:
        {
            if (!optval)
                ERAISE(-EINVAL);

            switch (optlen)
            {
                case sizeof(uint8_t):
                    _obj(sock)->so_reuseaddr = *(uint8_t*)optval;
                    break;
                case sizeof(uint16_t):
                    _obj(sock)->so_reuseaddr = *(uint16_t*)optval;
                    break;
                case sizeof(uint32_t):
                    _obj(sock)->so_reuseaddr = *(uint32_t*)optval;
                    break;
                case sizeof(uint64_t):
                    _obj(sock)->so_reuseaddr = *(uint64_t*)optval;
                    break;
                default:
                {
                    ERAISE(-EINVAL);
                    break;
                }
            }

            if (_obj(sock)->so_reuseaddr)
                _obj(sock)->so_reuseaddr = 1;

            break;
        }
        case SO_SNDBUF:
        {
            if (!optval)
                ERAISE(-EINVAL);

            switch (optlen)
            {
                case sizeof(uint8_t):
                    _obj(sock)->so_sndbuf = *(uint8_t*)optval;
                    break;
                case sizeof(uint16_t):
                    _obj(sock)->so_sndbuf = *(uint16_t*)optval;
                    break;
                case sizeof(uint32_t):
                    _obj(sock)->so_sndbuf = *(uint32_t*)optval;
                    break;
                case sizeof(uint64_t):
                    _obj(sock)->so_sndbuf = *(uint64_t*)optval;
                    break;
                default:
                {
                    ERAISE(-EINVAL);
                    break;
                }
            }

            _obj(sock)->so_sndbuf = _max(_obj(sock)->so_sndbuf, MIN_SO_SNDBUF);
            break;
        }
        case SO_RCVBUF:
        {
            if (!optval)
                ERAISE(-EINVAL);

            switch (optlen)
            {
                case sizeof(uint8_t):
                    _obj(sock)->so_rcvbuf = *(uint8_t*)optval;
                    break;
                case sizeof(uint16_t):
                    _obj(sock)->so_rcvbuf = *(uint16_t*)optval;
                    break;
                case sizeof(uint32_t):
                    _obj(sock)->so_rcvbuf = *(uint32_t*)optval;
                    break;
                case sizeof(uint64_t):
                    _obj(sock)->so_rcvbuf = *(uint64_t*)optval;
                    break;
                default:
                {
                    ERAISE(-EINVAL);
                    break;
                }
            }

            _obj(sock)->so_rcvbuf = _max(_obj(sock)->so_rcvbuf, MIN_SO_RCVBUF);
            break;
        }
        default:
        {
            MYST_ELOG("unsupported optname: %d\n", optname);
            ERAISE(-ENOTSUP);
        }
    }

done:
    return ret;
}

static int _udsdev_target_fd(myst_sockdev_t* dev, myst_sock_t* sock)
{
    int ret = 0;
    myst_sockdev_t* sockdev = myst_sockdev_get();

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    myst_sock_t* hsock = _obj(sock)->host_socketpair[0];
    ECHECK(ret = (*sockdev->sd_target_fd)(dev, hsock));

done:
    return ret;
}

static int _udsdev_fstat(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    struct stat* statbuf)
{
    int ret = 0;
    myst_sockdev_t* sockdev = myst_sockdev_get();

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    myst_sock_t* hsock = _obj(sock)->host_socketpair[0];
    ECHECK(ret = (*sockdev->sd_fstat)(dev, hsock, statbuf));

done:
    return ret;
}

static ssize_t _udsdev_sendto(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    const void* buf,
    size_t len,
    int flags,
    const struct sockaddr* dest_addr,
    socklen_t addrlen)
{
    return _send(dev, sock, buf, len, flags);
}

static ssize_t _udsdev_recvfrom(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    void* buf,
    size_t len,
    int flags,
    struct sockaddr* src_addr,
    socklen_t* addrlen)
{
    return _recv(dev, sock, buf, len, flags);
}

static ssize_t _udsdev_read(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    void* buf,
    size_t count)
{
    return _recv(dev, sock, buf, count, 0);
}

static ssize_t _udsdev_write(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    const void* buf,
    size_t count)
{
    return _send(dev, sock, buf, count, 0);
}

static ssize_t _udsdev_readv(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    ret = myst_fdops_readv(&dev->fdops, sock, iov, iovcnt);
    ECHECK(ret);

done:
    return ret;
}

static ssize_t _udsdev_writev(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    ret = myst_fdops_writev(&dev->fdops, sock, iov, iovcnt);
    ECHECK(ret);

done:
    return ret;
}

static int _udsdev_close(myst_sockdev_t* dev, myst_sock_t* sock)
{
    int ret = 0;
    T(printf(
          ">>>> [%d] %s(sock_shared=%p): enter\n",
          myst_getpid(),
          __FUNCTION__,
          sock->shared);)

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* notify the peer that the socket is closing */
    myst_mutex_lock(&_obj(sock)->mutex);
    {
        if (sock->shared->dup_count > 1)
        {
            sock->shared->dup_count--;
            myst_mutex_unlock(&_obj(sock)->mutex);
            free(sock);
            goto done;
        }

        if (_obj(sock)->peer)
        {
            _obj(sock)->peer->closed = true;
            myst_cond_signal(&_obj(sock)->peer->cond, FUTEX_BITSET_MATCH_ANY);
            _unref_sock(_obj(sock)->peer);
        }
    }
    myst_mutex_unlock(&_obj(sock)->mutex);

    if (_obj(sock)->acceptor)
        _release_acceptor(_obj(sock)->acceptor);

    /* release the host-side sockets */
    {
        myst_sockdev_t* sockdev = myst_sockdev_get();

        if (_obj(sock)->host_socketpair[0])
            (*sockdev->sd_close)(sockdev, _obj(sock)->host_socketpair[0]);

        if (_obj(sock)->host_socketpair[1])
            (*sockdev->sd_close)(sockdev, _obj(sock)->host_socketpair[1]);
    }

    _free_and_unref_sock(sock);

done:

    T(printf(">>>> %s(): ret=%d\n", __FUNCTION__, ret);)
    return ret;
}

static int _udsdev_fcntl(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    int cmd,
    long arg)
{
    int ret = 0;

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    switch (cmd)
    {
        case F_GETFD:
        {
            if (sock->cloexec)
                ret |= FD_CLOEXEC;
            break;
        }
        case F_SETFD:
        {
            sock->cloexec = (arg & FD_CLOEXEC);
            break;
        }
        case F_GETFL:
        {
            if (_obj(sock)->nonblock)
                ret |= O_NONBLOCK;

            ret |= O_RDWR;
            break;
        }
        case F_SETFL:
        {
            _obj(sock)->nonblock = (arg & O_NONBLOCK);
            break;
        }
        default:
        {
            ret = -ENOTSUP;
            break;
        }
    }

done:

    return ret;
}

static int _udsdev_ioctl(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    unsigned long request,
    long arg)
{
    int ret = 0;

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    switch (request)
    {
        case FIONBIO:
        {
            const int* val = (const int*)arg;

            if (!val)
                ERAISE(-EINVAL);

            _obj(sock)->nonblock = (bool)*val;
            break;
        }
        case FIONREAD:
        {
            int* val = (int*)arg;

            if (!val)
                ERAISE(-EINVAL);

            *((int*)val) = _obj(sock)->buf.size;
            break;
        }
        default:
        {
            ERAISE(-ENOTSUP);
            break;
        }
    }

done:
    return ret;
}

static int _udsdev_dup(
    myst_sockdev_t* dev,
    const myst_sock_t* sock,
    myst_sock_t** sock_out)
{
    int ret = 0;
    myst_sock_t* new_sock = NULL;

    T(printf(
          ">>>> [%d] %s(sock_shared=%p): enter\n",
          myst_getpid(),
          __FUNCTION__,
          sock->shared);)

    if (*sock_out)
        *sock_out = NULL;

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (!(new_sock = calloc(1, sizeof(myst_sock_t))))
        ERAISE(-ENOMEM);

    new_sock->shared = sock->shared;
    new_sock->cloexec = false;

    myst_mutex_lock(&_obj(sock)->mutex);
    new_sock->shared->dup_count++;
    myst_mutex_unlock(&_obj(sock)->mutex);

    *sock_out = new_sock;
    new_sock = NULL;

done:

    if (new_sock)
        free(new_sock);

    return ret;
}

static int _udsdev_get_events(myst_sockdev_t* dev, myst_sock_t* sock)
{
    int ret = 0;

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    ret = -ENOTSUP;

done:
    return ret;
}

static int _udsdev_sendmsg(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    const struct msghdr* msg,
    int flags)
{
    int ret = 0;
    void* buf = NULL;
    ssize_t count;
    ssize_t n;

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (!msg)
        ERAISE(-EINVAL);

    /* ATTN: control data is not supported */
    if (msg->msg_control || msg->msg_controllen)
    {
        MYST_ELOG("AF_LOCAL control data unsuuported");
        ERAISE(-ENOTSUP);
    }

    if (msg->msg_iovlen != 1)
    {
        ERAISE((count = myst_iov_gather(msg->msg_iov, msg->msg_iovlen, &buf)));
    }
    else
    {
        buf = msg->msg_iov[0].iov_base;
        count = msg->msg_iov[0].iov_len;
    }

    ECHECK(n = _send(dev, sock, buf, count, flags));

    ret = n;

done:

    /* release the gather buffer if any */
    if (msg && msg->msg_iov[0].iov_base != buf)
        free(buf);

    return ret;
}

static int _udsdev_recvmsg(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    struct msghdr* msg,
    int flags)
{
    int ret = 0;
    size_t count;
    char* buf = NULL;
    ssize_t n;

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (!msg)
        ERAISE(-EINVAL);

    if ((flags & MSG_PEEK))
    {
        MYST_ELOG("AF_LOCAL MSG_PEEK unsuuported");
        ERAISE(-ENOTSUP);
    }

    /* ATTN: control data is not supported */
    if (msg->msg_control || msg->msg_controllen)
    {
        MYST_ELOG("AF_LOCAL control data unsuuported");
        ERAISE(-ENOTSUP);
    }

    ERAISE(count = myst_iov_len(msg->msg_iov, msg->msg_iovlen));

    if (!(buf = malloc(count)))
        ERAISE(-ENOMEM);

    ECHECK(n = _recv(dev, sock, buf, count, flags));

    ECHECK(myst_iov_scatter(msg->msg_iov, msg->msg_iovlen, buf, n));

    ret = n;

done:

    if (buf)
        free(buf);

    return ret;
}

static int _udsdev_shutdown(myst_sockdev_t* dev, myst_sock_t* sock, int how)
{
    int ret = 0;

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

done:
    return ret;
}

static int _udsdev_getpeername(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    struct sockaddr* addr,
    socklen_t* addrlen)
{
    int ret = 0;

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (addr && addrlen)
    {
        memset(addr, 0, *addrlen);

        if (*addrlen >= SUN_FAMILY_SIZE)
            ((struct sockaddr_un*)addr)->sun_family = AF_LOCAL;
    }

done:
    return ret;
}

static int _udsdev_getsockname(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    struct sockaddr* addr,
    socklen_t* addrlen)
{
    int ret = 0;

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (addr && addrlen)
    {
        memset(addr, 0, *addrlen);

        if (_obj(sock)->abs_ns || *_obj(sock)->bind_addr.sun_path)
        {
            size_t min = _min(*addrlen, sizeof(struct sockaddr_un));
            memcpy(addr, &_obj(sock)->bind_addr, min);

            if (min < *addrlen)
                *addrlen = min;
        }
        else
        {
            if (*addrlen >= SUN_FAMILY_SIZE)
                ((struct sockaddr_un*)addr)->sun_family = AF_LOCAL;
        }
    }

done:
    return ret;
}

static int _udsdev_socketpair(
    myst_sockdev_t* dev,
    int domain,
    int type,
    int protocol,
    myst_sock_t* pair[2])
{
    int ret = 0;
    myst_sock_t* sv[2] = {NULL, NULL};

    if (pair)
    {
        pair[0] = NULL;
        pair[1] = NULL;
    }

    if (!dev || !pair)
        ERAISE(-EINVAL);

    if (domain != AF_UNIX && domain != AF_LOCAL)
        ERAISE(-ENOTSUP);

    if (!(type & SOCK_STREAM) && !(type & SOCK_DGRAM))
        ERAISE(-ENOTSUP);

    const bool nonblock = (type & SOCK_NONBLOCK);
    const bool cloexec = (type & SOCK_CLOEXEC);
    ECHECK(_new_sock(nonblock, cloexec, type, &sv[0]));
    ECHECK(_new_sock(nonblock, cloexec, type, &sv[1]));
    _ref_sock(_obj(sv[0])->peer = _obj(sv[1]));
    _ref_sock(_obj(sv[1])->peer = _obj(sv[0]));

    pair[0] = sv[0];
    pair[1] = sv[1];
    sv[0] = NULL;
    sv[1] = NULL;

done:

    if (sv[0])
        _free_and_unref_sock(sv[0]);

    if (sv[1])
        _free_and_unref_sock(sv[1]);

    return ret;
}

myst_sockdev_t* myst_udsdev_get(void)
{
    // clang-format off
    static myst_sockdev_t _dev =
    {
        {
            .fd_read = (void*)_udsdev_read,
            .fd_write = (void*)_udsdev_write,
            .fd_readv = (void*)_udsdev_readv,
            .fd_writev = (void*)_udsdev_writev,
            .fd_fstat = (void*)_udsdev_fstat,
            .fd_fcntl = (void*)_udsdev_fcntl,
            .fd_ioctl = (void*)_udsdev_ioctl,
            .fd_dup = (void*)_udsdev_dup,
            .fd_close = (void*)_udsdev_close,
            .fd_target_fd = (void*)_udsdev_target_fd,
            .fd_get_events = (void*)_udsdev_get_events,
        },
        .sd_socket = _udsdev_socket,
        .sd_socketpair = _udsdev_socketpair,
        .sd_connect = _udsdev_connect,
        .sd_accept4 = _udsdev_accept4,
        .sd_bind = _udsdev_bind,
        .sd_listen = _udsdev_listen,
        .sd_sendto = _udsdev_sendto,
        .sd_recvfrom = _udsdev_recvfrom,
        .sd_sendmsg = _udsdev_sendmsg,
        .sd_recvmsg = _udsdev_recvmsg,
        .sd_shutdown = _udsdev_shutdown,
        .sd_getsockopt = _udsdev_getsockopt,
        .sd_setsockopt = _udsdev_setsockopt,
        .sd_getpeername = _udsdev_getpeername,
        .sd_getsockname = _udsdev_getsockname,
        .sd_read = _udsdev_read,
        .sd_write = _udsdev_write,
        .sd_readv = _udsdev_readv,
        .sd_writev = _udsdev_writev,
        .sd_fstat = _udsdev_fstat,
        .sd_fcntl = _udsdev_fcntl,
        .sd_ioctl = _udsdev_ioctl,
        .sd_dup = _udsdev_dup,
        .sd_close = _udsdev_close,
        .sd_target_fd = _udsdev_target_fd,
        .sd_get_events = _udsdev_get_events,
    };
    // clang-format on

    return &_dev;
}
