// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
**==============================================================================
**
** Unix-domain sockets
** ===================
**
** This module implements Unix-domain sockets (UDS), which are created with
** the AF_LOCAL or AF_UNIX socket domain (which are equivalent in Linux).
**
**     int sockfd = socket(AF_LOCAL, SOCK_STREAM, 0);
**     int sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
**     int sockfd = socket(AF_LOCAL, SOCK_STREAM, 0);
**     int sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
**
** UDS is subject to the following limitations.
**
**     - Works only between two pseudo processes within the same kernel image
**         - No support for host-to-kernel UDS
**         - No support for kernel-to-kernel UDS
**     - Only supports SOCK_STREAM and SOCK_DGRAM
**     - Does not support ancillary data (aka, control data)
**
** This implementation employs host-side sockets but adds a layer of encryption
** performed inside the kernel. Each read/write is encapsulated in one or more
** encrypted frames (see frame_t below). Frames are 512 bytes and contain the
** following elements.
**
**     - magic number (FRAME_DATA_MAGIC or FRAME_CONTROL_MAGIC)
**     - size (the size in bytes of the user payload data)
**     - payload (zero-padded buffer of user data)
**     - hash (the hash of the full payload, including any zero padding)
**
** A frame may be a "data frame" or a "control frame" as indicated by the
** magic number (control frames are experimental and disabled by default).
**
** It may take multiple frames to encode the user data being transmitted. Each
** 512-byte frame may encode at most 472 bytes of data (512 minus the 40-byte
** header). So 512 bytes of user data will require two frames:
**
**     Frame-1:
**         40-byte header
**         472 bytes of user data
**         0 bytes of padding
**     Frame-2:
**         40-byte header
**         40 bytes of user data
**         432 bytes of zero padding
**
** The SHA-256 hash is the hash of the full payload, including any zero padding.
**
** Frames are encrypted/decrypted with the AES-256-XTS cipher, which is
** currently the default cipher for Linux file block encryption. The
** initialization vector is given by a message "counter" maintained within the
** kernel. Each socket endpoint increments this counter during each encrypt or
** decrypt operation.
**
** A single key is used for the lifetime of the kernel image. The key is
** obtained by myst_tcall_random(), which eventually calls oe_random() in
** SGX (based on either the RDRAND or SDRAND instruction).
**
** The combination between the initialization vector and random key renders
** replay attacks ineffective. The hash of the payload is not strictly necessary
** but provides additional data integrity for detecting possible programming
** errors. It is not a security measure. If messages are replayed out of order,
** the decryption operation will fail, since the cipher operation incorporates
** an initialization vector (containing a monotonically increasing message
** counter).
**
**==============================================================================
*/

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <myst/crypt.h>
#include <myst/defs.h>
#include <myst/eraise.h>
#include <myst/hex.h>
#include <myst/iov.h>
#include <myst/once.h>
#include <myst/sha256.h>
#include <myst/sockdev.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/syslog.h>
#include <myst/tcall.h>
#include <myst/time.h>

#define MAGIC 0xd731a683

#define PAYLOAD_SIZE (512 - sizeof(uint64_t) - sizeof(myst_sha256_t))

#define FRAME_CONTROL_MAGIC 0x9ef92565
#define FRAME_DATA_MAGIC 0x3fd95160

typedef struct frame
{
    struct
    {
        uint32_t magic;
        uint32_t size;
        myst_sha256_t hash;
    } header;
    uint8_t payload[PAYLOAD_SIZE];
} frame_t;

MYST_STATIC_ASSERT(sizeof(frame_t) == 512);
MYST_STATIC_ASSERT(MYST_OFFSETOF(frame_t, payload) == 40);

struct myst_sock
{
    uint32_t magic;
    bool nonblock;
    myst_sock_t* impl;
    uint8_t inbuf[PAYLOAD_SIZE];
    size_t inbuf_size;
    char sun_path[PATH_MAX]; /* the socket file path if any */
    size_t counter;
};

static int _sha256(myst_sha256_t* sha256, const void* data, size_t size)
{
    int ret = 0;
    myst_sha256_ctx_t ctx;

    if (!sha256 || !data)
        ERAISE(-EINVAL);

    ECHECK(myst_sha256_start(&ctx));
    ECHECK(myst_sha256_update(&ctx, data, size));
    ECHECK(myst_sha256_finish(&ctx, sha256));

done:
    return ret;
}

/* get or generate the key to be used for UDS encryption */
static const myst_key_512_t* _get_key(void)
{
    myst_key_512_t* ret = NULL;
    static myst_key_512_t _key;
    static myst_key_512_t _zero_key;
    static int _initialized;
    static myst_spinlock_t _lock;

    myst_spin_lock(&_lock);
    {
        if (_initialized == 0)
        {
            if (myst_tcall_random(_key.data, sizeof(_key)) == 0 &&
                memcmp(&_key, &_zero_key, sizeof(_key)) != 0)
            {
                _initialized = 1;
                ret = &_key;
            }
        }
        else
        {
            ret = &_key;
        }
    }
    myst_spin_unlock(&_lock);

    return ret;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstack-usage="
static int _encrypt_frame(frame_t* frame, size_t counter)
{
#ifdef DISABLE_ENCRYPTION
    (void)counter;
    (void)_get_key;
    frame_t in = *frame;
    memcpy(frame, &in, sizeof(in));
    return 0;
#else
    const myst_key_512_t* key = _get_key();

    if (!key)
        return -ENOSYS;

    frame_t in = *frame;
    _sha256(&in.header.hash, in.payload, PAYLOAD_SIZE);

    return myst_tcall_encrypt_aes_256_xts(key, &in, frame, sizeof(in), counter);
#endif
}
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstack-usage="
static int _decrypt_frame(frame_t* frame, size_t counter)
{
    int ret = 0;
    const myst_key_512_t* key = _get_key();
    myst_sha256_t hash;
    frame_t in = *frame;

    if (!key)
        return -ENOSYS;

    if (myst_tcall_decrypt_aes_256_xts(key, &in, frame, sizeof(in), counter) !=
        0)
    {
        ERAISE(-EIO);
    }

    if (frame->header.magic != FRAME_DATA_MAGIC &&
        frame->header.magic != FRAME_CONTROL_MAGIC)
    {
        ERAISE(-EIO);
    }

    if (frame->header.size > PAYLOAD_SIZE)
    {
        ERAISE(-EIO);
    }

    if (_sha256(&hash, frame->payload, PAYLOAD_SIZE) != 0)
        ERAISE(-EIO);

    if (memcmp(&hash, &frame->header.hash, sizeof(hash)) != 0)
        ERAISE(-EIO);

done:
    return ret;
}
#pragma GCC diagnostic pop

MYST_INLINE bool _valid_sock(const myst_sock_t* sock)
{
    return sock && sock->magic == MAGIC;
}

static void _free_sock(myst_sock_t* sock)
{
    if (sock)
    {
        memset(sock, 0, sizeof(myst_sock_t));
        free(sock);
    }
}

static size_t _min(size_t x, size_t y)
{
    return (x < y) ? x : y;
}

static int _new_sock(bool nonblock, myst_sock_t* impl, myst_sock_t** sock_out)
{
    int ret = 0;
    myst_sock_t* sock = NULL;

    if (!sock_out)
        ERAISE(-EINVAL);

    if (!(sock = calloc(1, sizeof(myst_sock_t))))
        ERAISE(-ENOMEM);

    sock->magic = MAGIC;
    sock->nonblock = nonblock;
    sock->impl = impl;

    *sock_out = sock;
    sock = NULL;

done:

    if (sock)
        _free_sock(sock);

    return ret;
}

static ssize_t _read(
    myst_sock_t* sock,
    myst_sockdev_t* sockdev,
    myst_sock_t* sock_impl,
    void* buf,
    size_t len)
{
    ssize_t ret = 0;
    uint8_t* ptr = buf;
    size_t rem = len;
    size_t total = 0;
    frame_t* frame = NULL;

    if (!(frame = calloc(1, sizeof(frame_t))))
        ERAISE(-ENOMEM);

    /* if any bytes left over in the input buffer form previous call */
    if (rem > 0 && sock->inbuf_size > 0)
    {
        const size_t min = _min(rem, sock->inbuf_size);
        memcpy(ptr, sock->inbuf, min);
        memmove(sock->inbuf, &sock->inbuf[min], sock->inbuf_size - min);
        sock->inbuf_size -= min;

        ptr += min;
        rem -= min;
        total += min;
    }

    while (rem > 0)
    {
        ssize_t n;

        /* delegate to socket device */
        n = (*sockdev->sd_read)(sockdev, sock_impl, frame, sizeof(frame_t));

        if (n < 0)
        {
            if (total > 0)
            {
                ret = total;
                goto done;
            }

            ECHECK(n);
        }

        if (n == 0)
        {
            ret = total;
            goto done;
        }

        assert(n == sizeof(frame_t));
        ECHECK(_decrypt_frame(frame, sock->counter++));

        const size_t min = _min(rem, frame->header.size);
        memcpy(ptr, frame->payload, min);
        ptr += min;
        rem -= min;
        total += min;

        /* if there are unused bytes, then save them for later */
        if (min < frame->header.size)
        {
            sock->inbuf_size = frame->header.size - min;
            memcpy(sock->inbuf, &frame->payload[min], sock->inbuf_size);
        }
    }

    ret = total;

done:

    if (frame)
        free(frame);

    return ret;
}

static ssize_t _write(
    myst_sock_t* sock,
    myst_sockdev_t* sockdev,
    myst_sock_t* sock_impl,
    const void* buf,
    size_t len)
{
    ssize_t ret = 0;
    const uint8_t* ptr = buf;
    size_t rem = len;
    size_t total = 0;
    frame_t* frame = NULL;

    if (!(frame = calloc(1, sizeof(frame_t))))
        ERAISE(-ENOMEM);

    while (rem > 0)
    {
        size_t min = _min(rem, PAYLOAD_SIZE);
        ssize_t n;

        frame->header.magic = FRAME_DATA_MAGIC;
        frame->header.size = min;
        memcpy(frame->payload, ptr, min);
        memset(frame->payload + min, 0, PAYLOAD_SIZE - min);
        ECHECK(_encrypt_frame(frame, sock->counter++));

        /* delegate to socket device */
        n = (*sockdev->sd_write)(sockdev, sock_impl, frame, sizeof(frame_t));

        if (n < 0)
        {
            if (total > 0)
            {
                ret = total;
                goto done;
            }

            ECHECK(n);
        }

        if (n == 0)
        {
            ret = total;
            goto done;
        }

        assert(n == sizeof(frame_t));

        ptr += min;
        rem -= min;
        total += min;
    }

    ret = total;

done:

    if (frame)
        free(frame);

    return ret;
}

static ssize_t _recvfrom(
    myst_sock_t* sock,
    myst_sockdev_t* sockdev,
    myst_sock_t* sock_impl,
    void* buf,
    size_t len,
    int flags,
    struct sockaddr* src_addr,
    socklen_t* addrlen)
{
    ssize_t ret = 0;
    uint8_t* ptr = buf;
    size_t rem = len;
    size_t total = 0;
    frame_t* frame = NULL;

    if (!(frame = calloc(1, sizeof(frame_t))))
        ERAISE(-ENOMEM);

    /* if any bytes left over in the input buffer form previous call */
    if (rem > 0 && sock->inbuf_size > 0)
    {
        const size_t min = _min(rem, sock->inbuf_size);
        memcpy(ptr, sock->inbuf, min);
        memmove(sock->inbuf, &sock->inbuf[min], sock->inbuf_size - min);
        sock->inbuf_size -= min;

        ptr += min;
        rem -= min;
        total += min;
    }

    while (rem > 0)
    {
        ssize_t n;

        /* delegate to socket device */
        n = (*sockdev->sd_recvfrom)(
            sockdev,
            sock_impl,
            frame,
            sizeof(frame_t),
            flags,
            src_addr,
            addrlen);

        if (n < 0)
        {
            if (total > 0)
            {
                ret = total;
                goto done;
            }

            ECHECK(n);
        }

        if (n == 0)
        {
            ret = total;
            goto done;
        }

        assert(n == sizeof(frame_t));
        ECHECK(_decrypt_frame(frame, sock->counter++));

        const size_t min = _min(rem, frame->header.size);
        memcpy(ptr, frame->payload, min);
        ptr += min;
        rem -= min;
        total += min;

        /* if there are unused bytes, then save them for later */
        if (min < frame->header.size)
        {
            sock->inbuf_size = frame->header.size - min;
            memcpy(sock->inbuf, &frame->payload[min], sock->inbuf_size);
        }
    }

    ret = total;

done:

    if (frame)
        free(frame);

    return ret;
}

static ssize_t _sendto(
    myst_sock_t* sock,
    myst_sockdev_t* sockdev,
    myst_sock_t* sock_impl,
    const void* buf,
    size_t len,
    int flags,
    const struct sockaddr* dest_addr,
    socklen_t addrlen)
{
    ssize_t ret = 0;
    const uint8_t* ptr = buf;
    size_t rem = len;
    size_t total = 0;
    frame_t* frame = NULL;

    if (!(frame = calloc(1, sizeof(frame_t))))
        ERAISE(-ENOMEM);

    while (rem > 0)
    {
        size_t min = _min(rem, PAYLOAD_SIZE);
        ssize_t n;

        frame->header.magic = FRAME_DATA_MAGIC;
        frame->header.size = min;
        memcpy(frame->payload, ptr, min);
        memset(frame->payload + min, 0, PAYLOAD_SIZE - min);
        ECHECK(_encrypt_frame(frame, sock->counter++));

        /* delegate to socket device */
        n = (*sockdev->sd_sendto)(
            sockdev,
            sock_impl,
            frame,
            sizeof(frame_t),
            flags,
            dest_addr,
            addrlen);

        if (n < 0)
        {
            if (total > 0)
            {
                ret = total;
                goto done;
            }

            ECHECK(n);
        }

        if (n == 0)
        {
            ret = total;
            goto done;
        }

        assert(n == sizeof(frame_t));

        ptr += min;
        rem -= min;
        total += min;
    }

    ret = total;

done:

    if (frame)
        free(frame);

    return ret;
}

static ssize_t _recvmsg(
    myst_sock_t* sock,
    myst_sockdev_t* sockdev,
    myst_sock_t* sock_impl,
    struct msghdr* msg,
    int flags)
{
    ssize_t ret = 0;
    size_t len;
    frame_t* frame = NULL;
    void* buf = NULL;
    struct peek_state
    {
        size_t counter;
        uint8_t inbuf[PAYLOAD_SIZE];
        size_t inbuf_size;
    };
    struct peek_state* peek_state = NULL;
    uint8_t* ptr;
    size_t rem;
    size_t total = 0; /* total data received */

    /* backup state if MSG_PEEK request */
    if (flags & MSG_PEEK)
    {
        if (!(peek_state = calloc(1, sizeof(struct peek_state))))
            ERAISE(-ENOMEM);

        peek_state->counter = sock->counter;
        memcpy(peek_state->inbuf, sock->inbuf, sizeof(peek_state->inbuf));
        peek_state->inbuf_size = sock->inbuf_size;
    }

    if (!(frame = calloc(1, sizeof(frame_t))))
        ERAISE(-ENOMEM);

    ERAISE(len = myst_iov_len(msg->msg_iov, msg->msg_iovlen));

    if (len == 0)
        goto done;

    if (!(buf = malloc(len)))
        ERAISE(-ENOMEM);

    ptr = buf;
    rem = len;

    /* if any bytes left over in the input buffer form previous call */
    if (rem > 0 && sock->inbuf_size > 0)
    {
        const size_t min = _min(rem, sock->inbuf_size);
        memcpy(ptr, sock->inbuf, min);
        memmove(sock->inbuf, &sock->inbuf[min], sock->inbuf_size - min);
        sock->inbuf_size -= min;

        ptr += min;
        rem -= min;
        total += min;
    }

#ifdef ENABLE_CONTROL_DATA
    if (msg->msg_control && msg->msg_controllen)
    {
        uint8_t* cptr = msg->msg_control;
        size_t crem = msg->msg_controllen;
        size_t ctotal = 0;

        msg->msg_controllen = 0;

        /* handle any control data */
        while (crem > 0)
        {
            ssize_t n;
            struct iovec iov_buf = {frame, sizeof(frame_t)};
            struct msghdr msg_buf;
            size_t min;

            memset(&msg_buf, 0, sizeof(msg_buf));
            msg_buf.msg_name = msg->msg_name;
            msg_buf.msg_namelen = msg->msg_namelen;
            msg_buf.msg_iov = &iov_buf;
            msg_buf.msg_iovlen = 1;

            /* peek at the next frame (leaving it on the wire) */
            {
                n = (*sockdev->sd_recvmsg)(
                    sockdev, sock_impl, &msg_buf, flags | MSG_PEEK);
                ECHECK(n);

                if (n == 0)
                    goto done;

                if (n != sizeof(frame_t))
                    ERAISE(-EIO);

                ECHECK(_decrypt_frame(frame, sock->counter));

                if (frame->header.magic != FRAME_CONTROL_MAGIC)
                    break;
            }

            /* read the frame for real now */
            {
                n = (*sockdev->sd_recvmsg)(sockdev, sock_impl, &msg_buf, flags);
                ECHECK(n);

                if (n == 0)
                    goto done;

                if (n != sizeof(frame_t))
                    ERAISE(-EIO);

                ECHECK(_decrypt_frame(frame, sock->counter++));

                if (frame->header.magic != FRAME_CONTROL_MAGIC)
                    break;
            }

            if ((min = _min(crem, frame->header.size)))
            {
                memcpy(cptr, frame->payload, min);
                cptr += min;
                crem -= min;
                ctotal += min;
            }
        }

        msg->msg_controllen = ctotal;
    }
#endif /* ENABLE_CONTROL_DATA */

    while (rem > 0)
    {
        ssize_t n;
        struct iovec iov_buf = {frame, sizeof(frame_t)};
        struct msghdr msg_buf;

        memset(&msg_buf, 0, sizeof(msg_buf));
        msg_buf.msg_name = msg->msg_name;
        msg_buf.msg_namelen = msg->msg_namelen;
        msg_buf.msg_iov = &iov_buf;
        msg_buf.msg_iovlen = 1;

        /* delegate to socket device */
        n = (*sockdev->sd_recvmsg)(sockdev, sock_impl, &msg_buf, flags);

        if (n < 0)
        {
            if (total > 0)
            {
                ret = total;
                break;
            }

            ECHECK(n);
        }

        if (n == 0)
        {
            ret = total;
            break;
        }

        assert(n == sizeof(frame_t));
        ECHECK(_decrypt_frame(frame, sock->counter++));

        const size_t min = _min(rem, frame->header.size);
        memcpy(ptr, frame->payload, min);
        ptr += min;
        rem -= min;
        total += min;

        /* if there are unused bytes, then save them for later */
        if (min < frame->header.size)
        {
            sock->inbuf_size = frame->header.size - min;
            memcpy(sock->inbuf, &frame->payload[min], sock->inbuf_size);
        }

#ifdef ENABLE_CONTROL_DATA
        if (msg->msg_controllen)
            break;
#endif /* ENABLE_CONTROL_DATA */
    }

    ECHECK(myst_iov_scatter(msg->msg_iov, msg->msg_iovlen, buf, total));

    ret = total;

done:

    /* restore the state if MSG_PEEK request */
    if (peek_state)
    {
        sock->counter = peek_state->counter;
        memcpy(sock->inbuf, peek_state->inbuf, sizeof(sock->inbuf));
        sock->inbuf_size = peek_state->inbuf_size;
        free(peek_state);
    }

    if (frame)
        free(frame);

    if (buf)
        free(buf);

    return ret;
}

static ssize_t _sendmsg(
    myst_sock_t* sock,
    myst_sockdev_t* sockdev,
    myst_sock_t* sock_impl,
    const struct msghdr* msg,
    int flags)
{
    ssize_t ret = 0;
    const uint8_t* ptr;
    size_t rem;
    size_t total = 0;
    frame_t* frame = NULL;
    void* base = NULL;

    if (!(frame = calloc(1, sizeof(frame_t))))
        ERAISE(-ENOMEM);

    if (msg->msg_iovlen != 1)
    {
        ERAISE((rem = myst_iov_gather(msg->msg_iov, msg->msg_iovlen, &base)));
        ptr = base;
    }
    else
    {
        ptr = msg->msg_iov[0].iov_base;
        rem = msg->msg_iov[0].iov_len;
    }

#ifdef ENABLE_CONTROL_DATA
    {
        const uint8_t* cptr = msg->msg_control;
        size_t crem = msg->msg_controllen;
        size_t ctotal = 0;

        /* send the ancillary data (control data) if any */
        while (crem > 0)
        {
            size_t min = _min(crem, PAYLOAD_SIZE);
            ssize_t n;
            struct iovec iov_buf = {frame, sizeof(frame_t)};
            struct msghdr msg_buf;

            memset(&msg_buf, 0, sizeof(msg_buf));
            msg_buf.msg_name = msg->msg_name;
            msg_buf.msg_namelen = msg->msg_namelen;
            msg_buf.msg_iov = &iov_buf;
            msg_buf.msg_iovlen = 1;

            frame->header.magic = FRAME_CONTROL_MAGIC;
            frame->header.size = min;
            memcpy(frame->payload, cptr, min);
            memset(frame->payload + min, 0, PAYLOAD_SIZE - min);
            ECHECK(_encrypt_frame(frame, sock->counter++));

            /* delegate to socket device */
            n = (*sockdev->sd_sendmsg)(sockdev, sock_impl, &msg_buf, flags);
            ECHECK(n);

            assert(n == sizeof(frame_t));

            cptr += min;
            crem -= min;
            ctotal += min;
        }
    }
#endif /* ENABLE_CONTROL_DATA */

    /* send the payload */
    while (rem > 0)
    {
        size_t min = _min(rem, PAYLOAD_SIZE);
        ssize_t n;
        struct iovec iov_buf = {frame, sizeof(frame_t)};
        struct msghdr msg_buf;

        memset(&msg_buf, 0, sizeof(msg_buf));
        msg_buf.msg_name = msg->msg_name;
        msg_buf.msg_namelen = msg->msg_namelen;
        msg_buf.msg_iov = &iov_buf;
        msg_buf.msg_iovlen = 1;

        frame->header.magic = FRAME_DATA_MAGIC;
        frame->header.size = min;

        memcpy(frame->payload, ptr, min);
        memset(frame->payload + min, 0, PAYLOAD_SIZE - min);
        ECHECK(_encrypt_frame(frame, sock->counter++));

        /* delegate to socket device */
        n = (*sockdev->sd_sendmsg)(sockdev, sock_impl, &msg_buf, flags);

        if (n < 0)
        {
            if (total > 0)
            {
                ret = total;
                goto done;
            }

            ECHECK(n);
        }

        if (n == 0)
        {
            ret = total;
            goto done;
        }

        assert(n == sizeof(frame_t));

        ptr += min;
        rem -= min;
        total += min;
    }

    ret = total;

done:

    if (base)
        free(base);

    if (frame)
        free(frame);

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
    myst_sockdev_t* sockdev = myst_sockdev_get();
    myst_sock_t* sock = NULL;
    myst_sock_t* sock_impl = NULL;

    if (sock_out)
        *sock_out = NULL;

    if (!dev || !sock_out)
        ERAISE(-EINVAL);

    if (domain != AF_UNIX && domain != AF_LOCAL)
        ERAISE(-ENOTSUP);

    if (!(type & SOCK_STREAM) && !(type & SOCK_DGRAM))
        ERAISE(-ENOTSUP);

    ECHECK((sockdev->sd_socket)(sockdev, domain, type, protocol, &sock_impl));
    const bool nonblock = type & SOCK_NONBLOCK;
    ECHECK(_new_sock(nonblock, sock_impl, &sock));

    *sock_out = sock;
    sock_impl = NULL;
    sock = NULL;

done:

    if (sock)
        _free_sock(sock);

    if (sock_impl)
        _free_sock(sock_impl);

    return ret;
}

static int _udsdev_listen(myst_sockdev_t* dev, myst_sock_t* sock, int backlog)
{
    int ret = 0;
    myst_sockdev_t* sockdev = myst_sockdev_get();

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* delegate to socket device */
    ECHECK((*sockdev->sd_listen)(sockdev, sock->impl, backlog));

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
    myst_sockdev_t* sockdev = myst_sockdev_get();
    struct locals
    {
        struct sockaddr_un addr;
        char path[PATH_MAX];
    };
    struct locals* locals = NULL;
    const struct sockaddr_un* sun = (const struct sockaddr_un*)addr;

    if (!dev || !_valid_sock(sock) || !addr)
        ERAISE(-EINVAL);

    /* Read the Unix-domain socket file link */
    if (*sun->sun_path)
    {
        const size_t size = sizeof(locals->path) - 1;
        ssize_t n;

        if (!(locals = calloc(1, sizeof(struct locals))))
            ERAISE(-ENOMEM);

        ECHECK(n = myst_syscall_readlink(sun->sun_path, locals->path, size));
        locals->path[n] = '\0';

        /* fixup the address to use the host-side address */
        memcpy(&locals->addr, addr, sizeof(struct sockaddr_un));
        myst_strlcpy(
            locals->addr.sun_path, locals->path, sizeof(locals->addr.sun_path));

        /* delegate to socket device */
        ECHECK((*sockdev->sd_connect)(
            sockdev, sock->impl, (struct sockaddr*)&locals->addr, addrlen));
    }
    else
    {
        /* delegate to socket device */
        ECHECK((*sockdev->sd_connect)(sockdev, sock->impl, addr, addrlen));
    }

done:

    if (locals)
        free(locals);

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
    myst_sockdev_t* sockdev = myst_sockdev_get();
    myst_sock_t* new_sock = NULL;
    myst_sock_t* new_sock_impl = NULL;

    if (!dev || !_valid_sock(sock) || !new_sock_out)
        ERAISE(-EINVAL);

    /* delegate to socket device */
    ECHECK((*sockdev->sd_accept4)(
        dev, sock->impl, addr, addrlen, flags, &new_sock_impl));

    const bool nonblock = flags & SOCK_NONBLOCK;
    ECHECK(_new_sock(nonblock, new_sock_impl, &new_sock));
    *new_sock_out = new_sock;
    new_sock = NULL;
    new_sock_impl = NULL;

done:

    if (new_sock)
        _free_sock(new_sock);

    if (new_sock_impl)
        _free_sock(new_sock_impl);

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
    myst_sockdev_t* sockdev = myst_sockdev_get();

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* delegate to socket device */
    ECHECK((*sockdev->sd_getsockopt)(
        sockdev, sock->impl, level, optname, optval, optlen));

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
    myst_sockdev_t* sockdev = myst_sockdev_get();

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* delegate to socket device */
    ECHECK((*sockdev->sd_setsockopt)(
        sockdev, sock->impl, level, optname, optval, optlen));

done:
    return ret;
}

static int _udsdev_target_fd(myst_sockdev_t* dev, myst_sock_t* sock)
{
    int ret = 0;
    myst_sockdev_t* sockdev = myst_sockdev_get();

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* delegate to socket device */
    ret = (*sockdev->sd_target_fd)(sockdev, sock->impl);
    ECHECK(ret);

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

    /* delegate to socket device */
    ECHECK((*sockdev->sd_fstat)(sockdev, sock->impl, statbuf));

done:

    return ret;
}

static int _udsdev_bind(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    const struct sockaddr* addr,
    socklen_t addrlen)
{
    int ret = 0;
    myst_sockdev_t* sockdev = myst_sockdev_get();
    struct locals
    {
        struct sockaddr_un addr;
        char path[PATH_MAX];
        struct sockaddr_un addr_buf;
    };
    struct locals* locals = NULL;
    const struct sockaddr_un* sun = (const struct sockaddr_un*)addr;

    if (!dev || !_valid_sock(sock) || !addr || !addrlen)
        ERAISE(-EINVAL);

    if (addrlen <= MYST_OFFSETOF(struct sockaddr_un, sun_path))
        ERAISE(-EINVAL);

    if (addrlen > sizeof(struct sockaddr_un))
        ERAISE(-EINVAL);

    if (!(locals = calloc(1, sizeof(struct locals))))
        ERAISE(-ENOMEM);

    memcpy(&locals->addr_buf, addr, addrlen);
    locals->addr_buf.sun_path[sizeof(sun->sun_path) - 1] = '\0';
    sun = &locals->addr_buf;

    /* create the Unix-domain socket file (use a symlink) */
    if (*sun->sun_path)
    {
        struct stat statbuf;

        /* raise EADDRINUSE if symbolic link already exists */
        if (myst_syscall_lstat(sun->sun_path, &statbuf) == 0)
            ERAISE(-EADDRINUSE);

        /* get a temporary file name on the host file system */
        ECHECK(
            myst_tcall_get_tempfile_name(locals->path, sizeof(locals->path)));

        ECHECK(myst_syscall_symlink(locals->path, sun->sun_path));

        myst_strlcpy(sock->sun_path, sun->sun_path, sizeof(sock->sun_path));

        locals->addr = locals->addr_buf;
        myst_strlcpy(
            locals->addr.sun_path, locals->path, sizeof(locals->addr.sun_path));

        /* delegate to socket device */
        ECHECK((*sockdev->sd_bind)(
            sockdev,
            sock->impl,
            (const struct sockaddr*)&locals->addr,
            addrlen));
    }
    else
    {
        /* delegate to socket device */
        ECHECK((*sockdev->sd_bind)(sockdev, sock->impl, addr, addrlen));
    }

done:

    if (locals)
        free(locals);

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
    int ret = 0;
    myst_sockdev_t* sockdev = myst_sockdev_get();

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    ret =
        _sendto(sock, sockdev, sock->impl, buf, len, flags, dest_addr, addrlen);
    ECHECK(ret);

done:
    return ret;
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
    int ret = 0;
    myst_sockdev_t* sockdev = myst_sockdev_get();

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* delegate to socket device */
    ret = _recvfrom(
        sock, sockdev, sock->impl, buf, len, flags, src_addr, addrlen);
    ECHECK(ret);

done:
    return ret;
}

static ssize_t _udsdev_read(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    void* buf,
    size_t count)
{
    int ret = 0;
    myst_sockdev_t* sockdev = myst_sockdev_get();

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    ret = _read(sock, sockdev, sock->impl, buf, count);
    ECHECK(ret);

done:
    return ret;
}

static ssize_t _udsdev_write(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    const void* buf,
    size_t count)
{
    int ret = 0;
    myst_sockdev_t* sockdev = myst_sockdev_get();

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* delegate to socket device */
    ret = _write(sock, sockdev, sock->impl, buf, count);
    ECHECK(ret);

done:
    return ret;
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
    myst_sockdev_t* sockdev = myst_sockdev_get();

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* delegate to socket device */
    ECHECK((*sockdev->sd_close)(sockdev, sock->impl));

    memset(sock, 0, sizeof(myst_sock_t));
    free(sock);

done:
    return ret;
}

static int _udsdev_fcntl(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    int cmd,
    long arg)
{
    int ret = 0;
    myst_sockdev_t* sockdev = myst_sockdev_get();

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* delegate to socket device */
    ECHECK(ret = (*sockdev->sd_fcntl)(sockdev, sock->impl, cmd, arg));

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
    myst_sockdev_t* sockdev = myst_sockdev_get();

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* delegate to socket device */
    ECHECK(ret = (*sockdev->sd_ioctl)(sockdev, sock->impl, request, arg));

done:
    return ret;
}

static int _udsdev_dup(
    myst_sockdev_t* dev,
    const myst_sock_t* sock,
    myst_sock_t** sock_out)
{
    int ret = 0;
    myst_sockdev_t* sockdev = myst_sockdev_get();
    myst_sock_t* new_sock = NULL;
    myst_sock_t* new_sock_impl = NULL;

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* delegate to socket device */
    ECHECK((*sockdev->sd_dup)(sockdev, sock->impl, &new_sock_impl));

    ECHECK(_new_sock(sock->nonblock, new_sock_impl, &new_sock));
    *sock_out = new_sock;
    new_sock = NULL;
    new_sock_impl = NULL;

done:

    if (new_sock_impl)
        (*sockdev->sd_close)(sockdev, new_sock_impl);

    if (new_sock)
        _free_sock(new_sock);

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
    myst_sockdev_t* sockdev = myst_sockdev_get();

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (!msg)
        ERAISE(-EINVAL);

#ifndef ENABLE_CONTROL_DATA
    /* ATTN: control information is not supported */
    if (msg->msg_control || msg->msg_controllen)
    {
        MYST_WLOG("AF_LOCAL control data unsuuported");
        ERAISE(-ENOTSUP);
    }
#endif /* !ENABLE_CONTROL_DATA */

    ret = _sendmsg(sock, sockdev, sock->impl, msg, flags);
    ECHECK(ret);

done:
    return ret;
}

static int _udsdev_recvmsg(
    myst_sockdev_t* dev,
    myst_sock_t* sock,
    struct msghdr* msg,
    int flags)
{
    int ret = 0;
    myst_sockdev_t* sockdev = myst_sockdev_get();

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (!msg)
        ERAISE(-EINVAL);

#ifndef ENABLE_CONTROL_DATA
    /* ATTN: control information is not supported */
    if (msg->msg_control || msg->msg_controllen)
    {
        MYST_WLOG("AF_LOCAL control data unsuuported");
        ERAISE(-ENOTSUP);
    }
#endif /* !ENABLE_CONTROL_DATA */

    ret = _recvmsg(sock, sockdev, sock->impl, msg, flags);
    ECHECK(ret);

done:
    return ret;
}

static int _udsdev_shutdown(myst_sockdev_t* dev, myst_sock_t* sock, int how)
{
    int ret = 0;
    myst_sockdev_t* sockdev = myst_sockdev_get();

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* delegate to socket device */
    ret = (*sockdev->sd_shutdown)(sockdev, sock->impl, how);
    ECHECK(ret);

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
    myst_sockdev_t* sockdev = myst_sockdev_get();

    if (!dev || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* delegate to socket device */
    ret = (*sockdev->sd_getpeername)(sockdev, sock->impl, addr, addrlen);
    ECHECK(ret);

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
    myst_sockdev_t* sockdev = myst_sockdev_get();
    size_t original_addrlen = 0;
    struct sockaddr_un* sun = (struct sockaddr_un*)addr;

    if (!dev || !_valid_sock(sock) || !addr || !addrlen)
        ERAISE(-EINVAL);

    original_addrlen = *addrlen;

    /* delegate to socket device */
    ret = (*sockdev->sd_getsockname)(sockdev, sock->impl, addr, addrlen);

    if (ret >= 0 && original_addrlen >= sizeof(struct sockaddr_un))
    {
        if (*sock->sun_path)
        {
            myst_strlcpy(sun->sun_path, sock->sun_path, sizeof(sun->sun_path));
            *addrlen = sizeof(struct sockaddr_un);
        }
        else
        {
            sun->sun_path[0] = '\0';
        }
    }

    ECHECK(ret);

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
    myst_sockdev_t* sockdev = myst_sockdev_get();
    myst_sock_t* new_pair[2] = {NULL, NULL};
    myst_sock_t* new_pair_impl[2] = {NULL, NULL};

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

    ECHECK((sockdev->sd_socketpair)(
        sockdev, domain, type, protocol, new_pair_impl));

    const bool nonblock = type & SOCK_NONBLOCK;
    ECHECK(_new_sock(nonblock, new_pair_impl[0], &new_pair[0]));
    ECHECK(_new_sock(nonblock, new_pair_impl[1], &new_pair[1]));

    pair[0] = new_pair[0];
    pair[1] = new_pair[1];
    new_pair_impl[0] = NULL;
    new_pair_impl[1] = NULL;
    new_pair[0] = NULL;
    new_pair[1] = NULL;

done:

    if (new_pair[0])
        _free_sock(new_pair[0]);

    if (new_pair[1])
        _free_sock(new_pair[1]);

    if (new_pair_impl[0])
        (*sockdev->sd_close)(sockdev, new_pair_impl[0]);

    if (new_pair_impl[1])
        (*sockdev->sd_close)(sockdev, new_pair_impl[1]);

    return ret;
}

myst_sockdev_t* myst_sockdev_get_uds(void)
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
