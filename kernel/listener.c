#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <myst/buf.h>
#include <myst/eraise.h>
#include <myst/fdtable.h>
#include <myst/kernel.h>
#include <myst/list.h>
#include <myst/listener.h>
#include <myst/mount.h>
#include <myst/mutex.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/process.h>
#include <myst/signal.h>
#include <myst/strings.h>
#include <myst/syscall.h>

/* ATTN.FORK: limits the number of simultaneous forked processes */
#define MAX_CONNECTIONS 32

#define MAGIC 0x425e6bdeed0a46f4

/* all messages begin with this struct */
typedef struct message
{
    uint64_t magic;
    uint64_t type;
    uint64_t size;
    int32_t pid; /* the process-id of the peer process */
    uint32_t padding;
    uint8_t data[];
} message_t;

static void _init_sockaddr(struct sockaddr_un* addr, pid_t pid)
{
    memset(addr, 0, sizeof(struct sockaddr_un));
    addr->sun_family = AF_UNIX;
    snprintf(addr->sun_path, sizeof(addr->sun_path), "/tmp/myst%u.socket", pid);
}

static int _set_blocking(int sock, bool blocking)
{
    int flags;

    if ((flags = fcntl(sock, F_GETFL, 0)) == -1)
        return -1;

    if (blocking)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;

    if (fcntl(sock, F_SETFL, flags) == -1)
        return -1;

    return 0;
}

typedef struct connection
{
    /* the first fields must must align with myst_list_node_t */
    struct connection* prev;
    struct connection* next;

    int sock;
    struct sockaddr_un addr;
    socklen_t addrlen;
    short events;
    myst_buf_t input;
    myst_buf_t output;
} connection_t;

static myst_list_t _connections;

static const message_t* _get_message(const myst_buf_t* buf)
{
    const message_t* message;

    if (buf->size < sizeof(message_t))
        return NULL;

    message = (const message_t*)buf->data;

    if (message->magic != MAGIC)
        myst_panic("corrupt listener request");

    if (buf->size < sizeof(message_t) + message->size)
        return NULL;

    return message;
}

static int _accept_connection(int lsock, connection_t** conn_out)
{
    int ret = 0;
    int sock;
    struct sockaddr_un addr;
    socklen_t addrlen = sizeof(addr);
    connection_t* conn = NULL;

    if (conn_out)
        *conn_out = NULL;

    if ((sock = accept(lsock, (struct sockaddr*)&addr, &addrlen)) < 0)
        ERAISE(-errno);

    if (_set_blocking(sock, false) != 0)
        ERAISE(-ENOSYS);

    if (!(conn = calloc(1, sizeof(connection_t))))
        ERAISE(-ENOMEM);

    conn->sock = sock;
    conn->addr = addr;
    conn->addrlen = addrlen;

    *conn_out = conn;
    conn = NULL;

done:

    if (conn)
        free(conn);

    return ret;
}

static connection_t* _find_connection(int sock)
{
    connection_t* p = (connection_t*)_connections.head;

    for (; p; p = p->next)
    {
        if (p->sock = sock)
            return p;
    }

    return NULL;
}

static void _release_connection(connection_t* conn)
{
    close(conn->sock);
    myst_buf_release(&conn->input);
    myst_buf_release(&conn->output);
    free(conn);
}

static void _init_message(
    message_t* message,
    myst_message_type_t type,
    size_t size)
{
    message->magic = MAGIC;
    message->type = type;
    message->size = size;
    message->pid = myst_getpid();
}

static int _enqueue_response(
    connection_t* conn,
    myst_message_type_t type,
    const void* data,
    size_t size)
{
    int ret = 0;
    message_t m;

    _init_message(&m, type, size);

    if (myst_buf_append(&conn->output, &m, sizeof(m)) != 0)
        ERAISE(-ENOMEM);

    if (data && size)
    {
        if (myst_buf_append(&conn->output, data, size) != 0)
            ERAISE(-ENOMEM);
    }

    conn->events |= EPOLLOUT;

done:
    return ret;
}

static int _handle_open(connection_t* conn, const myst_open_request_t* req)
{
    int ret = 0;
    myst_fs_t* fs = (myst_fs_t*)req->fs_cookie;
    myst_open_response_t rsp;
    myst_fs_t* new_fs = NULL;
    myst_file_t* new_file = NULL;

    rsp.retval = (*fs->fs_open)(
        fs, req->pathname, req->flags, req->mode, &new_fs, &new_file);

    rsp.fs_cookie = (uint64_t)new_fs;
    rsp.file_cookie = (uint64_t)new_file;

    ECHECK(_enqueue_response(conn, MYST_MESSAGE_OPEN, &rsp, sizeof(rsp)));

    new_fs = NULL;

done:

    /* if the enqueue failed, then release the file object */
    if (new_fs)
        (*new_fs->fs_close)(new_fs, new_file);

    return 0;
}

static int _handle_fileop(
    connection_t* conn,
    myst_message_type_t mt,
    const myst_fileop_request_t* req)
{
    int ret = 0;
    myst_fs_t* fs = (myst_fs_t*)req->fs_cookie;
    myst_file_t* file = (myst_file_t*)req->file_cookie;
    myst_fileop_response_t* rsp = NULL;
    size_t rsp_size = sizeof(*rsp) + req->outbufsize;
    long retval;

    if (!(rsp = calloc(1, rsp_size)))
        ERAISE(-ENOMEM);

    if (mt == MYST_MESSAGE_CLOSE)
    {
        retval = (*fs->fs_close)(fs, file);
    }
    else if (mt == MYST_MESSAGE_LSEEK)
    {
        retval = (*fs->fs_lseek)(
            fs, file, req->args.lseek.offset, req->args.lseek.whence);
    }
    else if (mt == MYST_MESSAGE_FTRUNCATE)
    {
        retval = (*fs->fs_ftruncate)(fs, file, req->args.ftruncate.length);
    }
    else if (mt == MYST_MESSAGE_FCNTL)
    {
        retval =
            (*fs->fs_fcntl)(fs, file, req->args.fcntl.cmd, req->args.fcntl.arg);
    }
    else if (mt == MYST_MESSAGE_IOCTL)
    {
        retval = (*fs->fs_ioctl)(
            fs, file, req->args.ioctl.request, req->args.ioctl.arg);
    }
    else if (mt == MYST_MESSAGE_TARGET_FD)
    {
        retval = (*fs->fs_target_fd)(fs, file);
    }
    else if (mt == MYST_MESSAGE_GET_EVENTS)
    {
        retval = (*fs->fs_get_events)(fs, file);
    }
    else if (mt == MYST_MESSAGE_FUTIMENS)
    {
        retval = (*fs->fs_futimens)(fs, file, req->args.futimens.times);
    }
    else if (mt == MYST_MESSAGE_FCHOWN)
    {
        retval = (*fs->fs_fchown)(
            fs, file, req->args.fchown.owner, req->args.fchown.group);
    }
    else if (mt == MYST_MESSAGE_FCHMOD)
    {
        retval = (*fs->fs_fchmod)(fs, file, req->args.fchmod.mode);
    }
    else if (mt == MYST_MESSAGE_FDATASYNC)
    {
        retval = (*fs->fs_fdatasync)(fs, file);
    }
    else if (mt == MYST_MESSAGE_FSYNC)
    {
        retval = (*fs->fs_fsync)(fs, file);
    }
    else if (mt == MYST_MESSAGE_FSTAT)
    {
        retval = (*fs->fs_fstat)(fs, file, (struct stat*)rsp->buf);
    }
    else if (mt == MYST_MESSAGE_FSTATFS)
    {
        retval = (*fs->fs_fstatfs)(fs, file, (struct statfs*)rsp->buf);
    }
    else if (mt == MYST_MESSAGE_READ)
    {
        retval = (*fs->fs_read)(fs, file, rsp->buf, req->outbufsize);
        rsp_size = sizeof(*rsp);

        if (retval > 0)
            rsp_size += retval;
    }
    else if (mt == MYST_MESSAGE_WRITE)
    {
        retval = (*fs->fs_write)(fs, file, req->buf, req->inbufsize);
    }
    else if (mt == MYST_MESSAGE_PWRITE)
    {
        retval = (*fs->fs_pwrite)(
            fs, file, req->buf, req->inbufsize, req->args.pwrite.offset);
    }
    else if (mt == MYST_MESSAGE_GETDENTS64)
    {
        retval = (*fs->fs_getdents64)(
            fs, file, (struct dirent*)rsp->buf, req->outbufsize);

        rsp_size = sizeof(*rsp);

        if (retval > 0)
            rsp_size += retval;
    }
    else if (mt == MYST_MESSAGE_REALPATH)
    {
        retval = (*fs->fs_realpath)(fs, file, (char*)rsp->buf, req->outbufsize);
    }
    else if (mt == MYST_MESSAGE_PREAD)
    {
        retval = (*fs->fs_pread)(
            fs, file, rsp->buf, req->outbufsize, req->args.pread.offset);
        rsp_size = sizeof(*rsp);

        if (retval > 0)
            rsp_size += retval;
    }
    else
    {
        ERAISE(-EINVAL);
    }

    rsp->retval = retval;

    ECHECK(_enqueue_response(conn, mt, rsp, rsp_size));

done:

    if (rsp)
        free(rsp);

    return 0;
}

static int _handle_pathop(
    connection_t* conn,
    myst_message_type_t mt,
    const myst_pathop_request_t* req)
{
    int ret = 0;
    myst_fs_t* fs = (myst_fs_t*)req->fs_cookie;
    myst_pathop_response_t* rsp = NULL;
    size_t rsp_size = sizeof(*rsp) + req->bufsize;
    long retval;

    if (!(rsp = calloc(1, rsp_size)))
        ERAISE(-ENOMEM);

    if (mt == MYST_MESSAGE_UNLINK)
    {
        retval = (*fs->fs_unlink)(fs, req->pathname);
    }
    else if (mt == MYST_MESSAGE_ACCESS)
    {
        retval = (*fs->fs_access)(fs, req->pathname, req->args.access.mode);
    }
    else if (mt == MYST_MESSAGE_TRUNCATE)
    {
        retval =
            (*fs->fs_truncate)(fs, req->pathname, req->args.truncate.length);
    }
    else if (mt == MYST_MESSAGE_MKDIR)
    {
        retval = (*fs->fs_mkdir)(fs, req->pathname, req->args.mkdir.mode);
    }
    else if (mt == MYST_MESSAGE_RMDIR)
    {
        retval = (*fs->fs_rmdir)(fs, req->pathname);
    }
    else if (mt == MYST_MESSAGE_CHMOD)
    {
        retval = (*fs->fs_chmod)(fs, req->pathname, req->args.chmod.mode);
    }
    else if (mt == MYST_MESSAGE_LCHOWN)
    {
        retval = (*fs->fs_lchown)(
            fs, req->pathname, req->args.lchown.owner, req->args.lchown.group);
    }
    else if (mt == MYST_MESSAGE_CHOWN)
    {
        retval = (*fs->fs_lchown)(
            fs, req->pathname, req->args.chown.owner, req->args.chown.group);
    }
    else if (mt == MYST_MESSAGE_STAT)
    {
        retval = (*fs->fs_stat)(fs, req->pathname, (struct stat*)rsp->buf);
    }
    else if (mt == MYST_MESSAGE_LSTAT)
    {
        retval = (*fs->fs_lstat)(fs, req->pathname, (struct stat*)rsp->buf);
    }
    else if (mt == MYST_MESSAGE_STATFS)
    {
        retval = (*fs->fs_statfs)(fs, req->pathname, (struct statfs*)rsp->buf);
    }
    else if (mt == MYST_MESSAGE_READLINK)
    {
        retval = (*fs->fs_readlink)(
            fs, req->pathname, (char*)rsp->buf, req->bufsize);
        rsp_size = sizeof(*rsp);

        if (retval > 0)
            rsp_size += retval;
    }
    else if (mt == MYST_MESSAGE_SYMLINK)
    {
        const char* path2 = req->pathname + strlen(req->pathname) + 1;
        retval = (*fs->fs_symlink)(fs, req->pathname, path2);
    }
    else if (mt == MYST_MESSAGE_LINK)
    {
        const char* path2 = req->pathname + strlen(req->pathname) + 1;
        retval = (*fs->fs_link)(fs, req->pathname, path2);
    }
    else if (mt == MYST_MESSAGE_RENAME)
    {
        const char* path2 = req->pathname + strlen(req->pathname) + 1;
        retval = (*fs->fs_rename)(fs, req->pathname, path2);
    }
    else
    {
        ERAISE(-EINVAL);
    }

    rsp->retval = retval;
    ECHECK(_enqueue_response(conn, mt, rsp, rsp_size));

done:

    if (rsp)
        free(rsp);

    return 0;
}

static int _handle_pipeop(
    connection_t* conn,
    myst_message_type_t mt,
    const myst_pipeop_request_t* req)
{
    int ret = 0;
    myst_pipedev_t* dev = (myst_pipedev_t*)req->pipedev_cookie;
    myst_pipe_t* pipe = (myst_pipe_t*)req->pipe_cookie;
    myst_pipeop_response_t* rsp = NULL;
    size_t rsp_size = sizeof(*rsp) + req->outbufsize;
    long retval;

    if (!(rsp = calloc(1, rsp_size)))
        ERAISE(-ENOMEM);

    if (mt == MYST_MESSAGE_WRITE_PIPE)
    {
        retval = (*dev->pd_write)(dev, pipe, req->buf, req->inbufsize);
    }
    else if (mt == MYST_MESSAGE_READ_PIPE)
    {
        retval = (*dev->pd_read)(dev, pipe, rsp->buf, req->outbufsize);
        rsp_size = sizeof(*rsp);

        if (retval > 0)
            rsp_size += retval;
    }
    else if (mt == MYST_MESSAGE_CLOSE_PIPE)
    {
        retval = (*dev->pd_close)(dev, pipe);
    }
    else if (mt == MYST_MESSAGE_FSTAT_PIPE)
    {
        retval = (*dev->pd_fstat)(dev, pipe, (struct stat*)rsp->buf);
    }
    else if (mt == MYST_MESSAGE_FCNTL_PIPE)
    {
        retval = (*dev->pd_fcntl)(
            dev, pipe, req->args.fcntl.cmd, req->args.fcntl.arg);
    }
    else if (mt == MYST_MESSAGE_DUP_PIPE)
    {
        myst_pipe_t* new_pipe = NULL;
        retval = (*dev->pd_dup)(dev, pipe, &new_pipe);

        if (retval == 0)
        {
            uint64_t cookie = (uint64_t)new_pipe;
            memcpy(rsp->buf, &cookie, sizeof(cookie));
        }
    }
    else
    {
        ERAISE(-EINVAL);
    }

    rsp->retval = retval;

    ECHECK(_enqueue_response(conn, mt, rsp, rsp_size));

done:

    if (rsp)
        free(rsp);

    return 0;
}

static int _handle_mount_resolve(
    connection_t* conn,
    const myst_mount_resolve_request_t* req)
{
    int ret = 0;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals;
    myst_fs_t* fs = NULL;
    myst_mount_resolve_response_t* rsp = NULL;
    size_t rsp_size;
    int retval;
    const myst_message_type_t mt = MYST_MESSAGE_MOUNT_RESOLVE;

    if (!(locals = calloc(1, sizeof(struct locals))))
        ERAISE(-ENOMEM);

    retval = myst_mount_resolve(req->path, locals->suffix, &fs);

    /* enqueue the rsp */
    if (retval == 0)
    {
        size_t len = strlen(locals->suffix);
        rsp_size = sizeof(*rsp) + len + 1;

        if (!(rsp = calloc(1, rsp_size)))
            ERAISE(-ENOMEM);

        rsp->retval = retval;
        rsp->fs_cookie = (uint64_t)fs;
        memcpy(rsp->suffix, locals->suffix, len + 1);
    }
    else
    {
        rsp_size = sizeof(*rsp) + 1;

        if (!(rsp = calloc(1, rsp_size)))
            ERAISE(-ENOMEM);

        rsp->retval = retval;
    }

    ECHECK(_enqueue_response(conn, mt, rsp, rsp_size));

done:

    if (locals)
        free(locals);

    if (rsp)
        free(rsp);

    return 0;
}

static int _handle_ping(connection_t* conn)
{
    myst_eprintf("MYST_MESSAGE_PING!!!\n");
    return _enqueue_response(conn, MYST_MESSAGE_PING, NULL, 0);
}

static int _handle_wake(connection_t* conn, const myst_wake_request_t* req)
{
    myst_wake_response_t rsp = {.retval = 0};

    __myst_wake((int*)req->addr, 0);

    return _enqueue_response(conn, MYST_MESSAGE_WAKE, &rsp, sizeof(rsp));
}

static int _handle_generate_tid(connection_t* conn, const message_t* message)
{
    pid_t pid = myst_generate_tid();
    return _enqueue_response(conn, message->type, &pid, sizeof(pid));
}

static int _handle_request(connection_t* conn, const message_t* message)
{
    int ret = 0;
    void* ptr = NULL;
    myst_thread_t* self = myst_thread_self();

    /* the the "effective process-id" for the duration of this request */
    self->epid = message->pid;

    switch (message->type)
    {
        case MYST_MESSAGE_PING:
        {
            ECHECK(_handle_ping(conn));
            break;
        }
        case MYST_MESSAGE_SHUTDOWN:
        {
            // myst_eprintf("MYST_MESSAGE_SHUTDOWN!!!\n");
            break;
        }
        case MYST_MESSAGE_WAKE:
        {
            myst_wake_request_t* req = (myst_wake_request_t*)message->data;

            if (message->size < sizeof(*req))
                myst_panic("corrupt req");

            if (_handle_wake(conn, req) != 0)
                myst_panic("_handle_wake()");
            break;
        }
        case MYST_MESSAGE_GENERATE_TID:
        {
            ECHECK(_handle_generate_tid(conn, message));
            break;
        }
        case MYST_MESSAGE_MOUNT_RESOLVE:
        {
            myst_mount_resolve_request_t* req = (void*)message->data;

            if (message->size < sizeof(*req))
                myst_panic("corrupt req");

            if (_handle_mount_resolve(conn, req) != 0)
                myst_panic("_handle_mount_resolve()");

            break;
        }
        case MYST_MESSAGE_OPEN:
        {
            myst_open_request_t* req = (myst_open_request_t*)message->data;

            if (message->size < sizeof(*req))
                myst_panic("corrupt req");

            if (_handle_open(conn, req) != 0)
                myst_panic("_handle_open()");
            break;
        }
        case MYST_MESSAGE_CLOSE:
        case MYST_MESSAGE_LSEEK:
        case MYST_MESSAGE_FTRUNCATE:
        case MYST_MESSAGE_FCNTL:
        case MYST_MESSAGE_IOCTL:
        case MYST_MESSAGE_TARGET_FD:
        case MYST_MESSAGE_GET_EVENTS:
        case MYST_MESSAGE_FUTIMENS:
        case MYST_MESSAGE_FCHOWN:
        case MYST_MESSAGE_FCHMOD:
        case MYST_MESSAGE_FDATASYNC:
        case MYST_MESSAGE_FSYNC:
        case MYST_MESSAGE_FSTAT:
        case MYST_MESSAGE_FSTATFS:
        case MYST_MESSAGE_READ:
        case MYST_MESSAGE_WRITE:
        case MYST_MESSAGE_PWRITE:
        case MYST_MESSAGE_PREAD:
        case MYST_MESSAGE_REALPATH:
        case MYST_MESSAGE_GETDENTS64:
        {
            myst_fileop_request_t* req = (myst_fileop_request_t*)message->data;

            if (message->size < sizeof(*req))
                myst_panic("corrupt req");

            if (_handle_fileop(conn, message->type, req) != 0)
                myst_panic("_handle_fileop()");
            break;
        }
        case MYST_MESSAGE_WRITE_PIPE:
        case MYST_MESSAGE_READ_PIPE:
        case MYST_MESSAGE_CLOSE_PIPE:
        case MYST_MESSAGE_FSTAT_PIPE:
        case MYST_MESSAGE_FCNTL_PIPE:
        case MYST_MESSAGE_DUP_PIPE:
        {
            myst_pipeop_request_t* req = (myst_pipeop_request_t*)message->data;

            if (message->size < sizeof(*req))
                myst_panic("corrupt req");

            if (_handle_pipeop(conn, message->type, req) != 0)
                myst_panic("_handle_pipeop()");
            break;
        }
        case MYST_MESSAGE_UNLINK:
        case MYST_MESSAGE_ACCESS:
        case MYST_MESSAGE_TRUNCATE:
        case MYST_MESSAGE_MKDIR:
        case MYST_MESSAGE_RMDIR:
        case MYST_MESSAGE_CHMOD:
        case MYST_MESSAGE_LCHOWN:
        case MYST_MESSAGE_CHOWN:
        case MYST_MESSAGE_STAT:
        case MYST_MESSAGE_LSTAT:
        case MYST_MESSAGE_STATFS:
        case MYST_MESSAGE_READLINK:
        case MYST_MESSAGE_SYMLINK:
        case MYST_MESSAGE_LINK:
        case MYST_MESSAGE_RENAME:
        {
            myst_pathop_request_t* req = (myst_pathop_request_t*)message->data;

            if (message->size < sizeof(*req))
                myst_panic("corrupt req");

            if (_handle_pathop(conn, message->type, req) != 0)
                myst_panic("_handle_pathop()");
            break;
        }
    }

    /* remove the request message from the input buffer */
    myst_buf_remove(&conn->input, 0, sizeof(message_t) + message->size);

done:

    if (ptr)
        free(ptr);

    self->epid = 0;

    return ret;
}

static int _handle_accept(int lsock, int revents)
{
    int ret = 0;

    if (revents & POLLIN)
    {
        connection_t* conn = NULL;

        if (_connections.size == MAX_CONNECTIONS)
            ERAISE(-ENOSYS);

        ECHECK(_accept_connection(lsock, &conn));

        /* watch input events initially */
        conn->events = POLLIN;

        /* add to the list of connections */
        myst_list_append(&_connections, (myst_list_node_t*)conn);
    }

done:
    return ret;
}

static int _handle_output(int sock)
{
    int ret = 0;
    connection_t* conn;
    ssize_t n;

    /* find the client with this file descriptor */
    if (!(conn = _find_connection(sock)))
        ERAISE(-ENOENT);

    /* read all client input */
    while ((n = write(conn->sock, conn->output.data, conn->output.size)) > 0)
    {
        myst_buf_remove(&conn->output, 0, n);

        if (conn->output.size == 0)
            conn->events &= ~EPOLLOUT;
    }

done:
    return ret;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstack-usage="
static int _handle_input(int sock)
{
    int ret = 0;
    ssize_t n;
    connection_t* conn;
    uint8_t buf[BUFSIZ];

    /* find the client with this file descriptor */
    if (!(conn = _find_connection(sock)))
        ERAISE(-ENOENT);

    /* read all client input */
    while ((n = read(conn->sock, buf, sizeof(buf))) > 0)
    {
        const message_t* m;

        if (myst_buf_append(&conn->input, buf, n) != 0)
            ERAISE(-ENOMEM);

        /* handle all queued messages */
        while ((m = _get_message(&conn->input)))
        {
            const bool shutdown = (m->type == MYST_MESSAGE_SHUTDOWN);

            _handle_request(conn, m);

            if (shutdown)
                ERAISE(-ENOSYS);
        }
    }

    /* if client closed the connection */
    if (n == 0)
    {
        myst_list_remove(&_connections, (myst_list_node_t*)conn);
        _release_connection(conn);
    }

done:
    return ret;
}
#pragma GCC diagnostic pop

static int _handle_shutdown(int lsock)
{
    int ret = 0;
    connection_t* p = (connection_t*)_connections.head;

    if (close(lsock) != 0)
        ERAISE(-errno);

    while (p)
    {
        connection_t* next = p->next;
        _release_connection(p);
        p = next;
    }

    _connections.head = NULL;
    _connections.tail = NULL;

done:
    return ret;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstack-usage="
long myst_syscall_run_listener(void)
{
    long ret = 0;
    int lsock = -1;
    connection_t* conn = NULL;
    struct sockaddr_un addr;
    struct pollfd fds[MAX_CONNECTIONS + 1]; /* extra entry for listener */

    _init_sockaddr(&addr, __myst_kernel_args.target_pid);

#if 1
    myst_eprintf(">>> listening on %s\n", addr.sun_path);
#endif

    if ((lsock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
        ERAISE(-errno);

    if (bind(lsock, (struct sockaddr*)&addr, sizeof(addr)) != 0)
        ERAISE(-errno);

    if (listen(lsock, 10) != 0)
        ERAISE(-errno);

    if (_set_blocking(lsock, false) != 0)
        ERAISE(-ENOSYS);

    for (;;)
    {
        size_t nfds = 0;

        /* watch input events on the listener socket */
        fds[nfds].fd = lsock;
        fds[nfds].events = POLLIN;
        nfds++;

        /* watch events on the connections */
        {
            connection_t* p = (connection_t*)_connections.head;

            for (; p; p = p->next)
            {
                fds[nfds].fd = p->sock;
                fds[nfds].events = p->events;
                fds[nfds].revents = 0;
                nfds++;
            }
        }

        /* wait for events. */
        if (poll(fds, nfds, -1) <= 0)
        {
            /* no events so retry */
            continue;
        }

        /* handle the polled events */
        for (size_t i = 0; i < nfds; i++)
        {
            struct pollfd* pollfd = &fds[i];
            int sock = fds[i].fd;

            if (pollfd->revents == 0)
                continue;

            if (pollfd->fd == lsock) /* accept connection */
            {
                if ((fds[i].revents & POLLIN))
                {
                    if (_handle_accept(lsock, pollfd->revents) != 0)
                    {
                        myst_eprintf("****** _handle_accept() failed\n");
                        continue;
                    }
                }
            }
            else if ((fds[i].revents & POLLOUT)) /* handle output */
            {
                int r = _handle_output(sock);

                if (r != 0)
                {
                    myst_eprintf("****** _handle_output() failed: %d\n", r);
                    continue;
                }
            }
            else if ((fds[i].revents & POLLIN)) /* handle input */
            {
                int r = _handle_input(sock);

                if (r == -ENOSYS)
                {
                    _handle_shutdown(lsock);
                    goto done;
                }

                if (r < 0)
                    ERAISE(r);
            }
        }
    }

done:

    if (lsock > 0)
        myst_syscall_close(lsock);

    if (conn)
        free(conn);

    return ret;
}
#pragma GCC diagnostic pop

static int _connect_to_listener(bool same_process)
{
    int ret = 0;
    struct sockaddr_un addr;
    int sock;
    pid_t pid;

    if (same_process)
        pid = __myst_kernel_args.target_pid;
    else
        pid = __myst_kernel_args.target_ppid;

    _init_sockaddr(&addr, pid);

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
        ERAISE(-errno);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0)
        ERAISE(-errno);

    ret = sock;

done:
    return ret;
}

static int _sock;
static bool _sock_initialized;
static myst_mutex_t _sock_lock;

int myst_listener_get_sock(void)
{
    int ret = 0;

    myst_mutex_lock(&_sock_lock);

    if (_sock == -1)
        ERAISE(-ENOSYS);

    if (_sock_initialized == false)
    {
        int sock;

        ECHECK(sock = _connect_to_listener(false));
        _sock = sock;
        _sock_initialized = true;
    }

    ret = _sock;

done:
    myst_mutex_unlock(&_sock_lock);

    return ret;
}

static ssize_t _writen(int fd, const void* data, size_t size)
{
    ssize_t ret = 0;
    const uint8_t* p = (const uint8_t*)data;
    size_t r = size;
    size_t m = 0;

    while (r > 0)
    {
        ssize_t n = write(fd, p, r);

        if (n <= 0)
            ERAISE(-errno);

        p += n;
        r -= (size_t)n;
        m += (size_t)n;
    }

    ret = m;

done:

    return ret;
}

static ssize_t _readn(int fd, void* data, size_t size)
{
    ssize_t ret = 0;
    uint8_t* p = (uint8_t*)data;
    size_t r = size;
    size_t m = 0;

    while (r > 0)
    {
        ssize_t n = read(fd, p, r);

        if (n < 0)
            ERAISE(-errno);

        /* end of file */
        if (n == 0)
            break;

        p += n;
        r -= (size_t)n;
        m += n;
    }

    ret = m;

done:

    return ret;
}

static int _send_request(
    int sock,
    myst_message_type_t type,
    const void* data,
    size_t size)
{
    int ret = 0;
    message_t m;
    ssize_t n;

    _init_message(&m, type, size);

    if ((n = _writen(sock, &m, sizeof(m))) != sizeof(m))
        ERAISE(-errno);

    if (data && size)
    {
        if (_writen(sock, data, size) != (ssize_t)size)
            ERAISE(-errno);
    }

done:
    return ret;
}

static int _recv_response(
    int sock,
    myst_message_type_t type,
    void** rsp_out,
    size_t* rsp_size_out)
{
    int ret = 0;
    message_t m;
    void* rsp = NULL;

    if (rsp_out)
        *rsp_out = NULL;

    if (rsp_size_out)
        *rsp_size_out = 0;

    if (_readn(sock, &m, sizeof(m)) != sizeof(m))
        ERAISE(-errno);

    if (m.magic != MAGIC)
        ERAISE(-EINVAL);

    if (m.type != type)
        ERAISE(-EINVAL);

    if (m.size)
    {
        if (!rsp_out || !rsp_size_out)
            ERAISE(-EINVAL);

        if (!(rsp = malloc(m.size)))
            ERAISE(-ENOMEM);

        if (_readn(sock, rsp, m.size) != (ssize_t)m.size)
            ERAISE(-errno);

        *rsp_out = rsp;
        *rsp_size_out = m.size;
        rsp = NULL;
    }

done:

    if (rsp)
        free(rsp);

    if (ret != 0)
        myst_panic("unexpected(): type=%u", type);

    return ret;
}

int myst_listener_ping(void)
{
    int ret = 0;
    int sock;
    void* rsp = NULL;
    size_t rsp_size;

    ECHECK(sock = myst_listener_get_sock());
    ECHECK(_send_request(sock, MYST_MESSAGE_PING, NULL, 0));
    ECHECK(_recv_response(sock, MYST_MESSAGE_PING, &rsp, &rsp_size));

    myst_eprintf("PING OKAY!!!\n");

done:

    if (rsp)
        free(rsp);

    return ret;
}

pid_t myst_listener_generate_tid(void)
{
    pid_t ret = 0;
    int sock;
    void* rsp = NULL;
    size_t rsp_size;
    const myst_message_type_t mt = MYST_MESSAGE_GENERATE_TID;

    ECHECK(sock = myst_listener_get_sock());
    ECHECK(_send_request(sock, mt, NULL, 0));
    ECHECK(_recv_response(sock, mt, &rsp, &rsp_size));

    if (!rsp || rsp_size != sizeof(pid_t))
        ERAISE(-ENOSYS);

    ret = *((pid_t*)rsp);

done:

    if (rsp)
        free(rsp);

    return ret;
}

/* called by parent for forked process */
int myst_listener_shutdown(void)
{
    int ret = 0;
    int sock = -1;
    static bool _shutdown;
    static myst_mutex_t _lock;

    myst_mutex_lock(&_lock);

    if (!_shutdown)
    {
        ECHECK(sock = _connect_to_listener(true));
        ECHECK(_send_request(sock, MYST_MESSAGE_SHUTDOWN, NULL, 0));
        _shutdown = true;
    }

done:

    if (sock >= 0)
        close(sock);

    myst_mutex_unlock(&_lock);

    return ret;
}

int myst_listener_call(
    myst_message_type_t mt,
    const void* req,
    size_t req_size,
    void** rsp_out,
    size_t* rsp_size_out)
{
    int ret = 0;
    int sock;
    void* rsp = NULL;
    size_t rsp_size;

    if (rsp_out)
        *rsp_out = NULL;

    if (rsp_size_out)
        *rsp_size_out = 0;

    if (mt == MYST_MESSAGE_NONE)
        ERAISE(-EINVAL);

    if (!rsp_out || !rsp_size_out)
        ERAISE(-EINVAL);

    ECHECK(sock = myst_listener_get_sock());
    ECHECK(_send_request(sock, mt, req, req_size));
    ECHECK(_recv_response(sock, mt, &rsp, &rsp_size));

    *rsp_out = rsp;
    *rsp_size_out = rsp_size;

done:

    if (ret != 0)
    {
        myst_eprintf("*** myst_listener_call(): ret=%d mt=%u\n", ret, mt);
    }

    return ret;
}

long myst_call_listener_helper(
    myst_message_type_t mt,
    const void* req,
    size_t req_size,
    size_t rsp_struct_size,
    void** rsp_out,
    size_t* rsp_size_out)
{
    long ret = 0;
    myst_response_t* rsp;
    size_t rsp_size;

    /* call into the listener */
    ECHECK(myst_listener_call(mt, req, req_size, (void**)&rsp, &rsp_size));

    if (rsp_size < rsp_struct_size)
        ERAISE(-EINVAL);

    ECHECK(rsp->retval);

    *rsp_out = rsp;
    *rsp_size_out = rsp_size;
    rsp = NULL;

done:

    if (rsp)
        free(rsp);

    return ret;
}

long myst_listener_wake(uint64_t addr)
{
    int ret = 0;
    myst_wake_request_t req = {.addr = addr};
    myst_wake_response_t* rsp = NULL;
    size_t rsp_size;

    ECHECK(myst_listener_call(
        MYST_MESSAGE_WAKE, &req, sizeof(req), (void**)&rsp, &rsp_size));

    ret = (int)rsp->retval;

done:

    if (rsp)
        free(rsp);

    return ret;
}
