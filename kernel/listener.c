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
#include <myst/mutex.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/signal.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/time.h>

/* ATTN: this will be the maximum number of forked processes */
#define MAX_CONNECTIONS 32

#define MAGIC 0x425e6bdeed0a46f4

typedef enum message_type
{
    MT_NONE,
    MT_PING = 1,
    MT_SHUTDOWN = 2,
} message_type_t;

/* all messages begin with this struct */
typedef struct message
{
    uint64_t magic;
    uint64_t type;
    uint64_t size;
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

static int _enqueue_reponse(
    connection_t* conn,
    message_type_t type,
    const void* data,
    size_t size)
{
    int ret = 0;
    message_t m = {.magic = MAGIC, .type = type, .size = size};

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

static int _handle_request(connection_t* conn, const message_t* message)
{
    int ret = 0;

    switch (message->type)
    {
        case MT_PING:
        {
            myst_eprintf("MT_PING!!!\n");
            ECHECK(_enqueue_reponse(conn, MT_PING, "ping", 5));
            break;
        }
        case MT_SHUTDOWN:
        {
            myst_eprintf("MT_SHUTDOWN!!!\n");
            break;
        }
    }

    /* remove the request message from the input buffer */
    myst_buf_remove(&conn->input, 0, sizeof(message_t) + message->size);

done:
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
            const bool shutdown = (m->type == MT_SHUTDOWN);

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

static int _get_listener_connection(void)
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

    while (r > 0)
    {
        ssize_t n = write(fd, p, r);

        if (n <= 0)
            ERAISE(-errno);

        p += n;
        r -= (size_t)n;
    }

done:

    return ret;
}

static ssize_t _readn(int fd, void* data, size_t size)
{
    ssize_t ret = 0;
    uint8_t* p = (uint8_t*)data;
    size_t r = size;

    while (r > 0)
    {
        ssize_t n = read(fd, p, r);

        if (n <= 0)
            ERAISE(-errno);

        p += n;
        r -= (size_t)n;
    }

done:

    return ret;
}

static int _recv_response(
    int sock,
    message_type_t type,
    message_t** message_out)
{
    int ret = 0;
    message_t m;
    message_t* message = NULL;

    if (message_out)
        *message_out = NULL;

    if (_readn(sock, &m, sizeof(m)) != sizeof(m))
        ERAISE(-errno);

    if (m.magic != MAGIC)
        ERAISE(-EINVAL);

    if (m.type != type)
        ERAISE(-EINVAL);

    if (!(message = malloc(sizeof(m) + m.size)))
        ERAISE(-ENOMEM);

    memcpy(message, &m, sizeof(m));

    if (m.size)
    {
        if (_readn(sock, message->data, m.size) != (ssize_t)m.size)
            ERAISE(-errno);
    }

    *message_out = message;
    message = NULL;

done:

    if (message)
        free(message);

    return ret;
}

static int _send_request(
    int sock,
    message_type_t type,
    const void* data,
    size_t size)
{
    int ret = 0;
    message_t m = {.magic = MAGIC, .type = type, .size = size};

    if (_writen(sock, &m, sizeof(m)) != sizeof(m))
        ERAISE(-errno);

    if (data && size)
    {
        if (_writen(sock, data, size) != (ssize_t)size)
            ERAISE(-errno);
    }

done:
    return ret;
}

int myst_ping_listener(void)
{
    int ret = 0;
    int sock;
    message_t* message = NULL;

    ECHECK(sock = _get_listener_connection());
    ECHECK(_send_request(sock, MT_PING, NULL, 0));
    ECHECK(_recv_response(sock, MT_PING, &message));

    myst_eprintf("PING OKAY!!!\n");

done:

    if (message)
        free(message);

    return ret;
}

int myst_shutdown_listener(void)
{
    int ret = 0;
    int sock = -1;
    static bool _shutdown;
    static myst_mutex_t _lock;

    myst_mutex_lock(&_lock);

    if (!_shutdown)
    {
        message_t m = {.magic = MAGIC, .type = MT_SHUTDOWN};

        ECHECK(sock = _connect_to_listener(true));

        if (write(sock, &m, sizeof(m)) != sizeof(m))
            ERAISE(-errno);

        _shutdown = true;
    }

done:

    if (sock >= 0)
        close(sock);

    myst_mutex_unlock(&_lock);

    return ret;
}
