#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <myst/buf.h>
#include <myst/eraise.h>
#include <myst/fdtable.h>
#include <myst/kernel.h>
#include <myst/list.h>
#include <myst/mutex.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/signal.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/time.h>

/* ATTN: this will be the maximum number of forked processes */
#define MAX_CONNECTIONS 32

static void _init_sockaddr(struct sockaddr_un* addr)
{
    pid_t pid = __myst_kernel_args.target_tid;

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

int _accept_connection(int lsock, connection_t** conn_out)
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

long myst_syscall_run_listener(void)
{
    long ret = 0;
    int lsock = -1;
    connection_t* conn = NULL;
    struct locals
    {
        struct sockaddr_un addr;
        struct pollfd fds[MAX_CONNECTIONS + 1]; /* extra for listener sock */
        uint8_t buf[BUFSIZ];
    };
    struct locals* locals;

    if (!(locals = calloc(1, sizeof(struct locals))))
        ERAISE(-ENOMEM);

    _init_sockaddr(&locals->addr);

    if ((lsock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
        ERAISE(-errno);

    if (bind(lsock, (struct sockaddr*)&locals->addr, sizeof(locals->addr)) != 0)
        ERAISE(-errno);

    if (listen(lsock, 10) != 0)
        ERAISE(-errno);

    if (_set_blocking(lsock, false) != 0)
        ERAISE(-ENOSYS);

    for (;;)
    {
        size_t nfds = 0;

        /* watch input events on the listener socket */
        locals->fds[nfds].fd = lsock;
        locals->fds[nfds].events = POLLIN;
        nfds++;

        /* watch events on the connections */
        {
            connection_t* p = (connection_t*)_connections.head;

            for (; p; p = p->next)
            {
                locals->fds[nfds].fd = p->sock;
                locals->fds[nfds].events = p->events;
                locals->fds[nfds].revents = 0;
                nfds++;
            }
        }

        /* wait for events. */
        if (poll(locals->fds, nfds, -1) <= 0)
        {
            /* no events so retry */
            continue;
        }

        /* handle the polled events */
        for (size_t i = 0; i < nfds; i++)
        {
            struct pollfd* pollfd = &locals->fds[i];

            if (pollfd->revents == 0)
                continue;

            /* accept a new connection */
            if (pollfd->fd == lsock)
            {
                if (pollfd->revents & POLLIN)
                {
                    if (_connections.size == MAX_CONNECTIONS)
                    {
                        myst_eprintf("****** too many connections\n");
                        continue;
                    }

                    if (_accept_connection(lsock, &conn) < 0)
                    {
                        myst_eprintf("****** _accept_connection() failed\n");
                        continue;
                    }

                    /* watch input events initially */
                    conn->events = POLLIN;

                    /* add to the list of connections */
                    myst_list_append(&_connections, (myst_list_node_t*)conn);
                    conn = NULL;
                }
            }
            else if ((locals->fds[i].revents & POLLOUT)) /* client output */
            {
                connection_t* conn;
                ssize_t n;

                /* find the client with this file descriptor */
                if (!(conn = _find_connection(locals->fds[i].fd)))
                {
                    myst_eprintf("****** connection not found\n");
                    continue;
                }

                /* read all client input */
                while ((n = write(
                            conn->sock, conn->output.data, conn->output.size)) >
                       0)
                {
                    myst_buf_remove(&conn->output, 0, n);

                    if (conn->output.size == 0)
                        conn->events &= ~EPOLLOUT;
                }
            }
            else if ((locals->fds[i].revents & POLLIN)) /* client input */
            {
                ssize_t n;
                connection_t* conn;

                /* find the client with this file descriptor */
                if (!(conn = _find_connection(locals->fds[i].fd)))
                {
                    myst_eprintf("****** connection not found\n");
                    continue;
                }

                /* read all client input */
                while ((n = read(
                            conn->sock, locals->buf, sizeof(locals->buf))) > 0)
                {
                    if (myst_buf_append(&conn->input, locals->buf, n) != 0)
                        ERAISE(-ENOMEM);
                }

                if (conn->input.size)
                {
                    if (myst_buf_append(
                            &conn->output,
                            conn->input.data,
                            conn->input.size) != 0)
                    {
                        ERAISE(-ENOMEM);
                    }

#if 0
                    printf("input{%.*s}\n", (int)conn->input.size,
                        (const char*)conn->input.data);
#endif

                    myst_buf_clear(&conn->input);
                    conn->events |= EPOLLOUT;
                }

                if (n == 0)
                {
                    myst_list_remove(&_connections, (myst_list_node_t*)conn);
                    _release_connection(conn);
                }
            }
        }
    }

done:

    if (lsock > 0)
        myst_syscall_close(lsock);

    if (conn)
        free(conn);

    if (locals)
        free(locals);

    return ret;
}
