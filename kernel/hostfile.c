#include <sys/types.h>
#include <unistd.h>

#include <myst/buf.h>
#include <myst/eraise.h>
#include <myst/hostfile.h>
#include <myst/syscall.h>
#include <myst/tcall.h>
#include <myst/trace.h>
#include <myst/uid_gid.h>

static int _get_host_uid_gid(uid_t* host_uid, gid_t* host_gid)
{
    int ret = 0;

    ECHECK(myst_enc_uid_to_host(myst_syscall_geteuid(), host_uid));
    ECHECK(myst_enc_gid_to_host(myst_syscall_getegid(), host_gid));

done:
    return ret;
}

static int _host_open(const char* pathname, int flags, mode_t mode)
{
    int ret = 0;
    uid_t uid;
    gid_t gid;

    ECHECK(_get_host_uid_gid(&uid, &gid));

    long params[6] = {
        (long)pathname, (long)flags, (long)mode, (long)uid, (long)gid};

    ECHECK(ret = (int)myst_tcall(SYS_open, params));

done:
    return ret;
}

static int _host_close(int fd)
{
    long params[6] = {(long)fd};
    return (int)myst_tcall(SYS_close, params);
}

static ssize_t _host_read(int fd, void* buf, size_t count)
{
    long params[6] = {(long)fd, (long)buf, (long)count};
    return (ssize_t)myst_tcall(SYS_read, params);
}

int myst_load_host_file(const char* path, void** data_out, size_t* size_out)
{
    int ret = 0;
    int fd = -1;
    myst_buf_t buf = MYST_BUF_INITIALIZER;
    const size_t min_buf_size = 4096;
    struct locals
    {
        char buf[BUFSIZ];
    };
    struct locals* locals = NULL;

    myst_set_trace(true);

    if (data_out)
        *data_out = NULL;

    if (size_out)
        *size_out = 0;

    if (!path || !data_out || !size_out)
        ERAISE(-EINVAL);

    if (!(locals = calloc(1, sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if (myst_buf_reserve(&buf, min_buf_size) != 0)
        ERAISE(-ENOMEM);

    ECHECK(fd = _host_open(path, O_RDONLY, 0));

    for (;;)
    {
        ssize_t n = _host_read(fd, locals->buf, sizeof(locals->buf));
        ECHECK(n);

        if (n == 0)
            break;

        if (myst_buf_append(&buf, locals->buf, (size_t)n) != 0)
            ERAISE(-ENOMEM);
    }

    /* append a zero-terminator character */
    {
        char c = '\0';

        if (myst_buf_append(&buf, &c, 1) != 0)
            ERAISE(-ENOMEM);
    }

    *data_out = buf.data;
    buf.data = NULL;
    *size_out = buf.size - 1; /* don't count the zero terminator */

done:

    if (buf.data)
        free(buf.data);

    if (fd >= 0)
        _host_close(fd);

    if (locals)
        free(locals);

    myst_set_trace(false);

    return ret;
}
