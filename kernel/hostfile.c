#include <sys/types.h>
#include <unistd.h>

#include <myst/buf.h>
#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/hostfile.h>
#include <myst/paths.h>
#include <myst/printf.h>
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

    ECHECK(ret = myst_tcall(SYS_open, params));

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

        if (myst_buf_append(&buf, locals->buf, n) != 0)
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

    return ret;
}

// Force copy a file from host to enclave.
// If enc_path doesn't exist, create.
// If enc_path already exists, overwrite;
// TODO keep host file's permission, mode. Set owner to root.
int myst_copy_host_file_to_enc(const char* host_path, const char* enc_path)
{
    int ret = 0;
    int fd = -1;
    void* buf = NULL;
    size_t buf_size;
    struct stat st;
    struct locals
    {
        char basename[PATH_MAX];
        char dirname[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!host_path || !enc_path)
        ERAISE(-EINVAL);

    ECHECK(myst_load_host_file(host_path, &buf, &buf_size));

    if (stat(enc_path, &st) == 0)
    {
        if ((myst_syscall_unlink(enc_path)) < 0)
        {
            myst_eprintf("kernel: failed to unlink file %s\n", enc_path);
            ERAISE(-EINVAL);
        }
    }
    else
    {
        if (!(locals = malloc(sizeof(struct locals))))
            ERAISE(-ENOMEM);

        ECHECK(myst_split_path(
            enc_path, locals->dirname, PATH_MAX, locals->basename, PATH_MAX));
        if (stat(locals->dirname, &st) == -1)
        {
            if ((myst_mkdirhier(locals->dirname, 0755)) != 0)
            {
                myst_eprintf("kernel: failed to mkdir %s\n", locals->dirname);
                ERAISE(-EINVAL);
            }
        }
        else if (!S_ISDIR(st.st_mode))
        {
            myst_eprintf(
                "kernel: enclave path %s is not a folder\n", locals->dirname);
            ERAISE(-EINVAL);
        }
    }
    if ((fd = creat(enc_path, 0644)) < 0)
    {
        myst_eprintf("kernel: failed to create file %s\n", enc_path);
        ERAISE(-EINVAL);
    }
    if ((myst_write_file_fd(fd, buf, buf_size)) < 0)
    {
        myst_eprintf("kernel: failed to write to file %s\n", enc_path);
        ERAISE(-EINVAL);
    }

done:

    if (fd >= 0)
        close(fd);

    if (buf)
        free(buf);

    if (locals)
        free(locals);

    return ret;
}

int myst_copy_host_files(
    const char** copy_host_files_data,
    size_t copy_host_files_size)
{
    int ret = 0;

    for (size_t i = 0; i < copy_host_files_size; i++)
    {
        ECHECK(myst_copy_host_file_to_enc(
            copy_host_files_data[i], copy_host_files_data[i]));
    }

done:

    return ret;
}
