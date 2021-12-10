#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>

#include <myst/eraise.h>
#include <myst/syscall.h>

MYST_INLINE size_t _min(size_t x, size_t y)
{
    return (x < y) ? x : y;
}

long myst_syscall_copy_file_range(
    int fd_in,
    off_t* off_in,
    int fd_out,
    off_t* off_out,
    size_t len,
    unsigned int flags)
{
    long ret = 0;
    ssize_t nwritten = 0;
    struct locals
    {
        char buf[BUFSIZ];
    };
    struct locals* locals = NULL;

    if (flags != 0)
        ERAISE(-EINVAL);

    if (len > SSIZE_MAX)
        ERAISE(-EFBIG);

    if (fd_in < 0 || fd_out < 0)
        ERAISE(-EINVAL);

    if (fd_in == fd_out && (off_in < off_out && off_out < off_in + len) &&
        (off_out < off_in && off_in < off_out + len))
        ERAISE(-EINVAL);

    struct stat sbuf_in;
    struct stat sbuf_out;
    ECHECK(fstat(fd_in, &sbuf_in));
    ECHECK(fstat(fd_out, &sbuf_out));
    if (S_ISDIR(sbuf_in.st_mode) || S_ISDIR(sbuf_out.st_mode))
        ERAISE(-EISDIR);
    if (!S_ISREG(sbuf_in.st_mode) || !S_ISREG(sbuf_out.st_mode))
        ERAISE(-EINVAL);

    long out_flags = myst_syscall_fcntl(fd_out, F_GETFL, 0);
    if (out_flags & O_APPEND)
        ERAISE(-EBADF);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    off_t cur_off_in;
    off_t cur_off_out;

    if (off_in)
    {
        cur_off_in = *off_in;
    }
    else
    {
        ECHECK_ERRNO(cur_off_in = lseek(fd_in, 0, SEEK_CUR));
    }

    if (off_out)
    {
        cur_off_out = *off_out;
    }
    else
    {
        ECHECK_ERRNO(cur_off_out = lseek(fd_out, 0, SEEK_CUR));
    }

    /* copy from fd_in to fd_out */
    {
        ssize_t n;
        size_t r = len;
        while (r > 0)
        {
            n = pread(fd_in, locals->buf, _min(r, BUFSIZ), cur_off_in);
            ECHECK(n);

            ssize_t m = pwrite(fd_out, locals->buf, n, cur_off_out);
            ECHECK_ERRNO(m);

            nwritten += m;
            cur_off_in += m;
            cur_off_out += m;
            r -= m;
        }
    }

    if (off_in)
    {
        *off_in = cur_off_in;
    }
    else
    {
        ECHECK_ERRNO(lseek(fd_in, cur_off_in, SEEK_SET));
    }

    if (off_out)
    {
        *off_out = cur_off_out;
    }
    else
    {
        ECHECK_ERRNO(lseek(fd_out, cur_off_out, SEEK_SET));
    }

    /* return the number of bytes written to fd_out */
    ret = nwritten;

done:

    if (locals)
        free(locals);

    return ret;
}
