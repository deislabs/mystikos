#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>

#include <myst/eraise.h>
#include <myst/syscall.h>

MYST_INLINE size_t _min(size_t x, size_t y)
{
    return (x < y) ? x : y;
}

long myst_syscall_sendfile(int out_fd, int in_fd, off_t* offset, size_t count)
{
    long ret = 0;
    ssize_t nwritten = 0;
    off_t original_offset = 0;
    struct locals
    {
        char buf[BUFSIZ];
    };
    struct locals* locals = NULL;

    // Note: according to the Linux documentation, in_fd must be a file that
    // can be passed as the fd argument to mmap(). It cannot be a socket.

    // Note: according to the Linux documentaiton, out_fd can be any kind of
    // file (including a socket).

    if (out_fd < 0 || in_fd < 0)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* if offset is not null, set file offset to this value */
    if (offset)
    {
        /* get the current offset */
        ECHECK_ERRNO(original_offset = lseek(in_fd, 0, SEEK_CUR));

        /* seek the new offset */
        ECHECK_ERRNO(lseek(in_fd, *offset, SEEK_SET));
    }

    /* copy from in_fd to out_fd */
    {
        ssize_t n;
        size_t r = count;

        while (r > 0 && (n = read(in_fd, locals->buf, _min(r, BUFSIZ))) > 0)
        {
            ssize_t m = write(out_fd, locals->buf, n);

            if (m == -1 && errno == EAGAIN)
            {
                /* rewind in_fd by n bytes (since they were not written) */
                lseek(in_fd, -n, SEEK_CUR);

                /* report any bytes that were written */
                if (nwritten > 0)
                    break;

                /* no bytes written yet, so raise EAGAIN */
                ERAISE(-EAGAIN);
            }

            ECHECK_ERRNO(m);

            nwritten += m;
            r -= m;

            /* If only part of the data is written */
            if (m < n)
            {
                /* rewind in_fd by n-m bytes (since they were not written) */
                lseek(in_fd, -(n - m), SEEK_CUR);
                break;
            }
        }
    }

    /* if offset is not null, restore the original offset */
    if (offset)
    {
        /* get the final offset */
        off_t final_offset = lseek(in_fd, 0, SEEK_CUR);
        ECHECK_ERRNO(final_offset);

        /* check that the offset is correct */
        if (*offset + nwritten != final_offset)
            ERAISE(-EIO);

        /* restore the original offset */
        ECHECK_ERRNO(lseek(in_fd, original_offset, SEEK_SET));
        *offset = final_offset;
    }

    /* return the number of bytes written to out_fd */
    ret = nwritten;

done:

    if (locals)
        free(locals);

    return ret;
}
