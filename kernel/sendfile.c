#include <stdlib.h>
#include <sys/sendfile.h>

#include <myst/eraise.h>
#include <myst/syscall.h>

long myst_syscall_sendfile(int out_fd, int in_fd, off_t* offset, size_t count)
{
    long ret = 0;
    ssize_t nwritten = 0;
    off_t original_offset = 0;
    struct vars
    {
        char buf[BUFSIZ];
    };
    struct vars* v = NULL;

    if (out_fd < 0 || in_fd < 0)
        ERAISE(-EINVAL);

    if (!(v = malloc(sizeof(struct vars))))
        ERAISE(-ENOMEM);

    /* if offset is not null, set file offset to this value */
    if (offset)
    {
        /* get the current offset */
        original_offset = lseek(in_fd, 0, SEEK_CUR);
        ECHECK(original_offset);

        /* seek the new offset */
        ECHECK(lseek(in_fd, *offset, SEEK_SET));
    }

    /* copy from in_fd to out_fd */
    {
        ssize_t n;
        size_t r = count;

        while (r > 0 && (n = read(in_fd, v->buf, sizeof(v->buf))) > 0)
        {
            ssize_t m = write(out_fd, v->buf, n);
            ECHECK(m);

            if (m != n)
                ERAISE(EIO);

            nwritten += m;
            r -= m;
        }
    }

    /* if offset is null, restore the original offset */
    if (offset)
    {
        /* get the final offset */
        off_t final_offset = lseek(in_fd, 0, SEEK_CUR);
        ECHECK(final_offset);

        if (*offset + nwritten != final_offset)
            ERAISE(-EIO);

        /* restore the original offset */
        ECHECK(lseek(in_fd, original_offset, SEEK_SET));
        *offset = final_offset;
    }

    /* return the number of bytes written to out_fd */
    ret = nwritten;

done:

    if (v)
        free(v);

    return ret;
}
