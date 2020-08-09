#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <openenclave/internal/print.h>
#include <openenclave/corelibc/stdio.h>
#include "posix_syscall.h"
#include "posix_io.h"
#include "posix_signal.h"
#include "posix_ocalls.h"
#include "posix_panic.h"

#include "posix_warnings.h"

int posix_puts(const char* str)
{
    ssize_t retval;
    size_t len = strlen(str);

    posix_lock_kill();

    if (posix_write_ocall(&retval, STDOUT_FILENO, str, len) != OE_OK)
    {
        POSIX_PANIC("unexpected");
    }

    posix_unlock_kill();

    if (retval < 0 || (size_t)retval != len)
        return -1;

    return 0;
}

int posix_printf(const char* fmt, ...)
{
    /* ATTN: use dynamic memory */
    char buf[4096];
    ssize_t retval;

    va_list ap;
    va_start(ap, fmt);
    int n = oe_vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (n > 0)
    {
        posix_lock_kill();

        if (posix_write_ocall(&retval, STDOUT_FILENO, buf, (size_t)n) != OE_OK)
        {
            POSIX_PANIC("unexpected");
        }

        posix_unlock_kill();

        posix_dispatch_signal();
        return (int)retval;
    }

    return n;
}

ssize_t posix_write(int fd, const void* buf, size_t count)
{
    if (fd == STDOUT_FILENO || fd == STDERR_FILENO)
    {
        ssize_t retval;

        posix_lock_kill();

        if (posix_write_ocall(&retval, fd, buf, count) != OE_OK)
        {
            POSIX_PANIC("unexpected");
        }

        posix_unlock_kill();

        posix_dispatch_signal();
        return (ssize_t)retval;
    }

    POSIX_PANIC("unexpected");
    return -EBADFD;
}

ssize_t posix_writev(int fd, const struct iovec *iov, int iovcnt)
{
    if (fd == STDOUT_FILENO || fd == STDERR_FILENO)
    {
        size_t count = 0;

        for (int i = 0; i < iovcnt; i++)
        {
            ssize_t retval;
            const char* p = iov[i].iov_base;
            size_t n = iov[i].iov_len;

            posix_lock_kill();

            if (posix_write_ocall(&retval, fd, p, n) != OE_OK)
            {
                POSIX_PANIC("unexpected");
                return -1;
            }

            posix_unlock_kill();

            if (retval != (ssize_t)n)
            {
                POSIX_PANIC("unexpected");
                break;
            }

            count += (size_t)retval;
        }

        posix_dispatch_signal();
        return (ssize_t)count;
    }

    POSIX_PANIC("unexpected");
    return -EBADFD;
}
