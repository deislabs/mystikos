// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdlib.h>
#include <string.h>

#include <myst/crash.h>
#include <myst/eraise.h>
#include <myst/malloc.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/strings.h>
#include <myst/tcall.h>

int myst_console_printf(int fd, const char* format, ...)
{
    int ret = 0;
    va_list ap;
    int count;
    struct locals
    {
        char buf[1024];
    };
    struct locals* locals = NULL;

    /* use raw malloc since debug-malloc indirectly calls this function */
    if (!(locals = myst_malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    va_start(ap, format);
    count = vsnprintf(locals->buf, sizeof(locals->buf), format, ap);
    va_end(ap);

    if (count < 0 || (size_t)count >= sizeof(locals->buf))
        ERAISE(-EINVAL);

    ECHECK(myst_tcall_write_console(fd, locals->buf, (size_t)count));

done:

    if (locals)
    {
        /* use raw free since this was allocated with raw malloc */
        myst_free(locals);
    }

    return ret;
}

int myst_console_vprintf(int fd, const char* format, va_list ap)
{
    int ret = 0;
    int count;
    struct locals
    {
        char buf[1024];
    };
    struct locals* locals = NULL;

    /* use raw malloc since debug-malloc indirectly calls this function */
    if (!(locals = myst_malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    count = vsnprintf(locals->buf, sizeof(locals->buf), format, ap);

    if (count < 0 || (size_t)count >= sizeof(locals->buf))
        return -EINVAL;

    ECHECK(myst_tcall_write_console(fd, locals->buf, (size_t)count));

done:

    if (locals)
    {
        /* use raw free since this was allocated with raw malloc */
        myst_free(locals);
    }

    return ret;
}

int myst_veprintf(const char* format, va_list ap)
{
    return myst_console_vprintf(STDERR_FILENO, format, ap);
}

int myst_eprintf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = myst_console_vprintf(STDERR_FILENO, format, ap);
    va_end(ap);

    return n;
}
