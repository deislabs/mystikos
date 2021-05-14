// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <myst/gcov.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int __popcountdi2(unsigned long a);

static FILE* _file(long x)
{
    FILE* stream = (FILE*)x;

    if (stream == MYST_GCOV_STDERR)
        return stderr;

    return stream;
}

long myst_gcov(const char* func, long p[6])
{
    if (strcmp(func, "myst_gcov_abort") == 0)
    {
        abort();
    }
    else if (strcmp(func, "myst_gcov_fopen") == 0)
    {
        return (long)fopen((const char*)p[0], (const char*)p[1]);
    }
    else if (strcmp(func, "myst_gcov_fdopen") == 0)
    {
        return (long)fdopen((int)p[0], (const char*)p[1]);
    }
    else if (strcmp(func, "myst_gcov_fread") == 0)
    {
        return (long)fread(
            (void*)p[0], (size_t)p[1], (size_t)p[2], _file(p[3]));
    }
    else if (strcmp(func, "myst_gcov_fwrite") == 0)
    {
        return (long)fwrite(
            (const void*)p[0], (size_t)p[1], (size_t)p[2], _file(p[3]));
    }
    else if (strcmp(func, "myst_gcov_fseek") == 0)
    {
        return (long)fseek(_file(p[0]), (long)p[1], (int)p[2]);
    }
    else if (strcmp(func, "myst_gcov_ftell") == 0)
    {
        return (long)ftell(_file(p[0]));
    }
    else if (strcmp(func, "myst_gcov_fclose") == 0)
    {
        return (long)fclose(_file(p[0]));
    }
    else if (strcmp(func, "myst_gcov_setbuf") == 0)
    {
        setbuf(_file(p[0]), (char*)p[1]);
    }
    else if (strcmp(func, "myst_gcov_open") == 0)
    {
        return (long)open((const char*)p[0], (int)p[1], (int)p[2]);
    }
    else if (strcmp(func, "myst_gcov_close") == 0)
    {
        return (long)close((int)p[0]);
    }
    else if (strcmp(func, "myst_gcov_fcntl") == 0)
    {
        return (long)fcntl((int)p[0], (int)p[1], (long)p[2]);
    }
    else if (strcmp(func, "myst_gcov_getenv") == 0)
    {
        return (long)getenv((const char*)p[0]);
    }
    else if (strcmp(func, "myst_gcov___errno_location") == 0)
    {
        return (long)__errno_location();
    }
    else if (strcmp(func, "myst_gcov_getpid") == 0)
    {
        return (long)getpid();
    }
    else if (strcmp(func, "myst_gcov_strtol") == 0)
    {
        return (long)strtol((const char*)p[0], (char**)p[1], (int)p[2]);
    }
    else if (strcmp(func, "myst_gcov_access") == 0)
    {
        return (long)access((const char*)p[0], (int)p[1]);
    }
    else if (strcmp(func, "myst_gcov_mkdir") == 0)
    {
        return (long)mkdir((const char*)p[0], (int)p[1]);
    }
    else if (strcmp(func, "myst_gcov___popcountdi2") == 0)
    {
        return (long)__popcountdi2((unsigned long)p[0]);
    }
    else
    {
        fprintf(stderr, "unhandled gcov function: %s\n", func);
        fflush(stderr);
        abort();
    }

    return 0;
}
