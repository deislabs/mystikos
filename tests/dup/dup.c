// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char alpha[] = "abcdefghijklmnopqrstuvwxyz";

static FILE* _out;

void test_dup(int version, int arg)
{
    FILE* out;
    FILE* in;

    fprintf(_out, "=== start test (dup: version=%d arg=%o)\n", version, arg);

    /* write /tmp/file */
    {
        int fd;

        if (!(out = fopen("/tmp/file", "w")))
            assert(false);

        switch (version)
        {
            case 1: /* dup() */
            {
                close(STDOUT_FILENO);
                fd = dup(fileno(out));
                break;
            }
            case 2: /* dup2() */
            {
                fd = dup2(fileno(out), STDOUT_FILENO);
                break;
            }
            case 3: /* dup3() */
            {
                fd = dup3(fileno(out), STDOUT_FILENO, arg);

                if (arg == O_CLOEXEC)
                {
                    int fdflags = fcntl(STDOUT_FILENO, F_GETFD);
                    assert(fdflags == FD_CLOEXEC);
                }

                break;
            }
            case 4: /* F_DUPFD */
            {
                close(STDOUT_FILENO);
                fd = fcntl(fileno(out), arg, STDOUT_FILENO);

                if (arg == F_DUPFD_CLOEXEC)
                {
                    int fdflags = fcntl(STDOUT_FILENO, F_GETFD);
                    assert(fdflags == FD_CLOEXEC);
                }
                break;
            }
            default:
            {
                assert(false);
            }
        }

        assert(fd == STDOUT_FILENO);

        // printf("%s\n", alpha);
        write(fd, alpha, sizeof(alpha) - 1);

        fflush(out);
        fclose(out);
    }

    /* read /tmp/file */
    {
        char buf[128];

        assert(access("/tmp/file", R_OK) == 0);

        if (!(in = fopen("/tmp/file", "r")))
            assert(false);

        size_t n = fread(buf, 1, sizeof(buf), in);
        assert(n == sizeof(alpha) - 1);
        assert(memcmp(buf, alpha, sizeof(alpha) - 1) == 0);
        fclose(in);
    }

    fprintf(_out, "=== passed test (dup: version=%d arg=%o)\n", version, arg);
}

int main(int argc, const char* argv[])
{
    int fd;

    assert((fd = dup(STDOUT_FILENO)) >= 0);
    assert(_out = fdopen(fd, "w"));

    test_dup(1, 0);
    test_dup(2, 0);
    test_dup(3, 0);
    test_dup(3, O_CLOEXEC);
    test_dup(4, F_DUPFD);
    test_dup(4, F_DUPFD_CLOEXEC);
    close(fd);

    fprintf(_out, "=== passed test (%s)\n", argv[0]);

    return 0;
}
