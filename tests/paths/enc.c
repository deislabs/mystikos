// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <libos/realpath.h>
#include <libos/cwd.h>
#include <libos/paths.h>
#include <libos/strings.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "run_t.h"

int test_normalize(const char* toks[], const char* path)
{
    int ret = -1;
    char* s = NULL;

#if 1
    libos_toks_dump(toks);
#endif

    if (libos_path_normalize(toks) != 0)
        goto done;

#if 1
    libos_toks_dump(toks);
#endif

    if (libos_strjoin(toks, libos_tokslen(toks), NULL, "/", NULL, &s) != 0)
        goto done;

    if (strcmp(s, path) != 0)
        goto done;

    ret = 0;

done:

    if (s)
        free(s);

    return ret;
}

int run_ecall(void)
{
    /* Test libos_setcwd/libos_getcwd */
    {
        const char path[] = "/a/bb/ccc/dddd";
        char cwd[PATH_MAX];

        assert(libos_chdir(path) == 0);
        assert(libos_getcwd(cwd, sizeof(cwd)) != NULL);
        assert(strcmp(cwd, path) == 0);
    }

    /* Test libos_realpath */
    {
        libos_path_t path;

        assert(libos_realpath(".", &path) == 0);
        assert(strcmp(path.buf, "/a/bb/ccc/dddd") == 0);

        assert(libos_realpath("..", &path) == 0);
        assert(strcmp(path.buf, "/a/bb/ccc") == 0);

        assert(libos_realpath("../..", &path) == 0);
        assert(strcmp(path.buf, "/a/bb") == 0);

        assert(libos_realpath("../../..", &path) == 0);
        assert(strcmp(path.buf, "/a") == 0);

        assert(libos_realpath("../../../..", &path) == 0);
        assert(strcmp(path.buf, "/") == 0);

        assert(libos_realpath("../../../../..", &path) == 0);
        assert(strcmp(path.buf, "/") == 0);

        assert(libos_realpath("../../ddd", &path) == 0);
        assert(strcmp(path.buf, "/a/bb/ddd") == 0);
    }

    /* Test normalize */
    {
        {
            const char* toks[] = { "red", "green", "blue", NULL };
            assert(test_normalize(toks, "red/green/blue") == 0);
        }
        {
            const char* toks[] = { "red", "..", "blue", NULL };
            assert(test_normalize(toks, "blue") == 0);
        }
        {
            const char* toks[] = { "..", "blue", NULL };
            assert(test_normalize(toks, "blue") == 0);
        }
        {
            const char* toks[] = { "red", "green", "..", NULL };
            assert(test_normalize(toks, "red") == 0);
        }
        {
            const char* toks[] = { "..", NULL };
            assert(test_normalize(toks, "") == 0);
        }
        {
            const char* toks[] = { ".", "red", ".", "blue", ".", NULL };
            assert(test_normalize(toks, "red/blue") == 0);
        }
    }

    /* Test */

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    16*4096, /* NumHeapPages */
    4096, /* NumStackPages */
    2);   /* NumTCS */
