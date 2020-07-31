// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <libos/realpath.h>
#include <libos/cwd.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "run_t.h"

int run_ecall(void)
{
    /* Test libos_setcwd/libos_getcwd */
    {
        const char path[] = "/a/bb/ccc/dddd";
        libos_path_t cwd;

        assert(libos_setcwd(path) == 0);
        assert(libos_getcwd(&cwd) == 0);
        assert(strcmp(cwd.buf, path) == 0);
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

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    16*4096, /* NumHeapPages */
    4096, /* NumStackPages */
    2);   /* NumTCS */
