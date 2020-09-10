// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <libos/atexit.h>
#include <libos/mount.h>
#include <libos/ramfs.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <string.h>
#include "run_t.h"

int run_ecall(void)
{
    libos_fs_t* fs1;
    libos_fs_t* fs2;

    /* create a new ramfs file system */
    assert(libos_init_ramfs(&fs1) == 0);

    /* create a new ramfs file system */
    assert(libos_init_ramfs(&fs2) == 0);

    /* mount the file system */
    assert(libos_mount(fs1, "/") == 0);

    /* resolve path to this file system */
    {
        char suffix[PATH_MAX];
        libos_fs_t* tmp;
        assert(libos_mount_resolve("/", suffix, &tmp) == 0);
        assert(strcmp(suffix, "/") == 0);
        assert(tmp == fs1);
    }

    /* release the file system */
    assert((*fs1->fs_release)(fs1) == 0);
    assert((*fs2->fs_release)(fs2) == 0);

    libos_call_atexit_functions();

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,         /* ProductID */
    1,         /* SecurityVersion */
    true,      /* Debug */
    16 * 4096, /* NumHeapPages */
    4096,      /* NumStackPages */
    2);        /* NumTCS */
