// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include "./syscall.h"
#include "./mmanutils.h"
#include <sys/mount.h>
#include "run_t.h"
#include "elfutils.h"
#include <oel/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <lthread.h>
#include <setjmp.h>

typedef long (*syscall_callback_t)(long n, long params[6]);

#define ARGV0 "/root/oe-libos/build/bin/samples/split/main"

static void _setup_hostfs(void)
{
    if (oe_load_module_host_file_system() != OE_OK)
    {
        fprintf(stderr, "oe_load_module_host_file_system() failed\n");
        assert(false);
    }

    if (mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL) != 0)
    {
        fprintf(stderr, "mount() failed\n");
        assert(false);
    }
}

static void _teardown_hostfs(void)
{
    if (umount("/") != 0)
    {
        fprintf(stderr, "umount() failed\n");
        assert(false);
    }
}

static int _enter_crt(void)
{
    const char* argv[] = { "arg0", ARGV0, "arg2", NULL };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    const char* envp[] = { "ENV0=zero", "ENV1=one", "ENV2=two", NULL };
    size_t envc = sizeof(envp) / sizeof(envp[0]) - 1;

    return elf_enter_crt(argc, argv, envc, envp);
}

int run_ecall(void)
{
    const size_t MMAN_SIZE = 16 * 1024 * 1024;

    if (oel_setup_mman(MMAN_SIZE) != 0)
    {
        fprintf(stderr, "_setup_mman() failed\n");
        assert(false);
    }

    _setup_hostfs();

    int ret = _enter_crt();

    _teardown_hostfs();
    oel_teardown_mman();

    printf("ret=%d\n", ret);

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    16*4096, /* NumHeapPages */
    4096, /* NumStackPages */
    4);   /* NumTCS */
