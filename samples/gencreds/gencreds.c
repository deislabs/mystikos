// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Extended syscall */

int main(int argc, const char* argv[])
{
    long ret;
    const long SYS_myst_gen_creds = 1009;
    const long SYS_myst_free_creds = 1010;
    void* cert = NULL;
    size_t cert_size = 0;
    void* pkey = NULL;
    size_t pkey_size = 0;

    setenv("AZDCAP_DEBUG_LOG_LEVEL", "0", 1);

    ret = syscall(SYS_myst_gen_creds, &cert, &cert_size, &pkey, &pkey_size);
    assert(ret == 0);

    printf(
        "ret=%ld cert=%p cert_size=%zu pkey=%p pkey_size=%zu\n",
        ret,
        cert,
        cert_size,
        pkey,
        pkey_size);

    ret = syscall(SYS_myst_free_creds, cert, cert_size, pkey, pkey_size);
    assert(ret == 0);

    return 0;
}
