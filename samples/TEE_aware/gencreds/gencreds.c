// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <myst/tee.h> //Included from the Mystikos installation. $(MYSTIKOS_INSTALL_DIR)/include
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int _verifier(myst_tee_identity_t* identity, void* ptr)
{
    // Expected Product ID: {1}
    const uint8_t PRODID[MYST_PRODUCT_ID_SIZE] = {1};
    // Expected security version: 1
    const int SVN = 1;

    // Returning 0 means pass.
    // We can easily expand this to more sophicated checks
    // based on unique_id, signer_id, etc.
    return memcmp(identity->product_id, PRODID, MYST_PRODUCT_ID_SIZE) ||
           identity->security_version != SVN;
}

int main()
{
    long ret;
    void* cert = NULL;
    void* pkey = NULL;
    size_t cert_size = 0, pkey_size = 0;

    const char* target = getenv("MYST_TARGET");
    if (!target)
    {
        printf("****I am in unknown environment, returning\n");
        return 0;
    }
    if (strcmp(target, "sgx") != 0)
    {
        printf("****I am in non-TEE, returning\n");
        return 0;
    }
    else
    {
        printf("****I am in an SGX TEE, I will proceed to generate and verify "
               "TEE credentials\n");
        ret = syscall(SYS_myst_gen_creds, &cert, &cert_size, &pkey, &pkey_size);
        assert(ret == 0);
        printf("Generated a self-signed certificate and a private key\n");

        ret = syscall(SYS_myst_verify_cert, cert, cert_size, _verifier, NULL);
        assert(ret == 0);
        printf("Verified the self-signed certificate\n");

        ret = syscall(
            SYS_myst_free_creds, cert, cert_size, pkey, pkey_size, NULL, 0);
        assert(ret == 0);
    }

    return 0;
}
