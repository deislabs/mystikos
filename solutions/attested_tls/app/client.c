// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "tlscli.h"

#define TLS_CERT_PATH "./cert.der"
#define TLS_PKEY_PATH "./private_key.pem"
#define SERVER_PORT "17500"

static tlscli_err_t tlsError;

static tlscli_t* trustedChannel;

static int load_file(const char* path, void** buf, size_t* n)
{
    FILE* f;
    long size;

    if ((f = fopen(path, "rb")) == NULL)
        return (-1);

    fseek(f, 0, SEEK_END);
    if ((size = ftell(f)) == -1)
    {
        fclose(f);
        return (-1);
    }
    fseek(f, 0, SEEK_SET);

    *n = (size_t)size;

    if ((*buf = calloc(1, *n)) == NULL)
    {
        fclose(f);
        return (-1);
    }

    if (fread(*buf, 1, *n, f) != *n)
    {
        fclose(f);
        free(*buf);
        *buf = NULL;
        return (-1);
    }

    fclose(f);

    return (0);
}

static int trusted_channel_init(const char* serverIP)
{
    int rc = 1;
    void* cert = NULL;
    size_t cert_size = 0;
    void* pkey = NULL;
    size_t pkey_size = 0;
    const long SYS_myst_gen_creds = 1009;
    const long SYS_myst_free_creds = 1010;
    bool enclave_mode = false;

    if ((rc = tlscli_startup(&tlsError)) != 0)
    {
        printf("client Agent failed! tlscli_startup\n");
        goto done;
    }

    char* target = getenv("MYST_TARGET");
    if (target && strcmp(target, "sgx") == 0)
    {
        enclave_mode = true;
        // The existence of the manifesto file indicates we are running in
        // an enclave. Ask the kernel for help.
        int ret =
            syscall(SYS_myst_gen_creds, &cert, &cert_size, &pkey, &pkey_size);
        if (ret != 0)
        {
            fprintf(stderr, "Error: failed to generate TLS credentials\n");
            goto done;
        }
    }
    else
    {
        // Load cert/pkey from files in non-enclave mode.
        if (load_file(TLS_CERT_PATH, &cert, &cert_size))
        {
            fprintf(
                stderr, "Error: failed to load cert file %s\n", TLS_CERT_PATH);
            goto done;
        }
        if (load_file(TLS_PKEY_PATH, &pkey, &pkey_size))
        {
            fprintf(
                stderr,
                "Error: failed to load private key file %s\n",
                TLS_PKEY_PATH);
            goto done;
        }
    }

    if ((rc = tlscli_connect(
             true,
             serverIP,
             SERVER_PORT,
             cert,
             cert_size,
             pkey,
             pkey_size,
             &trustedChannel,
             &tlsError)) != 0)
    {
        printf("tlscli_connect failed!\n");
        goto done;
    }

    rc = 0;
done:

    if (cert || pkey)
    {
        if (enclave_mode)
            syscall(SYS_myst_free_creds, cert, cert_size, pkey, pkey_size);
        else
        {
            free(cert);
            free(pkey);
        }
    }

    if (rc != 0)
    {
        tlscli_destroy(trustedChannel, &tlsError);
        tlscli_shutdown(&tlsError);
    }

    return rc;
}

int main(int argc, char** argv)
{
    int result = 0;
    char* serverIP = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "usage: %s serverIP\n", argv[0]);
        return 1;
    }
    serverIP = argv[1];

    trusted_channel_init(serverIP);
    if (trustedChannel == NULL)
    {
        fprintf(stderr, "server: failed to establish channel\n");
        goto done;
    }

done:
    tlscli_destroy(trustedChannel, &tlsError);
    tlscli_shutdown(&tlsError);
    return result;
}
