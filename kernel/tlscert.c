// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <myst/eraise.h>
#include <myst/printf.h>
#include <myst/tcall.h>
#include <myst/tee.h>
#include <myst/tlscert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int _create_tls_credentials(myst_fs_t* fs, bool separate_report)
{
    int ret = -EINVAL;
    uint8_t* cert = NULL;
    size_t cert_size = 0;
    uint8_t* pkey = NULL;
    size_t pkey_size = 0;
    uint8_t* report = NULL;
    size_t report_size = 0;
    const char* certificate_path = MYST_CERTIFICATE_PATH;
    const char* private_key_path = MYST_PRIVATE_KEY_PATH;
    const char* report_path = MYST_ATTESTATION_REPORT_PATH;

    assert(fs != NULL);

#ifdef USE_TMPFS
    /* clip the "/tmp" prefix from certificate_path and private_key_path */
    {
        const char prefix[] = "/tmp";
        const size_t len = sizeof(prefix) - 1;

        if (strncmp(certificate_path, prefix, len) == 0)
            certificate_path += len;

        if (strncmp(private_key_path, prefix, len) == 0)
            private_key_path += len;

        if (strncmp(report_path, prefix, len) == 0)
            report_path += len;
    }
#endif

    myst_file_t* file = NULL;
    int flags = O_CREAT | O_WRONLY;

    if (!separate_report)
    {
        long params[6] = {
            (long)&cert, (long)&cert_size, (long)&pkey, (long)&pkey_size};
        ECHECK(myst_tcall(MYST_TCALL_GEN_CREDS, params));
    }
    else
    {
        long params[6] = {(long)&cert,
                          (long)&cert_size,
                          (long)&pkey,
                          (long)&pkey_size,
                          (long)&report,
                          (long)&report_size};
        ECHECK(myst_tcall(MYST_TCALL_GEN_CREDS_EX, params));
    }

    // Save the certificate
    ECHECK((fs->fs_open)(fs, certificate_path, flags, 0444, NULL, &file));
    ECHECK((fs->fs_write)(fs, file, cert, cert_size) == (int64_t)cert_size);
    ECHECK((fs->fs_close)(fs, file));
    file = NULL;

    // Save the private key
    ECHECK((fs->fs_open)(fs, private_key_path, flags, 0444, NULL, &file));
    ECHECK((fs->fs_write)(fs, file, pkey, pkey_size) == (int64_t)pkey_size);
    ECHECK((fs->fs_close)(fs, file));
    file = NULL;

    if (separate_report)
    {
        // Save the report file
        ECHECK((fs->fs_open)(fs, report_path, flags, 0444, NULL, &file));
        ECHECK(
            (fs->fs_write)(fs, file, report, report_size) ==
            (int64_t)report_size);
        ECHECK((fs->fs_close)(fs, file));
        file = NULL;
    }

    ret = 0;

done:

{
    long params[6] = {(long)cert,
                      (long)cert_size,
                      (long)pkey,
                      (long)pkey_size,
                      (long)report,
                      (long)report_size};
    myst_tcall(MYST_TCALL_FREE_CREDS, params);
}

    if (file)
    {
        fs->fs_close(fs, file);
    }

    return ret;
}

/* Generate TLS credentials if needed */
int myst_init_tls_credential_files(
    const char* want_tls_creds,
    myst_fs_t* fs,
    myst_fstype_t fstype)
{
    int ret = 0;
    if (want_tls_creds == NULL)
        goto done;

#ifndef USE_TMPFS
    /* Avoid leaking TEE-generated certificate files and key files to host */
    if (fstype == MYST_FSTYPE_HOSTFS)
        ERAISE(-EPERM);
#endif

    if (strcmp(want_tls_creds, CERT_AND_PEMKEY) == 0)
    {
        ECHECK(_create_tls_credentials(fs, false));
    }
    else if (strcmp(want_tls_creds, CERT_PEMKEY_REPORT) == 0)
    {
        ECHECK(_create_tls_credentials(fs, true));
    }
    else
    {
        myst_eprintf("Invalid environment variable %s\n", want_tls_creds);
        ERAISE(-EINVAL);
    }

done:
    return ret;
}