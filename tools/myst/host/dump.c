// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <inttypes.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <unistd.h>

#include <myst/elf.h>
#include <myst/file.h>
#include <openenclave/bits/properties.h>
#include <openenclave/bits/sgx/sgxproperties.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/host.h>

#include "dump.h"
#include "utils.h"

// Helper functions from within OE to get OE related info
oe_result_t oe_read_oeinfo_sgx(
    const char* path,
    oe_sgx_enclave_properties_t* properties);

static void _hex_dump(const unsigned char* data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        printf("%02x", data[i]);

    printf("\n");
}

static int _sha256(const void* data, size_t size, unsigned char* mrsigner)
{
    SHA256_CTX ctx = {0};
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, size);
    SHA256_Final(mrsigner, &ctx);

    return 0;
}

static void _dump_mrsigner(
    const uint8_t* public_key_modulus,
    size_t public_key_modulus_size)
{
    unsigned char mrsigner[SHA256_DIGEST_LENGTH] = {0};

    /* Check if modulus value is not set */
    size_t i = 0;
    while (i < public_key_modulus_size && public_key_modulus[i] == 0)
        i++;

    if (public_key_modulus_size > i)
    {
        _sha256(public_key_modulus, public_key_modulus_size, mrsigner);
    }

    _hex_dump(mrsigner, sizeof(mrsigner));
}

static int dump_enclave_properties(oe_sgx_enclave_properties_t* properties)
{
    const sgx_sigstruct_t* sigstruct;

    printf("product_id=%u\n", properties->config.product_id);

    printf("security_version=%u\n", properties->config.security_version);

    bool debug = properties->config.attributes & OE_SGX_FLAGS_DEBUG;
    printf("debug=%u\n", debug);

    printf("xfrm=%#016" PRIx64 "\n", properties->config.xfrm);

    printf(
        "num_stack_pages=%" PRIu64 "\n",
        properties->header.size_settings.num_stack_pages);

    printf(
        "num_heap_pages=%" PRIu64 "\n",
        properties->header.size_settings.num_heap_pages);

    printf("num_tcs=%" PRIu64 "\n", properties->header.size_settings.num_tcs);

    sigstruct = (const sgx_sigstruct_t*)properties->sigstruct;

    printf("mrenclave=");
    _hex_dump(sigstruct->enclavehash, sizeof(sigstruct->enclavehash));

    printf("mrsigner=");
    _dump_mrsigner(sigstruct->modulus, sizeof(sigstruct->modulus));

    printf("signature=");
    _hex_dump(sigstruct->signature, sizeof(sigstruct->signature));

    return 0;
}

#define USAGE_DUMP \
    "\
\n\
Usage: %s dump-sgx <sgx_package> [options]\n\
\n\
Where:\n\
    dump-sgx      -- dump the SGX enclave configuration along with the\n\
                     packaging configuration from an SGX packaged executable\n\
    <sgx-package> -- path to the packaged SGX application\n\
\n\
and <options> are one of:\n\
    --help        -- this message\n\
\n\
"

int dump_action(int argc, const char* argv[], const char* envp[])
{
    int ret = -1;
    elf_t elf = {0};
    int elf_loaded = false;
    unsigned char* buffer = NULL;
    size_t buffer_length = 0;
    int enc_fd = -1;
    oe_sgx_enclave_properties_t properties = {0};
    oe_result_t oe_result;
    char* enc_filename = NULL;

    // check parameters
    if ((argc < 3) || (cli_getopt(&argc, argv, "--help", NULL) == 0) ||
        (cli_getopt(&argc, argv, "-h", NULL) == 0))
    {
        fprintf(stderr, USAGE_DUMP, argv[0]);
        goto done;
    }

    // load argv[0] elf image
    if (elf_load(argv[2], &elf) != 0)
    {
        fprintf(stderr, "Failed to load elf image %s\n", argv[2]);
        goto done;
    }

    elf_loaded = 1;

    // Find enclave image
    if (elf_find_section(&elf, ".mystenc", &buffer, &buffer_length) != 0)
    {
        fprintf(
            stderr,
            "Failed to find enclave image in %s\nThis is probably not an Open "
            "Mystikos package "
            "file\n",
            argv[0]);
        goto done;
    }

    // save it in temporary file
    char enc_filename_buf[] = "/tmp/mystencXXXXXX";

    enc_fd = mkstemp(enc_filename_buf);
    if (enc_fd < 0)
    {
        fprintf(stderr, "Failed to create temporary enclave file under /tmp\n");
        goto done;
    }

    enc_filename = enc_filename_buf;

    if (myst_write_file_fd(enc_fd, buffer, buffer_length) != 0)
    {
        fprintf(stderr, "Failed to write enclave to %s\n", enc_filename);
        goto done;
    }

    close(enc_fd);
    enc_fd = -1;

    // get the SGX properties from the enclave
    oe_result = oe_read_oeinfo_sgx(enc_filename, &properties);
    if (oe_result != OE_OK)
    {
        fprintf(
            stderr,
            "Failed to get SGX properties from enclave file %s\n",
            enc_filename);
        goto done;
    }

    if (dump_enclave_properties(&properties) != 0)
    {
        fprintf(stderr, "Failed to dump enclave properties\n");
        goto done;
    }

    elf_unload(&elf);
    elf_loaded = 0;

    // Now load the configuration that is in the enclave
    if (elf_load(enc_filename, &elf) != 0)
    {
        fprintf(stderr, "Failed to load elf image %s\n", argv[2]);
        goto done;
    }

    elf_loaded = 1;

    // Find config image
    if (elf_find_section(&elf, ".mystconfig", &buffer, &buffer_length) != 0)
    {
        fprintf(stderr, "Failed to find configuration in enclave image\n");
        goto done;
    }

    printf("Package configuration:\n%*s", (int)buffer_length, buffer);

    ret = 0;

done:
    if (enc_fd >= 0)
        close(enc_fd);

    if (elf_loaded)
        elf_unload(&elf);

    if (enc_filename)
        unlink(enc_filename);

    return ret;
}
