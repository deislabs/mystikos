// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <libos/elf.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <limits.h>
#include <libgen.h>
#include "parse_options.h"
#include "utils.h"
#include "libos_u.h"
#include "regions.h"

// Pulled in from liboesign.a
// Actual OE signer code from oesign tool.
int oesign(
    const char* enclave,
    const char* conffile,
    const char* keyfile,
    const char* digest_signature,
    const char* x509,
    const char* engine_id,
    const char* engine_load_path,
    const char* key_id);

#define USAGE_SIGN "\
\n\
Usage: %s sign <thing-to-sign> [options] ...\n\
\n\
Where <thing-to-sign> is the binary or shared library to be signed \n\
and <options> are one of:\n\
    --help                -- ths message\n\
    --platform OE         -- execute an application within the libos\n\
    --target <filename>   -- target to be signed, OE Enclave when platform is OE\n\
    --rootfs <filename>   -- path to CPIO archive file\n\
    --pem_file <filename> -- filename of private RSA key in PEM format\n\
    --config_file <filename>   -- filename of signing configuration\n\
\n\
"

static const char *sign_help_present = NULL;
static const char *sign_platform = NULL;
static const char *sign_target = NULL;
static const char *sign_rootfs = NULL;
static const char *sign_pem_file = NULL;
static const char *sign_config_file = NULL;

static const char *help_options[] = {"--help", "-h"};
static const char *platform_options[] = {"--platform", "-p"};
static const char *target_options[] = {"--target", "-t"};
static const char *rootfs_options[] = {"--rootfs", "-r"};
static const char *pem_options[] = {"--pem_file", "-k"};
static const char *config_options[] = {"--config_file", "-c"};

struct _option option_list[] = 
{
    // {names array}, names_count, num_extra_param, extra_param, extra_param_required
    {help_options, sizeof(help_options)/sizeof(const char *), 0, &sign_help_present, 0},
    {platform_options, sizeof(platform_options)/sizeof(const char *), 1, &sign_platform, 1},
    {target_options, sizeof(target_options)/sizeof(const char *), 1, &sign_target, 1},
    {rootfs_options, sizeof(rootfs_options)/sizeof(const char *), 1, &sign_rootfs, 1},
    {pem_options, sizeof(pem_options)/sizeof(const char *), 1, &sign_pem_file, 1},
    {config_options, sizeof(config_options)/sizeof(const char *), 1, &sign_config_file, 1}
};
struct _options options =
{
    option_list,
    sizeof(option_list)/sizeof(struct _option)
};

int _sign(int argc, const char* argv[])
{
    int ret = 0;
    const region_details *details;

    // We are in the right operation, right?
    assert(strcmp(argv[1], "sign") == 0);

    // Parse the extra options and validate they exist when required
    if ((ret = parse_options(argc, argv, 2, &options)) != 0)
    {
        _err("Failed to parse options.");
    }

    if ((details = create_region_details(sign_target, sign_rootfs)) == NULL)
    {
        _err("Creating region data failed.");
    }

    // Initiate signing with extracted parameters
    if (oesign(details->enc_path, NULL /*limited_config*/, sign_pem_file, NULL, NULL, NULL, NULL, NULL) != 0)
    {
        _err("Failed to sign binary");
    }

    return 0;
}
