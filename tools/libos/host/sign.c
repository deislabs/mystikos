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

// needed for oe_region_add_regions()
extern elf_image_t _crt_image;
extern char _crt_path[PATH_MAX];
extern void* _rootfs_data;
extern size_t _rootfs_size;


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

int _sign(int argc, const char* argv[])
{
    char dir[PATH_MAX];
    int ret = 0;
    const char *help_present = NULL;
    const char *platform = NULL;
    const char *target = NULL;
    const char *rootfs = NULL;
    const char *pem_file = NULL;
    const char *config_file = NULL;
    static const char *help_options[] = {"--help", "-h"};
    static const char *platform_options[] = {"--platform", "-p"};
    static const char *target_options[] = {"--target", "-t"};
    static const char *rootfs_options[] = {"--rootfs", "-r"};
    static const char *pem_options[] = {"--pem_file", "-k"};
    static const char *config_options[] = {"--config_file", "-c"};
    struct _option option_list[] = 
    {
        // {names array}, names_count, num_extra_param, extra_param, extra_param_required
        {help_options, sizeof(help_options)/sizeof(const char *), 0, &help_present, 0},
        {platform_options, sizeof(platform_options)/sizeof(const char *), 1, &platform, 1},
        {target_options, sizeof(target_options)/sizeof(const char *), 1, &target, 1},
        {rootfs_options, sizeof(rootfs_options)/sizeof(const char *), 1, &rootfs, 1},
        {pem_options, sizeof(pem_options)/sizeof(const char *), 1, &pem_file, 1},
        {config_options, sizeof(config_options)/sizeof(const char *), 1, &config_file, 1}
    };
    struct _options options =
    {
        option_list,
        sizeof(option_list)/sizeof(struct _option)
    };

    /* Get the directory that contains argv[0] */
    strcpy(dir, get_program_file());
    dirname(dir);

    // We are in the right operation, right?
    assert(strcmp(argv[1], "sign") == 0);

    // Parse the extra options and validate they exist when required
    if ((ret = parse_options(argc, argv, 2, &options)) != 0)
        return ret;
    
    // Initiate signing with extracted parameters

    return 0;
}
