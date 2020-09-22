// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libos/elf.h>
#include <libos/getopt.h>
#include <libos/malloc.h>
#include <openenclave/bits/sgx/region.h>
#include <openenclave/host.h>

#include "../config.h"
#include "cpio.h"
#include "exec.h"
#include "libos/file.h"
#include "libos_args.h"
#include "parse_options.h"
#include "regions.h"
#include "sign.h"
#include "utils.h"

#define USAGE_PACKAGE \
    "\
\n\
Usage: %s sign package <app_dir> <pem_file> <config> [options]\n\
\n\
Where:\n\
    <app_dir> -- directory with files for root filesystem\n\
    <pem_file> -- private key to sign enclave\n\
    <config>   -- configuration for signing and application runtime\n\
\n\
and <options> are one of:\n\
    --help        -- this message\n\
    --platform OE -- execute an application within the libos\n\
                     Default = OE\n\
\n\
"

static const char* help_present = NULL;
static const char* platform = "OE";

static const char* help_options[] = {"--help", "-h"};
static const char* platform_options[] = {"--platform", "-p"};

static struct _option option_list[] = {
    // {names array}, names_count, num_extra_param, extra_param,
    // extra_param_required
    {help_options,
     sizeof(help_options) / sizeof(const char*),
     0,
     &help_present,
     0},
    {platform_options,
     sizeof(platform_options) / sizeof(const char*),
     1,
     &platform,
     1},
};
static struct _options options = {option_list,
                                  sizeof(option_list) / sizeof(struct _option)};

static int _add_image_to_elf_section(
    elf_t* elf,
    const char* path,
    const char* section_name)
{
    void* image = NULL;
    size_t image_length = 0;
    int ret = -1;

    if (libos_load_file(path, &image, &image_length) != 0)
    {
        fprintf(stderr, "Failed to load %s", path);
        goto done;
    }
    if (elf_add_section(elf, section_name, SHT_PROGBITS, image, image_length) !=
        0)
    {
        fprintf(stderr, "Failed to add %s to elf image", path);
        goto done;
    }
    libos_free(image);

    ret = 0;

done:
    return ret;
}

#define DIR_MODE                                                          \
    S_IROTH | S_IXOTH | S_IXGRP | S_IWGRP | S_IRGRP | S_IXUSR | S_IWUSR | \
        S_IRUSR

// libos package <app_dir> <pem_file> <config> [options]
int _package(int argc, const char* argv[])
{
    char scratch_path[PATH_MAX];
    char scratch_path2[PATH_MAX];
    config_parsed_data_t callback_data = {0};

    if ((argc < 5) || (parse_options(argc, argv, 5, &options) != 0) ||
        help_present)
    {
        fprintf(stderr, USAGE_PACKAGE, argv[0]);
        return -1;
    }

    // We are in the right operation, right?
    assert(strcmp(argv[1], "package") == 0);

    const char* app_dir = argv[2];
    const char* pem_file = argv[3];
    const char* config_file = argv[4];
    const char* target;  // Extracted from config
    const char* appname; // Extracted from target

    if (parse_config_from_file(config_file, &callback_data) != 0)
    {
        _err(
            "Failed to generate OE configuration file %s from LibOS "
            "configuration file %s",
            scratch_path2,
            config_file);
    }

    target = callback_data.application_path;
    if ((target == NULL) || (target[0] != '/'))
    {
        _err(
            "target in config file must be fully qualified path within rootfs");
    }

    appname = strrchr(target, '/');
    if (appname == NULL)
    {
        _err("Failed to get appname from target path");
    }
    appname++;
    if (*appname == '\0')
    {
        _err("Failed to get appname from target path");
    }

    // Make sure we have the signing directory
    if (snprintf(scratch_path, PATH_MAX, "%s.signed", appname) >= PATH_MAX)
    {
        _err("File path to long: %.signed", appname);
    }

    if ((mkdir(scratch_path, DIR_MODE) != 0) && (errno != EEXIST))
    {
        _err("Failed to create directory \"%s\".", scratch_path);
    }

    // Make a temporary copy of the rootfs
    if (snprintf(scratch_path, PATH_MAX, "%s.signed/rootfs.temp", appname) >=
        PATH_MAX)
    {
        _err("File path to long: %s.signed", appname);
    }
    const char* mkcpio_args[] = {
        argv[0], // ..../libos
        "mkcpio",
        app_dir,     // <app_dir>
        scratch_path // ./<appname>.signed/rootfs.temp
    };
    if (_mkcpio(sizeof(mkcpio_args) / sizeof(mkcpio_args[0]), mkcpio_args) != 0)
    {
        _err(
            "Failed to create root filesystem \"%s\" in directory \"%s\"",
            scratch_path,
            app_dir);
    }

    // sign the enclave and measure all regions of enclave
    const char* sign_args[] = {
        argv[0],
        "sign",
        scratch_path, // rootfs
        pem_file,
        config_file,
    };

    // Sign and copy everything into app.signed directory
    if (_sign(sizeof(sign_args) / sizeof(sign_args[0]), sign_args) != 0)
    {
        _err("Failed to sign enclave file");
    }

    // remove the temporary copy of rootfs
    unlink(scratch_path);

    // Now package everything up in a single binary
    elf_t elf;

    memset(&elf, 0, sizeof(elf));

    // First load the libos application so we can add the other components
    // as named sections in the image
    if (snprintf(scratch_path, PATH_MAX, "%s.signed/bin/libos", appname) >=
        PATH_MAX)
    {
        _err("File path to long: %s.signed.signed/bin/libos", appname);
    }
    if (elf_load(scratch_path, &elf) != 0)
    {
        _err("Failed to load %s.signed/bin/libos", appname);
    }

    // Add the enclave to libos
    if (snprintf(
            scratch_path,
            PATH_MAX,
            "%s.signed/lib/openenclave/libosenc.so",
            appname) >= PATH_MAX)
    {
        _err(
            "File path to long: %s.signed/openenclave/lib/libosenc.so",
            appname);
    }
    if (_add_image_to_elf_section(&elf, scratch_path, ".libosenc") != 0)
    {
        _err(
            "Failed to add image %s to to binary %s.signed/bin/libos",
            scratch_path,
            appname);
    }
    if (libos_unlink(scratch_path) != 0)
    {
        _err("Failed to delete temporary file %s", scratch_path);
    }

    // Add the enclave CRT to libos
    if (snprintf(
            scratch_path, PATH_MAX, "%s.signed/lib/liboscrt.so", appname) >=
        PATH_MAX)
    {
        _err("File path to long: %s.signed/lib/liboscrt.so", appname);
    }
    if (_add_image_to_elf_section(&elf, scratch_path, ".liboscrt") != 0)
    {
        _err(
            "Failed to add image %s to to binary %s.signed/bin/libos",
            scratch_path,
            appname);
    }
    if (libos_unlink(scratch_path) != 0)
    {
        _err("Failed to delete temporary file %s", scratch_path);
    }

    // Add the kernel to libos
    if (snprintf(
            scratch_path, PATH_MAX, "%s.signed/lib/liboskernel.so", appname) >=
        PATH_MAX)
    {
        _err("File path to long: %s.signed/lib/liboskernel.so", appname);
    }
    if (_add_image_to_elf_section(&elf, scratch_path, ".liboskernel") != 0)
    {
        _err(
            "Failed to add image %s to to binary %s.signed/lib/libos",
            scratch_path,
            appname);
    }
    if (libos_unlink(scratch_path) != 0)
    {
        _err("Failed to delete temporary file %s", scratch_path);
    }

    // Add the rootfs to libos
    if (snprintf(scratch_path, PATH_MAX, "%s.signed/rootfs", appname) >=
        PATH_MAX)
    {
        _err("File path to long: %s.signed/rootfs", appname);
    }
    if (_add_image_to_elf_section(&elf, scratch_path, ".libosrootfs") != 0)
    {
        _err(
            "Failed to add image %s to to binary %s.signed/bin/libos",
            scratch_path,
            appname);
    }
    if (libos_unlink(scratch_path) != 0)
    {
        _err("Failed to delete temporary file %s", scratch_path);
    }

    // Add the config to libos
    if (_add_image_to_elf_section(&elf, config_file, ".libosconfig") != 0)
    {
        _err(
            "Failed to add image %s to to binary %s.signed/bin/libos",
            config_file,
            appname);
    }

    // Save new elf image back
    if (snprintf(
            scratch_path, PATH_MAX, "%s.signed/bin/%s", appname, appname) >=
        PATH_MAX)
    {
        _err("File path to long: %s.signed/bin/%s", appname, appname);
    }
    int fd = libos_open(scratch_path, O_WRONLY | O_CREAT | O_TRUNC, 0774);
    if (fd == 0)
    {
        _err("Failed to create %s for writing", scratch_path);
    }
    if (libos_write_file_fd(fd, elf.data, elf.size) != 0)
    {
        _err("File to save final signed image: %s", scratch_path);
    }
    libos_close(fd);

    elf_unload(&elf);

    // clean up original libos executable
    if (snprintf(scratch_path, PATH_MAX, "%s.signed/bin/libos", appname) >=
        PATH_MAX)
    {
        _err("File path to long: %s.signed/bin/libos", appname);
    }
    if (libos_unlink(scratch_path) != 0)
    {
        _err("Failed to delete temporary file %s", scratch_path);
    }

    return 0;
}

static int _getopt(
    int* argc,
    const char* argv[],
    const char* opt,
    const char** optarg)
{
    char err[128];
    int ret;

    ret = libos_getopt(argc, argv, opt, optarg, err, sizeof(err));

    if (ret < 0)
        _err("%s", err);

    return ret;
}

// <app_name> [app args]
int _exec_package(
    int argc,
    const char* argv[],
    const char* envp[],
    const char* executable)
{
    char app_dir[PATH_MAX];
    char scratch_path[PATH_MAX];
    char* scratch_string = NULL;
    const region_details* details;
    unsigned char* buffer = NULL;
    size_t buffer_length = 0;
    elf_image_t libos_elf = {0};
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    struct libos_options options = {0};
    char* config_buffer = NULL;
    size_t config_size = 0;

    /* Get options */
    {
        /* Get --trace-syscalls option */
        if (_getopt(&argc, argv, "--trace-syscalls", NULL) == 0 ||
            _getopt(&argc, argv, "--strace", NULL) == 0)
        {
            options.trace_syscalls = true;
        }
    }

    if (snprintf(app_dir, PATH_MAX, "%s", argv[0]) >= PATH_MAX)
    {
        _err("File path %s is too long", argv[0]);
    }
    scratch_string = strrchr(app_dir, '/');
    if ((scratch_string != NULL) && (*scratch_string == '/'))
    {
        *scratch_string = '\0';
    }

    // Load main executable so we can extract sections
    if (elf_image_load(get_program_file(), &libos_elf) != 0)
        _err("failed to load libos image: %s", get_program_file());

    // Make enclave directory and extract enclave into it
    if (snprintf(scratch_path, PATH_MAX, "%s/../lib", app_dir) >= PATH_MAX)
    {
        _err("File path %s/enc is too long", app_dir);
    }
    if ((mkdir(scratch_path, DIR_MODE) != 0) && (errno != EEXIST))
    {
        _err("Failed to create directory \"%s\".", scratch_path);
    }
    if (snprintf(
            scratch_path,
            PATH_MAX,
            "%s/../lib/openenclave/libosenc.so",
            app_dir) >= PATH_MAX)
    {
        _err("File path %s/lib/openenclave/ is too long", app_dir);
    }
    if (elf_find_section(
            &libos_elf.elf, ".libosenc", &buffer, &buffer_length) != 0)
    {
        _err("Failed to extract enclave from %s", get_program_file());
    }

    if (libos_write_file(scratch_path, buffer, buffer_length) != 0)
    {
        _err("Failed to write %s", scratch_path);
    }

    if (elf_find_section(
            &libos_elf.elf,
            ".libosconfig",
            (unsigned char**)&config_buffer,
            &config_size) != 0)
    {
        _err("Failed to extract config from %s", get_program_file());
    }

    // Need to duplicate the config buffer or we will be corrupting the image
    // data
    config_parsed_data_t callback_data = {0};

    if (parse_config_from_buffer(
            (char*)config_buffer, config_size, &callback_data) != 0)
    {
        _err("Failed to process configuration");
    }
    if ((callback_data.allow_host_parameters == 0) && (argc > 1))
    {
        printf(
            "Command line arguments will be ignored due to configuration.\n");
    }
    if (callback_data.application_path == NULL)
    {
        _err(
            "No target filename in configuration. This should be the fully "
            "qualified path to the executable within the "
            "%s directory, but should be relative to this directory",
            app_dir);
    }

    if ((details = create_region_details_from_package(
             &libos_elf, callback_data.user_pages)) == NULL)
    {
        _err("Failed to extract all sections");
    }

    // build argv with application name. If we are allowed command line args
    // then append them also
    int num_args = 1; // argv[0];

    if (callback_data.allow_host_parameters)
    {
        num_args = argc;
    }

    const char** exec_args = malloc((num_args + 1) * sizeof(char*));
    if (exec_args == NULL)
    {
        _err("out of memory");
    }
    exec_args[0] = callback_data.application_path;
    int args_iter = 1;
    while (args_iter != num_args)
    {
        exec_args[args_iter] = argv[args_iter];
        args_iter++;
    }
    exec_args[args_iter] = NULL;

    if (exec_launch_enclave(
            scratch_path, type, flags, exec_args, envp, &options) != 0)
    {
        _err("Failed to run enclave %s", scratch_path);
    }

    free(exec_args);

    free_region_details();

    elf_image_free(&libos_elf);

    return 0;
}
