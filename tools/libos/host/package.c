// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <libos/types.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libos/elf.h>
#include <libos/getopt.h>
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
     1}};
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
    free(image);

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
    int ret = -1;
    const char* app_dir = NULL;
    const char* pem_file = NULL;
    const char* config_file = NULL;
    const char* target = NULL;  // Extracted from config
    const char* appname = NULL; // Extracted from target
    char* tmp_dir = NULL;
    char dir_template[] = "/tmp/libosXXXXXX";
    char rootfs_file[PATH_MAX];
    char scratch_path[PATH_MAX];
    char scratch_path2[PATH_MAX];
    config_parsed_data_t parsed_data = {0};

    if ((argc < 5) || (parse_options(argc, argv, 5, &options) != 0) ||
        help_present)
    {
        fprintf(stderr, USAGE_PACKAGE, argv[0]);
        goto done;
    }

    // We are in the right operation, right?
    assert(strcmp(argv[1], "package") == 0);

    app_dir = argv[2];
    pem_file = argv[3];
    config_file = argv[4];

    tmp_dir = mkdtemp(dir_template);
    if (tmp_dir == NULL)
    {
        fprintf(stderr, "Failed to create temporary directory in /tmp\n");
        goto done;
    }

    if (snprintf(rootfs_file, PATH_MAX, "%s/rootfs.pkg", tmp_dir) >= PATH_MAX)
    {
        fprintf(stderr, "File path too long? %s/rootfs.pkg\n", tmp_dir);
        goto done;
    }

    const char* mkcpio_args[] = {argv[0], // ..../libos
                                 "mkcpio",
                                 app_dir,
                                 rootfs_file};

    if (_mkcpio(sizeof(mkcpio_args) / sizeof(mkcpio_args[0]), mkcpio_args) != 0)
    {
        fprintf(
            stderr,
            "Failed to create root filesystem \"%s\" from directory \"%s\"\n",
            rootfs_file,
            app_dir);
        goto done;
    }

    if (parse_config_from_file(config_file, &parsed_data) != 0)
    {
        fprintf(
            stderr,
            "Failed to generate OE configuration file %s from LibOS "
            "configuration file %s\n",
            scratch_path2,
            config_file);
        goto done;
    }

    target = parsed_data.application_path;
    if ((target == NULL) || (target[0] != '/'))
    {
        fprintf(
            stderr,
            "target in config file must be fully qualified path within rootfs");
        goto done;
    }

    appname = strrchr(target, '/');
    if (appname == NULL)
    {
        fprintf(stderr, "Failed to get appname from target path");
        goto done;
    }
    appname++;
    if (*appname == '\0')
    {
        fprintf(stderr, "Failed to get appname from target path");
        goto done;
    }

    // sign the enclave and measure all regions of enclave
    const char* sign_args[] = {argv[0],
                               "sign",
                               rootfs_file,
                               pem_file,
                               config_file,
                               "--ourdir",
                               tmp_dir};

    // Sign and copy everything into app.signed directory
    if (_sign(sizeof(sign_args) / sizeof(sign_args[0]), sign_args) != 0)
    {
        fprintf(stderr, "Failed to sign enclave file");
        goto done;
    }

    // Now package everything up in a single binary
    elf_t elf;

    memset(&elf, 0, sizeof(elf));

    // First load the libos application so we can add the other components
    // as named sections in the image
    if (snprintf(scratch_path, PATH_MAX, "%s/bin/libos", tmp_dir) >= PATH_MAX)
    {
        fprintf(stderr, "File path to long: %s/bin/libos", tmp_dir);
        goto done;
    }
    if (elf_load(scratch_path, &elf) != 0)
    {
        fprintf(stderr, "Failed to load %s/bin/libos", tmp_dir);
        goto done;
    }

    // Add the enclave to libos
    if (snprintf(
            scratch_path,
            PATH_MAX,
            "%s/lib/openenclave/libosenc.so",
            tmp_dir) >= PATH_MAX)
    {
        fprintf(
            stderr,
            "File path to long: %s/openenclave/lib/libosenc.so",
            tmp_dir);
        goto done;
    }
    if (_add_image_to_elf_section(&elf, scratch_path, ".libosenc") != 0)
    {
        fprintf(
            stderr,
            "Failed to add %s to enclave section .libosenc",
            scratch_path);
        goto done;
    }

    // Add the enclave CRT to libos
    if (snprintf(scratch_path, PATH_MAX, "%s/lib/liboscrt.so", tmp_dir) >=
        PATH_MAX)
    {
        fprintf(stderr, "File path to long: %s/lib/liboscrt.so", tmp_dir);
        goto done;
    }
    if (_add_image_to_elf_section(&elf, scratch_path, ".liboscrt") != 0)
    {
        fprintf(
            stderr,
            "Failed to add image %s to enclave section .lioscrt",
            scratch_path);
        goto done;
    }

    // Add the kernel to libos
    if (snprintf(scratch_path, PATH_MAX, "%s/lib/liboskernel.so", tmp_dir) >=
        PATH_MAX)
    {
        fprintf(stderr, "File path to long: %s/lib/liboskernel.so", tmp_dir);
        goto done;
    }
    if (_add_image_to_elf_section(&elf, scratch_path, ".liboskernel") != 0)
    {
        fprintf(
            stderr,
            "Failed to add image %s to enclave section .liboskernel",
            scratch_path);
        goto done;
    }

    // Add the rootfs to libos
    if (_add_image_to_elf_section(&elf, rootfs_file, ".libosrootfs") != 0)
    {
        fprintf(
            stderr,
            "Failed to add image %s to enclave section .libosrootfs",
            rootfs_file);
        goto done;
    }

    // Add the config to libos
    if (_add_image_to_elf_section(&elf, config_file, ".libosconfig") != 0)
    {
        fprintf(
            stderr,
            "Failed to add image %s to enclave section .libosconfig",
            config_file);
        goto done;
    }

    // Save new elf image back
    if (snprintf(scratch_path, PATH_MAX, "%s/bin/%s", tmp_dir, appname) >=
        PATH_MAX)
    {
        fprintf(stderr, "File path to long: %s/bin/%s", tmp_dir, appname);
        goto done;
    }
    int fd = open(scratch_path, O_WRONLY | O_CREAT | O_TRUNC, 0774);
    if (fd == 0)
    {
        fprintf(
            stderr,
            "Failed to epn file to write final binary image back to %s",
            scratch_path);
        goto done;
    }
    if (libos_write_file_fd(fd, elf.data, elf.size) != 0)
    {
        close(fd);
        fprintf(
            stderr,
            "File to save final binary image back to: %s",
            scratch_path);
        goto done;
    }
    close(fd);

    elf_unload(&elf);

    //
    // Move the final file to the proper destination
    //
    // Create destination directory libos/bin
    if ((mkdir("libos", 0775) != 0) && (errno != EEXIST))
    {
        fprintf(stderr, "Failed to make destination directory libos\n");
        goto done;
    }
    if ((mkdir("libos/bin", 0775) != 0) && (errno != EEXIST))
    {
        fprintf(stderr, "Failed to make destination directory libos/bin\n");
        goto done;
    }

    // Destination filename
    if (snprintf(scratch_path, PATH_MAX, "libos/bin/%s", appname) >= PATH_MAX)
    {
        fprintf(stderr, "File path to long: libos/bin/%s", appname);
        goto done;
    }

    // Source filename
    if (snprintf(scratch_path2, PATH_MAX, "%s/bin/%s", tmp_dir, appname) >=
        PATH_MAX)
    {
        fprintf(stderr, "File path to long: %s/bin/%s", tmp_dir, appname);
        goto done;
    }

    if (libos_copy_file(scratch_path2, scratch_path) != 0)
    {
        fprintf(
            stderr,
            "Failed to copy final package from %s to %s",
            scratch_path2,
            scratch_path);
        goto done;
    }

    ret = 0;

done:

    if (tmp_dir)
        remove_recursive(tmp_dir);

    return ret;
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
    char full_app_path[PATH_MAX];
    char* app_dir = NULL;
    char* app_name = NULL;
    char scratch_path[PATH_MAX];
    const region_details* details = NULL;
    unsigned char* buffer = NULL;
    size_t buffer_length = 0;
    elf_image_t libos_elf = {0};
    int elf_loaded = 0;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    struct libos_options options = {0};
    char* config_buffer = NULL;
    size_t config_size = 0;
    char unpack_dir_template[] = "/tmp/libosXXXXXX";
    char* unpack_dir = NULL;
    int ret = -1;
    const char** exec_args = NULL;

    /* Get options */
    {
        /* Get --trace-syscalls option */
        if (_getopt(&argc, argv, "--trace-syscalls", NULL) == 0 ||
            _getopt(&argc, argv, "--strace", NULL) == 0)
        {
            options.trace_syscalls = true;
        }
    }

    if (snprintf(full_app_path, PATH_MAX, "%s", argv[0]) >= PATH_MAX)
    {
        fprintf(stderr, "File path %s is too long\n", argv[0]);
        goto done;
    }
    app_dir = dirname(full_app_path);
    app_name = basename(full_app_path);

    // Create a directory to unpack the package into, and to run from,
    // as well as the directory structure we need
    if ((unpack_dir = mkdtemp(unpack_dir_template)) == NULL)
    {
        fprintf(stderr, "Failed to create unpack directory\n");
        goto done;
    }
    if (snprintf(scratch_path, PATH_MAX, "%s/lib", unpack_dir) >= PATH_MAX)
    {
        fprintf(stderr, "File path %s/lib is too long\n", unpack_dir);
        goto done;
    }
    if ((mkdir(scratch_path, DIR_MODE) != 0) && (errno != EEXIST))
    {
        fprintf(stderr, "Failed to create directory \"%s\".\n", scratch_path);
        goto done;
    }
    if (snprintf(scratch_path, PATH_MAX, "%s/bin", unpack_dir) >= PATH_MAX)
    {
        fprintf(stderr, "File path %s/bin is too long\n", unpack_dir);
        goto done;
    }
    if ((mkdir(scratch_path, DIR_MODE) != 0) && (errno != EEXIST))
    {
        fprintf(stderr, "Failed to create directory \"%s\".\n", scratch_path);
        goto done;
    }
    if (snprintf(scratch_path, PATH_MAX, "%s/lib/openenclave", unpack_dir) >=
        PATH_MAX)
    {
        fprintf(
            stderr, "File path %s/lib/openenclave is too long\n", unpack_dir);
        goto done;
    }
    if ((mkdir(scratch_path, DIR_MODE) != 0) && (errno != EEXIST))
    {
        fprintf(stderr, "Failed to create directory \"%s\".\n", scratch_path);
        goto done;
    }

    // Load main executable so we can extract sections
    if (elf_image_load(get_program_file(), &libos_elf) != 0)
    {
        fprintf(stderr, "failed to load libos image: %s\n", get_program_file());
        goto done;
    }
    elf_loaded = 1;

    // copy executable to unpack directory where we will run it from
    if (snprintf(scratch_path, PATH_MAX, "%s/bin/%s", unpack_dir, app_name) >=
        PATH_MAX)
    {
        fprintf(
            stderr, "File path %s/bin/%s is too long\n", unpack_dir, app_name);
        goto done;
    }
    if (libos_copy_file(get_program_file(), scratch_path) < 0)
    {
        fprintf(
            stderr,
            "Failed to copy %s to %s\n",
            get_program_file(),
            scratch_path);
        goto done;
    }

    // Make enclave directory and extract enclave into it
    if (snprintf(
            scratch_path,
            PATH_MAX,
            "%s/lib/openenclave/libosenc.so",
            unpack_dir) >= PATH_MAX)
    {
        fprintf(
            stderr, "File path %s/lib/openenclave/ is too long\n", unpack_dir);
        goto done;
    }
    if (elf_find_section(
            &libos_elf.elf, ".libosenc", &buffer, &buffer_length) != 0)
    {
        fprintf(
            stderr, "Failed to extract enclave from %s\n", get_program_file());
        goto done;
    }

    if (libos_write_file(scratch_path, buffer, buffer_length) != 0)
    {
        fprintf(stderr, "Failed to write %s\n", scratch_path);
        goto done;
    }

    if (elf_find_section(
            &libos_elf.elf,
            ".libosconfig",
            (unsigned char**)&config_buffer,
            &config_size) != 0)
    {
        fprintf(
            stderr, "Failed to extract config from %s\n", get_program_file());
        goto done;
    }
    elf_loaded = 1;

    // Need to duplicate the config buffer or we will be corrupting the image
    // data
    config_parsed_data_t parsed_data = {0};

    if (parse_config_from_buffer(
            (char*)config_buffer, config_size, &parsed_data) != 0)
    {
        fprintf(stderr, "Failed to process configuration\n");
    }
    if ((parsed_data.allow_host_parameters == 0) && (argc > 1))
    {
        printf(
            "Command line arguments will be ignored due to configuration.\n");
    }
    if (parsed_data.application_path == NULL)
    {
        fprintf(
            stderr,
            "No target filename in configuration. This should be the fully "
            "qualified path to the executable within the "
            "%s directory, but should be relative to this directory\n",
            app_dir);
        goto done;
    }

    if ((details = create_region_details_from_package(
             &libos_elf, parsed_data.user_pages)) == NULL)
    {
        fprintf(stderr, "Failed to extract all sections\n");
        goto done;
    }

    parsed_data.oe_num_heap_pages =
        (details->rootfs.buffer_size + (5 * 1024 * 1024)) / LIBOS_PAGE_SIZE;

    // build argv with application name. If we are allowed command line args
    // then append them also
    int num_args = 1; // argv[0];

    if (parsed_data.allow_host_parameters)
    {
        num_args = argc;
    }

    exec_args = malloc((num_args + 1) * sizeof(char*));
    if (exec_args == NULL)
    {
        fprintf(stderr, "out of memory\n");
        goto done;
    }
    exec_args[0] = parsed_data.application_path;
    int args_iter = 1;
    while (args_iter != num_args)
    {
        exec_args[args_iter] = argv[args_iter];
        args_iter++;
    }
    exec_args[args_iter] = NULL;

    if (snprintf(
            scratch_path,
            PATH_MAX,
            "%s/lib/openenclave/libosenc.so",
            unpack_dir) >= PATH_MAX)
    {
        fprintf(
            stderr, "File path %s/lib/openenclave/ is too long\n", unpack_dir);
        goto done;
    }

    if (exec_launch_enclave(
            scratch_path, type, flags, exec_args, envp, &options) != 0)
    {
        fprintf(stderr, "Failed to run enclave %s\n", scratch_path);
        goto done;
    }

    ret = 0;

done:
    if (unpack_dir)
        unlink(unpack_dir);

    if (elf_loaded)
        elf_image_free(&libos_elf);

    if (details)
        free_region_details();

    if (exec_args)
        free(exec_args);

    return ret;
}
