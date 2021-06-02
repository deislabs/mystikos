#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <myst/cpio.h>
#include <myst/file.h>
#include <myst/getopt.h>
#include <myst/paths.h>
#include <myst/strings.h>

#include "archive.h"
#include "utils.h"

static int _getopt(
    int* argc,
    const char* argv[],
    const char* opt,
    const char** optarg)
{
    char err[128];
    int ret;

    ret = myst_getopt(argc, argv, opt, optarg, err, sizeof(err));

    if (ret < 0)
        puterr("%s", err);

    return ret;
}

void get_archive_options(
    int* argc,
    const char* argv[],
    const char* pubkeys[],
    size_t max_pubkeys,
    size_t* num_pubkeys_out,
    const char* roothashes[],
    size_t max_roothashes,
    size_t* num_roothashes_out)
{
    const char* pubkey;
    const char* roothash;
    size_t num_pubkeys = 0;
    size_t num_roothashes = 0;

    while (_getopt(argc, argv, "--pubkey", &pubkey) == 0)
    {
        struct stat statbuf;

        if (num_pubkeys == max_pubkeys)
            puterr("too many --pubkey options (> %zu)", max_pubkeys);

        if (stat(pubkey, &statbuf) != 0)
            puterr("no such file for --pubkey options: %s", pubkey);

        pubkeys[num_pubkeys++] = pubkey;
    }

    while (_getopt(argc, argv, "--roothash", &roothash) == 0)
    {
        struct stat statbuf;

        if (num_roothashes == max_roothashes)
            puterr("too many --roothash options (> %zu)", max_roothashes);

        if (stat(roothash, &statbuf) != 0)
            puterr("no such file for --roothash options: %s", roothash);

        roothashes[num_roothashes++] = roothash;
    }

    *num_pubkeys_out = num_pubkeys;
    *num_roothashes_out = num_roothashes;
}

/* create the CPIO archive */
void create_archive(
    const char* pubkeys[],
    size_t num_pubkeys,
    const char* roothashes[],
    size_t num_roothashes,
    char archive_path[PATH_MAX])
{
    char dir_template[] = "/tmp/mystXXXXXX";
    char* dirname = NULL;
    char filename[] = "/tmp/mystXXXXXX";
    int fd;

    if (!(dirname = mkdtemp(dir_template)))
        puterr("cannot create temporary directory");

    if ((fd = mkstemp(filename)) < 0)
        puterr("cannot create temporary file");

    /* create the pubkeys directory */
    {
        char path[PATH_MAX];
        const int n = sizeof(path);

        if (snprintf(path, n, "%s/pubkeys", dirname) >= n)
            puterr("path too long");

        if (mkdir(path, 0700) != 0)
            puterr("failed to create directory: %s", path);

        /* create <dirname>/pubkeys/<pubkey> files */
        for (size_t i = 0; i < num_pubkeys; i++)
        {
            const char* pubkey = pubkeys[i];
            const char* basename = myst_basename(pubkey);

            if (snprintf(path, n, "%s/pubkeys/%s", dirname, basename) >= n)
                puterr("path too long");

            if (myst_copy_file(pubkey, path) != 0)
                puterr("failed to copy %s to %s", pubkey, path);
        }
    }

    /* create the roothashes directory */
    {
        char path[PATH_MAX];
        const int n = sizeof(path);

        if (snprintf(path, n, "%s/roothashes", dirname) >= n)
            puterr("path too long");

        if (mkdir(path, 0700) != 0)
            puterr("failed to create directory: %s", path);

        /* create <dirname>/roothashes/<roothash> files */
        for (size_t i = 0; i < num_roothashes; i++)
        {
            const char* roothash = roothashes[i];
            const char* basename = myst_basename(roothash);

            if (snprintf(path, n, "%s/roothashes/%s", dirname, basename) >= n)
            {
                puterr("path too long");
            }

            if (myst_copy_file(roothash, path) != 0)
                puterr("failed to copy %s to %s", roothash, path);
        }
    }

    /* pack the directory into a CPIO archive */
    if (myst_cpio_pack(dirname, filename) != 0)
        puterr("failed to CPIO archive from %s", dirname);

    if (remove_recursive(dirname) != 0)
        puterr("failed to remove directory: %s", dirname);

    myst_strlcpy(archive_path, filename, PATH_MAX);
}
