// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include "cpio.h"
#include "sign.h"
#include "utils.h"

// libos package <app_dir> <app_name> 
int _package(int argc, const char* argv[])
{
    char sign_dir[PATH_MAX];
    size_t sign_dir_len;
//    const char *app_dir = argv[2];
//    const char *app_name = argv[3];

    // We are in the right operation, right?
    assert(strcmp(argv[1], "package") == 0);

    strcpy(sign_dir, argv[3]);
    strcpy(sign_dir, ".signed");
    sign_dir_len = strlen(sign_dir);

    if ((mkdir(sign_dir, S_IROTH|S_IXOTH|S_IXGRP|S_IWGRP|S_IRGRP|S_IXUSR|S_IWUSR|S_IRUSR) != 0) && (errno != EEXIST))
    {
        _err("Failed to create directory \"%s\".", sign_dir);
    }

    strcpy(sign_dir+sign_dir_len, "/");
    sign_dir_len++;

    strcpy(sign_dir + sign_dir_len, ".signed");

    const char *mkcpio_args[] = 
    {
        argv[0],
        argv[2],
        sign_dir
    };
    _mkcpio(sizeof(mkcpio_args)/sizeof(mkcpio_args[0]), mkcpio_args);

    return -1;
}