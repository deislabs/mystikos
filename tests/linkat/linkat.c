// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <fcntl.h> /* Definition of AT_* constants */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#define REG_FILE "regfile"
#define SYMLINK_TO_REG "symlinktoreg"
#define HARDLINK_TO_SYMLINK "hardlinktosymlink"
#define HARDLINK_TO_REG "hardlinktooldfile"

int main(int argc, const char* argv[])
{
    struct stat sb;

    assert(
        open(
            REG_FILE,
            O_CREAT,
            S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) != -1);

    assert(symlink(REG_FILE, SYMLINK_TO_REG) == 0);
    assert(
        linkat(
            AT_FDCWD,
            SYMLINK_TO_REG,
            AT_FDCWD,
            HARDLINK_TO_REG,
            AT_SYMLINK_FOLLOW) == 0);

    assert(lstat(HARDLINK_TO_REG, &sb) == 0);
    assert(!S_ISLNK(sb.st_mode));

    assert(
        linkat(AT_FDCWD, SYMLINK_TO_REG, AT_FDCWD, HARDLINK_TO_SYMLINK, 0) ==
        0);
    assert(lstat(HARDLINK_TO_SYMLINK, &sb) == 0);
    assert(S_ISLNK(sb.st_mode));

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
