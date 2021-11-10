#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
    printf("This program is called by exec\n");

    int fd1 = atoi(argv[1]);
    int fd2 = atoi(argv[2]);
    printf("fd1 %i\n", fd1);
    printf("fd2 %i\n", fd2);

    // fd1 is closed (FD_CLOEXEC set)
    assert(lseek(fd1, 0, SEEK_CUR) == -1);

    // fd2 is not closed
    assert(lseek(fd2, 0, SEEK_CUR) == 0);

    assert(close(fd1) != 0);
    assert(close(fd2) == 0);
    printf("=== passed test test_dup_cloexec\n");
    return 0;
}