#include <unistd.h>
#include <limits.h>
#include <stdio.h>

int main(int argc, const char* argv[])
{
    char buf[PATH_MAX];

    getcwd(buf, sizeof(buf));

    printf("cwd={%s}\n", buf);

    return 0;
}
