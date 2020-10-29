#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, const char* argv[])
{
    struct stat buf;

    /* Test fstat() with file */
    {
        int fd;
        const char path[] = "/tmp/somefile";
        assert((fd = open(path, O_WRONLY | O_CREAT, 0777)) > 0);
        assert(fstat(fd, &buf) == 0);
        assert(S_ISREG(buf.st_mode));
        close(fd);
        assert(unlink(path) == 0);
    }

    /* Test fstat() with directory */
    {
        int fd;
        const char path[] = "/tmp/somedir";
        assert(mkdir(path, 0777) == 0);
        assert((fd = open(path, O_RDONLY)) > 0);
        assert(fstat(fd, &buf) == 0);
        assert(S_ISDIR(buf.st_mode));
        close(fd);
        assert(rmdir(path) == 0);
    }

    /* Test fstat() with pipe */
    {
        int pipefd[2];
        assert(pipe(pipefd) == 0);
        assert(fstat(pipefd[0], &buf) == 0);
        assert(S_ISFIFO(buf.st_mode));
        assert(fstat(pipefd[1], &buf) == 0);
        assert(S_ISFIFO(buf.st_mode));
        close(pipefd[0]);
        close(pipefd[1]);
    }

    /* Test fstat() with socket */
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        assert(sock >= 0);
        memset(&buf, 0, sizeof(buf));
        assert(fstat(sock, &buf) == 0);
        assert(S_ISSOCK(buf.st_mode));
        close(sock);
    }

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
