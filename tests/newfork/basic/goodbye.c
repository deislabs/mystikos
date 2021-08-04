#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void* start(void* arg)
{
    printf("goodbye thread\n");
    sleep(1);
    return arg;
}

int main(int argc, const char* argv[])
{
    for (size_t i = 0; i < 3; i++)
    {
        printf("%s: %zu\n", argv[0], i);
        sleep(1);
    }

    pthread_t th;
    assert(pthread_create(&th, NULL, start, NULL) == 0);
    assert(pthread_join(th, NULL) == 0);

    /* enumerate the /bin diretory entries */
    {
        DIR* dir;
        struct dirent* ent;
        assert((dir = opendir("/bin")));
        size_t count = 0;

        while ((ent = readdir(dir)))
        {
            // printf("{%s}\n", ent->d_name);
            count++;
        }

        closedir(dir);
        assert(count == 5);
    }

    /* create a file containing the alphabet */
    {
        int fd;
        int flags = O_CREAT | O_TRUNC | O_WRONLY;
        assert((fd = open("/tmp/alpha", flags, 0666)) > 0);
        assert(write(fd, "abcdefghijklmnopqrstuvwxyz", 27) == 27);
        close(fd);
    }

    printf("%s: return\n", argv[0]);
    return 123;
}
