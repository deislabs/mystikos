#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void* start(void* arg)
{
    printf("hello thread\n");
    sleep(1);
    return arg;
}

int main(int argc, const char* argv[])
{
    printf("%s\n", argv[0]);

    for (size_t i = 0; i < 3; i++)
    {
        printf("%s: %zu\n", argv[0], i);
        sleep(1);
    }

    pthread_t th;
    assert(pthread_create(&th, NULL, start, NULL) == 0);
    assert(pthread_join(th, NULL) == 0);

    char* args[] = {"/bin/goodbye", NULL};
    char* env[] = {NULL};
    execve("/bin/goodbye", args, env);
    abort();

    return 123;
}
