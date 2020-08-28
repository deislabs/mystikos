#include <pthread.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

void* start_routine(void* arg)
{
    printf("\n");

    for (size_t i = 0; i < 5; i++)
    {
        printf("sleep...\n");
        fflush(stdout);
        sleep(1);
    }

    return arg;
}

int main(int argc, const char* argv[])
{
    pthread_t pt;
    int r;

    r = pthread_create(&pt, NULL, start_routine, (void*)0xabcd);

    printf("pthread_create(): return: %d\n", r);

    sleep(7);

    return 0;
}
