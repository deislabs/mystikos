#include <pthread.h>
#include <stdio.h>

void* start_routine(void* arg)
{
    printf("start_routine()\n");
    fflush(stdout);
    return arg;
}

int main(int argc, const char* argv[])
{
    pthread_t pt;
    int r;

    r = pthread_create(&pt, NULL, start_routine, (void*)0xabcd);

    printf("r=%d\n", r);

    return 0;
}
