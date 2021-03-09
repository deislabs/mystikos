// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdbool.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

static bool _got_sigalrm;

void handler(int signo)
{
    if (signo == SIGALRM)
        _got_sigalrm = true;
}

void sleep_msec(uint64_t milliseconds)
{
    struct timespec ts;
    const struct timespec* req = &ts;
    struct timespec rem = {0, 0};
    static const uint64_t _SEC_TO_MSEC = 1000UL;
    static const uint64_t _MSEC_TO_NSEC = 1000000UL;

    ts.tv_sec = (time_t)(milliseconds / _SEC_TO_MSEC);
    ts.tv_nsec = (long)((milliseconds % _SEC_TO_MSEC) * _MSEC_TO_NSEC);

    while (nanosleep(req, &rem) != 0 && errno == EINTR)
    {
        req = &rem;
    }
}

static uint64_t _time(void)
{
    const uint64_t USEC = 1000000;
    struct timespec now;

    clock_gettime(CLOCK_REALTIME, &now);

    return (now.tv_sec * USEC) + (now.tv_nsec / 1000);
}

int main(int argc, const char* argv[])
{
    const uint64_t USEC = 1000000;
    const uint64_t slop = 10000;

    printf("=== start test\n");

    /* save the start time */
    uint64_t start = _time();

    /* solicit the SIGALRM signal */
    assert(signal(SIGALRM, handler) == 0);

    /* set a timer for one second */
    {
        struct itimerval new_value = { { 0, 0 }, { 1, 0 } };
        struct itimerval old_value = { { 1, 2 }, { 3, 4 } };

        if (setitimer(ITIMER_REAL, &new_value, &old_value) != 0)
        {
            fprintf(stderr, "setitimer() failed\n");
            exit(1);
        }

        assert(old_value.it_interval.tv_sec == 0);
        assert(old_value.it_interval.tv_usec == 0);
        assert(old_value.it_value.tv_sec == 0);
        assert(old_value.it_value.tv_usec == 0);
    }

    /* check the timer every 1/4 second */
    {
        uint64_t orig = USEC;
        uint64_t prev = orig;
        uint64_t value = 0;
        uint64_t total = 0;

        for (size_t i = 0; i < 5; i++)
        {
            struct itimerval it;

            if (getitimer(ITIMER_REAL, &it) != 0)
            {
                fprintf(stderr, "getitimer() failed\n");
                exit(1);
            }

            value = it.it_value.tv_sec * USEC + it.it_value.tv_usec;

            switch (i)
            {
                case 0:
                {
                    uint64_t val = 1000000;
                    assert(value >= val - slop && value <= val + slop);
                    break;
                }
                case 1:
                {
                    uint64_t val = 750000;
                    assert(value >= val - slop && value <= val + slop);
                    break;
                }
                case 2:
                {
                    uint64_t val = 500000;
                    assert(value >= val - slop && value <= val + slop);
                    break;
                }
                case 3:
                {
                    uint64_t val = 250000;
                    assert(value >= val - slop && value <= val + slop);
                    break;
                }
                case 4:
                {
                    uint64_t val = 0;
                    assert(value <= val + slop);
                    break;
                }
            }

            assert(value <= prev);
            total += prev - value;
            prev = value;

            /* sleep for 1/4 second */
            sleep_msec(1000 / 4);
        }
    }

    /* calculate elapsed time */
    uint64_t end = _time();
    uint64_t elapsed = end - start;

    /* the run time should be approximately 1.5 seconds */
    assert(elapsed >= 1250000 - slop && elapsed <= 1250000 + slop);

    /* confirm that SIGALRM was received */
    assert(_got_sigalrm);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
