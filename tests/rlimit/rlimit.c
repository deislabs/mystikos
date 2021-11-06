// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>

void assert_rlimit(
    int resource,
    const char* name,
    int64_t expected_cur,
    int64_t expected_max)
{
    struct rlimit rlim;
    assert(!getrlimit(resource, &rlim));
    long int cur = rlim.rlim_cur;
    long int max = rlim.rlim_max;
    printf("%i %s: rlim_cur: %li, :rlim_max: %li \n", resource, name, cur, max);
    assert(rlim.rlim_cur == expected_cur);
    assert(rlim.rlim_max == expected_max);
}

void assert_rlimit_gt(
    int resource,
    const char* name,
    int64_t lower_cur,
    int64_t lower_max)
{
    struct rlimit rlim;
    assert(!getrlimit(resource, &rlim));
    long int cur = rlim.rlim_cur;
    long int max = rlim.rlim_max;
    printf("%i %s: rlim_cur: %li, :rlim_max: %li \n", resource, name, cur, max);
    assert(rlim.rlim_cur > lower_cur);
    assert(rlim.rlim_max > lower_max);
}

void assert_error(int resource, const char* name)
{
    struct rlimit rlim;
    assert(getrlimit(resource, &rlim) == -1);
    printf("%s: not supported \n", name);
}

int main(int argc, char* argv[])
{
    assert_rlimit(RLIMIT_CPU, "RLIMIT_CPU", RLIM_INFINITY, RLIM_INFINITY);
    assert_rlimit(RLIMIT_FSIZE, "RLIMIT_FSIZE", RLIM_INFINITY, RLIM_INFINITY);
    struct sysinfo info;
    sysinfo(&info);
    int64_t limit_data = floor(info.totalram * 0.70);
    assert_rlimit(RLIMIT_DATA, "RLIMIT_DATA", limit_data, limit_data);
    assert_rlimit_gt(RLIMIT_STACK, "RLIMIT_STACK", 1000000, 1000000);
    assert_rlimit(RLIMIT_CORE, "RLIMIT_CORE", 0, RLIM_INFINITY);
    assert_rlimit(RLIMIT_RSS, "RLIMIT_RSS", RLIM_INFINITY, RLIM_INFINITY);
    assert_rlimit(RLIMIT_NPROC, "RLIMIT_NPROC", 1024, 1024);
    assert_rlimit(RLIMIT_NOFILE, "RLIMIT_NOFILE", 1024, 1024);
    assert_rlimit(RLIMIT_MEMLOCK, "RLIMIT_MEMLOCK", 67108864, 67108864);
    assert_rlimit(RLIMIT_AS, "RLIMIT_AS", RLIM_INFINITY, RLIM_INFINITY);
    assert_rlimit(RLIMIT_LOCKS, "RLIMIT_LOCKS", RLIM_INFINITY, RLIM_INFINITY);
    assert_rlimit(RLIMIT_SIGPENDING, "RLIMIT_SIGPENDING", 128319, 128319);
    assert_rlimit(RLIMIT_MSGQUEUE, "RLIMIT_MSGQUEUE", 819200, 819200);
    assert_rlimit(RLIMIT_NICE, "RLIMIT_NICE", 0, 0);
    assert_rlimit(RLIMIT_RTPRIO, "RLIMIT_RTPRIO", 0, 0);
    assert_rlimit(RLIMIT_RTTIME, "RLIMIT_RTTIME", RLIM_INFINITY, RLIM_INFINITY);
}
