// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <myst/maps.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int test_meminfo()
{
    int fd;
    char buf[1024];

    fd = open("/proc/meminfo", O_RDONLY);
    assert(fd > 0);
    assert(read(fd, buf, sizeof(buf)));

    printf("%s\n", buf);
}

int test_self_symlink()
{
    char pid_path[PATH_MAX];
    const size_t n = sizeof(pid_path);
    snprintf(pid_path, n, "/proc/%d", getpid());

    char proc_self_target[PATH_MAX];
    readlink("/proc/self", proc_self_target, sizeof(proc_self_target));

    printf("%s\n", proc_self_target);
    assert(!strcmp(proc_self_target, pid_path));
}

int test_self_exe(const char* pn)
{
    int ret;
    char target[PATH_MAX];
    ret = readlink("/proc/self/exe", target, sizeof(target));
    assert(ret > 0);
    assert(!strcmp(pn, target));
}

int test_self_fd()
{
    const char filename[] = "/file1";
    int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR);
    assert(fd > 0);

    char fd_link_path[PATH_MAX];
    char target[PATH_MAX];
    const size_t n = sizeof(fd_link_path);
    snprintf(fd_link_path, n, "/proc/self/fd/%d", fd);
    readlink(fd_link_path, target, sizeof(target));
    assert(!strcmp(target, filename));
}

int test_status()
{
    int fd;
    char buf[1024];
    printf("****\n");

    fd = open("/proc/self/status", O_RDONLY);
    assert(fd > 0);
    while (read(fd, buf, sizeof(buf)))
        printf("%s", buf);

    close(fd);

    printf("****\n");
}

int test_self_links(const char* pn)
{
    test_self_symlink();
    test_self_exe(pn);
    test_self_fd();
    test_status();
}

int test_readonly()
{
    int fd;
    fd = open("/proc/meminfo", O_RDWR);
    assert(fd == -1);
    assert(errno == EPERM);
}

int static _check_maps(
    myst_maps_t* maps,
    int prot,
    const char* path,
    size_t length)
{
    for (myst_maps_t* p = maps; p; p = p->next)
    {
        if (p->prot == prot && strcmp(p->path, path) == 0)
        {
            if (length == 0)
                return 0;

            if (length == (p->end - p->start))
                return 0;
        }
    }

    /* failed */
    return -1;
}

int test_maps()
{
    char buf[16 * 1024];
    void* addr1;
    void* addr3;
    size_t length1;
    size_t length2;
    size_t length3;

    {
        const int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
        const int flags = MAP_PRIVATE | MAP_ANONYMOUS;
        length1 = 4096 * 1024;
        if ((addr1 = mmap(NULL, length1, prot, flags, -1, 0)) == MAP_FAILED)
            assert(0);
    }

    {
        const int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
        const int flags = MAP_PRIVATE | MAP_ANONYMOUS;
        length3 = 3 * 4096;
        if ((addr3 = mmap(NULL, length3, prot, flags, -1, 0)) == MAP_FAILED)
            assert(0);
    }

    struct stat statbuf;
    assert(stat("/datafile", &statbuf) == 0);
    int fd = open("/datafile", O_RDWR);
    assert(fd >= 0);

    {
        const int prot = PROT_READ | PROT_WRITE;
        const int flags = MAP_PRIVATE | MAP_FIXED;
        length2 = statbuf.st_size / 2;
        if (mmap(addr1, length2, prot, flags, fd, 8192) == MAP_FAILED)
            assert(0);
    }

    myst_maps_t* maps;
    assert(myst_maps_load(&maps) == 0);
    printf("================\n");
    myst_maps_dump(maps);

    int prot_rwx = PROT_READ | PROT_WRITE | PROT_EXEC;
    int prot_rw = PROT_READ | PROT_WRITE;
    int prot_rx = PROT_READ | PROT_EXEC;
    int prot_r = PROT_READ;

    assert(_check_maps(maps, prot_rw, "/bin/procfs", 0) == 0);
    assert(_check_maps(maps, prot_r, "/bin/procfs", 0) == 0);
    assert(_check_maps(maps, prot_rx, "/bin/procfs", 0) == 0);
    assert(_check_maps(maps, prot_rw, "/datafile", 0) == 0);
    assert(_check_maps(maps, PROT_NONE, "/nosuchfile", 0) == -1);
    assert(_check_maps(maps, prot_rw, "/datafile", length2) == 0);

    myst_maps_free(maps);

    /* unmap the second page of the /datafile mapping */
    {
        const int prot = PROT_READ | PROT_WRITE;
        const int flags = MAP_PRIVATE | MAP_ANONYMOUS;

        if (munmap(addr1 + 4096, 4096) != 0)
            assert(0);
    }

    /* verify that the /datafile mapping was split into two mappings */
    {
        printf("================\n");
        myst_maps_t* maps;
        assert(myst_maps_load(&maps) == 0);
        myst_maps_dump(maps);
        assert(_check_maps(maps, prot_rw, "/datafile", 4096) == 0);
        assert(_check_maps(maps, prot_rw, "/datafile", length2 - 8192) == 0);
        myst_maps_free(maps);
    }

    if (munmap(addr1, 4096) != 0)
        assert(0);

    if (munmap(addr1 + 8192, length2 - 8192) != 0)
        assert(0);

    {
        printf("================\n");
        myst_maps_t* maps;
        assert(myst_maps_load(&maps) == 0);
        assert(_check_maps(maps, prot_rw, "/datafile", 4096) == -1);
        assert(_check_maps(maps, prot_rw, "/datafile", length2 - 8192) == -1);
        myst_maps_dump(maps);
        myst_maps_free(maps);
    }
}

int test_cpuinfo()
{
    int fd;
    char buf[1024];

    fd = open("/proc/cpuinfo", O_RDONLY);
    assert(fd > 0);
    while (read(fd, buf, sizeof(buf)))
        printf("%s", buf);

    close(fd);
}

int test_fdatasync()
{
    int fd;
    char buf[1024];

    fd = open("/proc/cpuinfo", O_RDONLY);
    assert(fd > 0);
    int ret = fdatasync(fd);
    assert(ret == -1 && errno == EINVAL);
    close(fd);
}

struct proc_pid_stat
{
    /* data */
    pid_t pid;
    char name[18];
    char state;
    unsigned long long starttime;
};
typedef struct proc_pid_stat proc_pid_stat_t;

#define NANO_IN_SECOND 1000000000
#define TIMESPEC_TO_NANOS(tp) tp.tv_sec* NANO_IN_SECOND + tp.tv_nsec

int parse_proc_stat_file(pid_t pid, proc_pid_stat_t* statptr)
{
    char stat_file_name[1024];
    snprintf(stat_file_name, sizeof(stat_file_name), "/proc/%d/stat", pid);
    FILE* fp = fopen(stat_file_name, "r");
    assert(fp != NULL);
    int sscanfRet = fscanf(
        fp,
        "%d %s %c %*d %*d %*d %*d %*d %*u %*lu %*lu %*lu %*lu %*lu %*lu %*ld "
        "%*ld %*ld %*ld %*ld %*ld %llu \n",
        &statptr->pid,
        statptr->name,
        &statptr->state,
        &statptr->starttime);

    printf(
        "%d %s %c %llu\n",
        statptr->pid,
        statptr->name,
        statptr->state,
        statptr->starttime);
    fclose(fp);
}

int test_stat()
{
    // change thread name
    prctl(PR_SET_NAME, "mystikos");

    // read /proc/self/stat
    proc_pid_stat_t stat;
    parse_proc_stat_file(getpid(), &stat);

    assert(stat.pid == getpid());
    assert(strcmp(stat.name, "(mystikos)") == 0);
    assert(stat.state == 'R');
}

#define SLEEP_DUR 3
int test_stat_from_child()
{
    struct timespec tp;
    assert(clock_gettime(CLOCK_MONOTONIC, &tp) == 0);

    // sleep so that child's start time is further away from kernel boot time
    sleep(SLEEP_DUR);
    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) // child
    {
        // read /proc/[parent-pid]/stat
        proc_pid_stat_t parent_stat;
        parse_proc_stat_file(getppid(), &parent_stat);

        assert(parent_stat.pid == getppid());
        assert(parent_stat.state != 'Z'); // parent should not be a zombie

        // read /proc/self/stat
        proc_pid_stat_t self_stat;
        parse_proc_stat_file(getpid(), &self_stat);

        assert(self_stat.pid = getpid());
        assert(self_stat.starttime >= SLEEP_DUR * sysconf(_SC_CLK_TCK));

        exit(0);
    }
    else // parent
    {
        int status;
        wait(&status);
    }
}

int main(int argc, const char* argv[])
{
    test_meminfo();
    test_self_links(argv[0]);
    test_readonly();
    test_maps();
    test_cpuinfo();
    test_fdatasync();
    test_stat();
    test_stat_from_child();

    printf("\n=== passed test (%s)\n", argv[0]);
    return 0;
}
