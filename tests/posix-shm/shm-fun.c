#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#define SHM_SIZE 10
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#define MYST_POSIX_SHM_DEV_NUM 26
#define ROUNDUP(x, n) ((x + n - 1) & ~(n - 1))

static void printUsage()
{
    printf("Usage: TEST [SHM-NAME]\n");
}

static bool is_running_on_myst()
{
    struct utsname buf;
    uname(&buf);
    return !strncmp(buf.version, "Mystikos", 8);
}
int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printUsage();
        exit(1);
    }

    bool myst_run = is_running_on_myst();
    char* shm_name = "/shm-fun-1";
    if (argc == 3)
    {
        shm_name = argv[2];
    }

    if (strcmp(argv[1], "basic") == 0)
    {
        int fd =
            shm_open(shm_name, O_CREAT | O_EXCL | O_RDWR, (S_IRUSR | S_IWUSR));
        assert(fd >= 0);

        assert(ftruncate(fd, SHM_SIZE) != -1);

        char* addr =
            mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        assert(addr != MAP_FAILED);

        printf("addr=%p\n", addr);
        printf("mem before copy: %s\n", addr);
        strcpy(addr, "hellowrld");
        printf("mem after copy: %s\n", addr);
        assert(!strcmp(addr, "hellowrld"));

        {
            struct stat statbuf;
            assert(!fstat(fd, &statbuf));
            printf("statbuf dev %ld\n", statbuf.st_dev);
            printf("statbuf rdev %ld\n", statbuf.st_rdev);
            printf("statbuf size %ld\n", statbuf.st_size);
            // Device number is different on WSL - 9 and Linux - 26
            if (myst_run)
                assert(statbuf.st_dev == MYST_POSIX_SHM_DEV_NUM);
            assert(statbuf.st_size == SHM_SIZE);
        }

        assert(shm_unlink(shm_name) != -1);
    }
    else if (strcmp(argv[1], "empty-file") == 0)
    {
        int fd =
            shm_open(shm_name, O_CREAT | O_EXCL | O_RDWR, (S_IRUSR | S_IWUSR));
        assert(fd >= 0);

        char* addr =
            mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        printf("addr=%p errno=%d\n", addr, errno);
        assert(addr == MAP_FAILED && errno == ENOEXEC);
    }
    else if (strcmp(argv[1], "write") == 0)
    {
        int fd = shm_open(shm_name, O_RDWR, 0);
        assert(fd >= 0);

        char* addr =
            mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        assert(addr != MAP_FAILED);

        printf("addr=%p contents before write=%s\n", addr, addr);
        strcpy(addr, "wrldhello");
        printf("addr=%p contents after write=%s\n", addr, addr);

        munmap(addr, SHM_SIZE);
        shm_unlink(shm_name);
    }
    else if (strcmp(argv[1], "share") == 0)
    {
        char* addr;
        {
            int fd = shm_open(shm_name, O_CREAT | O_RDWR, (S_IRUSR | S_IWUSR));
            assert(fd >= 0);

            assert(ftruncate(fd, SHM_SIZE) != -1);

            addr = mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            assert(addr != MAP_FAILED);

            close(fd);

            printf("addr=%p contents before fork=%s\n", addr, addr);
            assert(!strcmp(addr, "")); // assert zero-filled-memory
        }

        pid_t pid = fork();
        assert(pid != -1);

        if (pid == 0) // child execve's self and writes to shared memory
        {
            char buf[PATH_MAX];
            readlink("/proc/self/exe", buf, PATH_MAX);
            char* argVec[] = {buf, "write", 0};
            char* envVec[] = {0};
            execve(buf, argVec, envVec);
        }
        else // parent waits on child and then verifies write
        {
            waitpid(pid, NULL, 0);
            printf("addr=%p contents after fork=%s\n", addr, addr);
            assert(!strcmp(addr, "wrldhello"));
            exit(0);
        }
    }
    else if (strcmp(argv[1], "resize-file") == 0)
    {
        int fd = shm_open(shm_name, O_CREAT | O_RDWR, (S_IRUSR | S_IWUSR));
        assert(fd >= 0);

        assert(ftruncate(fd, SHM_SIZE) != -1);

        char* addr =
            mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

        {
            // truncate file to size zero
            int ret = ftruncate(fd, 0);
            printf("ftruncate ret=%d errno=%d\n", ret, errno);
            // Access to shm object if backing file is size zero causes SIGBUS
            // on Linux.
            if (myst_run)
                printf("mem after ftruncate: %s\n", addr);

            // Write bytes more than 1 page - 6000 bytes
            for (int i = 0; i < 200; i++)
                write(fd, "hellowrldhellowrldhellowrldddd", 30);

            // Check backing file size and contents of shared memory
            struct stat statbuf;
            assert(!fstat(fd, &statbuf));
            printf(
                "len of string after write =%ld file size=%ld\n",
                strlen(addr),
                statbuf.st_size);

            // Mystikos doesn't allow growing buffers beyond size(rounded up
            // to be a page size multiple) specified in the first ftruncate.
            if (myst_run)
            {
                assert(statbuf.st_size < ROUNDUP(SHM_SIZE, PAGE_SIZE));
            }

            // grow with ftruncate
            {
                ret = ftruncate(fd, 2 * PAGE_SIZE);
                printf("ftruncate ret=%d errno=%d\n", ret, errno);
                struct stat statbuf;
                assert(!fstat(fd, &statbuf));
                printf("file size=%ld\n", statbuf.st_size);
                if (myst_run)
                {
                    assert(statbuf.st_size < ROUNDUP(SHM_SIZE, PAGE_SIZE));
                }
            }

            // shrink with ftruncate
            {
                ret = ftruncate(fd, PAGE_SIZE / 2);
                printf("ftruncate ret=%d errno=%d\n", ret, errno);
                struct stat statbuf;
                assert(!fstat(fd, &statbuf));
                printf("file size=%ld\n", statbuf.st_size);
                if (myst_run)
                {
                    assert(statbuf.st_size == PAGE_SIZE / 2);
                }
            }
        }

        assert(shm_unlink(shm_name) != -1);
    }
    else if (strcmp(argv[1], "resize-memory") == 0)
    {
        int fd = shm_open(shm_name, O_CREAT | O_RDWR, (S_IRUSR | S_IWUSR));
        assert(fd >= 0);

        assert(ftruncate(fd, SHM_SIZE) != -1);

        char* addr =
            mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

        {
            char* new_addr =
                mremap(addr, SHM_SIZE, 2 * PAGE_SIZE, MREMAP_MAYMOVE);
            printf(
                "addr=%p new_addr=%p errno=%s\n",
                addr,
                new_addr,
                strerror(errno));
            {
                struct stat statbuf;
                assert(!fstat(fd, &statbuf));
                printf("statbuf size %ld\n", statbuf.st_size);
            }
        }

        assert(shm_unlink(shm_name) != -1);
    }
    else
    {
        printf("Unsupported test arg: %s\n", argv[1]);
    }
}
