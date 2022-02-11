#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SHM_SIZE 10
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static void printUsage()
{
    printf("Usage: OPERATION [SHM-NAME]\n");
    printf("OPERATION: create|read|write|unlink \n");
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printUsage();
        exit(1);
    }

    char* shm_name = "/shm-fun-1";
    if (argc == 3)
    {
        shm_name = argv[2];
    }

    if (strcmp(argv[1], "create") == 0)
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
    else if (strcmp(argv[1], "unlink") == 0)
    {
        assert(shm_unlink(shm_name) != -1);
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

            printf("addr=%p contents before fork=%s\n", addr, addr);
        }

        pid_t pid = fork();
        assert(pid != -1);

        if (pid)
        {
            waitpid(pid, NULL, 0);
            printf("addr=%p contents after fork=%s\n", addr, addr);
            exit(0);
        }
        else if (pid == 0)
        {
            char buf[PATH_MAX];
            readlink("/proc/self/exe", buf, PATH_MAX);
            printf("%s %ld\n", buf, strlen(buf));
            char* argVec[] = {buf, "write", 0};
            char* envVec[] = {0};
            execve(buf, argVec, envVec);
        }

        /*
        This test implies, syncing of memory region
        */
    }
    else if (strcmp(argv[1], "share2") == 0)
    {
        char* addr;
        {
            int fd = shm_open(shm_name, O_RDWR, 0);
            assert(fd >= 0);

            addr = mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            assert(addr != MAP_FAILED);

            printf("addr=%p contents before fork=%s\n", addr, addr);
            strcpy(addr, "wrldhello");
            printf(
                "addr=%p contents before fork + after write =%s\n", addr, addr);
        }

        pid_t pid = fork();
        assert(pid != -1);

        if (pid)
        {
            waitpid(pid, NULL, 0);
            printf("addr=%p contents after fork=%s\n", addr, addr);
            exit(0);
        }
        else if (pid == 0)
        {
            char* argVec[] = {"shm-fun", "read", "a", 0};
            char* envVec[] = {0};
            execve("./shm-fun", argVec, envVec);
        }

        /*
        This test implies, syncing of memory region happens even without munmap
        */
    }
    else if (strcmp(argv[1], "fstat") == 0)
    {
        int fd = shm_open(shm_name, O_CREAT | O_RDWR, (S_IRUSR | S_IWUSR));
        assert(fd >= 0);
        assert(ftruncate(fd, SHM_SIZE) != -1);

        struct stat statbuf;
        assert(!fstat(fd, &statbuf));
        printf("statbuf dev %ld\n", statbuf.st_dev);
        printf("statbuf rdev %ld\n", statbuf.st_rdev);
        printf("statbuf size %ld\n", statbuf.st_size);
        // Different on WSL - 9 and Linux - 26
        // assert(statbuf.st_dev == 9);
        assert(statbuf.st_size == SHM_SIZE);
    }
    else
    {
        printf("Unsupported operation arg: %s\n", argv[1]);
    }
}
