#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define FILE_SIZE 20

typedef enum
{
    NONE,
    WSL, // Windows subsystem for Linux
    LINUX,
    MYSTIKOS
} os_t;

static os_t get_os_type()
{
    struct utsname buf;
    uname(&buf);
    if (!strncmp(buf.version, "Mystikos", 8))
        return MYSTIKOS;
    if (strstr(buf.version, "Microsoft") != NULL)
        return WSL;
    else if (!strncmp(buf.sysname, "Linux", 5))
        return LINUX;
    return NONE;
}

static void printUsage()
{
    printf("Usage: TEST [TEST NAME]\n");
}

/*
Test the most basic functions
1. memfd_create should success with flag
    (but don't check if flag works in this test)
2. read and write from fd
4. mmap
*/
int test_basic()
{
    char name[] = "file created by memfd_create";
    int fd = memfd_create(name, MFD_CLOEXEC);
    if (fd < 0)
    {
        fprintf(stderr, "test_basic memfd_create failed: %d\n", errno);
        return 1;
    }

    // read and write using fd
    char content[] = "Hello, World!";
    char buf[FILE_SIZE] = {0};

    int count = read(fd, buf, FILE_SIZE);
    assert(count == 0);

    count = write(fd, content, strlen(content));
    assert(count == strlen(content));

    lseek(fd, 0, SEEK_SET);
    count = read(fd, buf, FILE_SIZE);
    assert(count != -1);
    assert(0 == strcmp(content, buf));

    // test mmap
    ftruncate(fd, FILE_SIZE); // native linux doesn't need this step
    char* addr =
        mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    printf("addr=%p errno=%d\n", addr, errno);

    assert(0 == strcmp(content, addr));
    strcpy(addr, "abc");
    assert(0 == strcmp(addr, "abc"));

    munmap(addr, FILE_SIZE);
    return close(fd);
}

int test_empty_file()
{
    os_t os = get_os_type();
    char name[] = "any text";
    int fd = memfd_create(name, 0);
    assert(fd >= 0);

    char* addr =
        mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    printf("addr=%p errno=%d\n", addr, errno);

    // Linux allows mmap an empty file, but will deliver a SIGBUS if the
    // memory was accessed.
    if (os == MYSTIKOS || os == WSL)
        assert(addr == MAP_FAILED && errno == ENOEXEC);
    return 0;
}

/*
Create child process and write into mmap-ed addr
Parent check content
*/
int test_share()
{
    char content[] = "Hello, World!";
    int fd = memfd_create("memfd_file1", 0);
    assert(fd >= 0);
    assert(ftruncate(fd, FILE_SIZE) != -1);

    char* addr =
        mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    assert(addr != MAP_FAILED);

    printf("addr=%p contents before fork=%s\n", addr, addr);
    assert(!strcmp(addr, "")); // assert zero-filled-memory

    pid_t pid = fork();
    assert(pid != -1);

    if (pid == 0)
    {
        // child
        strcpy(addr, content);
        assert(munmap(addr, FILE_SIZE) == 0);
    }
    else
    {
        // parent
        waitpid(pid, NULL, 0);
        printf("addr=%p contents after fork=%s\n", addr, addr);
        assert(!strcmp(addr, content));
    }
}

int test_duplicate()
{
    char content[] = "Hello, World!";
    char name[] = "memfd_create_file1";
    int fd1 = memfd_create(name, 0);
    assert(fd1 >= 0);

    int fd2 = memfd_create(name, 0);
    assert(fd2 >= 0);

    // check they are not the same file
    assert(fd1 != fd2);
    ftruncate(fd1, FILE_SIZE);
    ftruncate(fd2, FILE_SIZE);
    char* addr1 =
        mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 0);
    assert(addr1 != MAP_FAILED);

    char* addr2 =
        mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd2, 0);
    assert(addr2 != MAP_FAILED);

    assert(addr1 != addr2);

    // validate they are not the same file
    strcpy(addr1, content);
    assert(0 == strcmp(addr1, content));
    assert(0 != strcmp(addr1, addr2));

    munmap(addr1, FILE_SIZE);
    munmap(addr2, FILE_SIZE);

    close(fd1);
    close(fd2);
}

int test_cloexec_no_flag()
{
    int fd = memfd_create("memfd_file1", 0);
    assert(fd >= 0);
    assert(ftruncate(fd, FILE_SIZE) != -1);

    char* addr =
        mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    assert(addr != MAP_FAILED);

    printf("addr=%p contents before fork=%s\n", addr, addr);
    assert(!strcmp(addr, "")); // assert zero-filled-memory

    pid_t pid = fork();
    assert(pid != -1);

    if (pid == 0)
    {
        // child
        assert(munmap(addr, FILE_SIZE) == 0);

        // execve and write to fd
        char buf[PATH_MAX];
        readlink("/proc/self/exe", buf, PATH_MAX);
        char s_fd[] = "00";
        sprintf(s_fd, "%d", fd);
        char* argVec[] = {buf, "child-write", s_fd, "0", 0};
        char* envVec[] = {0};
        execve(buf, argVec, envVec);
    }
    else
    {
        // parent
        waitpid(pid, NULL, 0);
        printf("addr=%p contents after fork=%s\n", addr, addr);
        assert(!strcmp(addr, "Hello, World!"));
        close(fd);
    }
}

int test_child_write(int fd, int shouldFail)
{
    // try to write to fd
    char content[] = "Hello, World!";
    int count = write(fd, content, strlen(content));
    if (!shouldFail)
    {
        assert(count == strlen(content));
        close(fd);
    }
    else
    {
        assert(count == -1);
        assert(errno == EBADF);
    }
}

int test_cloexec_with_flag()
{
    int fd = memfd_create("memfd_file1", MFD_CLOEXEC);
    assert(fd >= 0);
    assert(ftruncate(fd, FILE_SIZE) != -1);

    char* addr =
        mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    assert(addr != MAP_FAILED);

    printf("addr=%p contents before fork=%s\n", addr, addr);
    assert(!strcmp(addr, "")); // assert zero-filled-memory

    pid_t pid = fork();
    assert(pid != -1);

    if (pid == 0)
    {
        // child
        assert(munmap(addr, FILE_SIZE) == 0);

        // execve and write to fd
        char buf[PATH_MAX];
        readlink("/proc/self/exe", buf, PATH_MAX);
        char s_fd[] = "00";
        sprintf(s_fd, "%d", fd);
        char* argVec[] = {buf, "child-write", s_fd, "1", 0};
        char* envVec[] = {0};
        execve(buf, argVec, envVec);
    }
    else
    {
        // parent
        waitpid(pid, NULL, 0);
        printf("addr=%p contents after fork=%s\n", addr, addr);
        assert(!strcmp(addr, ""));
        close(fd);
    }
}

int test_cloexec()
{
    int ret = test_cloexec_no_flag();
    assert(ret == 0);
    ret = test_cloexec_with_flag();
    return ret;
}

/*
Not supported by Mystikos, yet
*/
int test_proc()
{
    int fd1 = memfd_create("doesn't matter", 0);
    assert(fd1 >= 0);

    // Open /proc/self/fd/[fd]
    char buf[] = "/proc/self/fd/xxx";
    sprintf(buf, "/proc/self/fd/%d", fd1);
    int fd2 = open(buf, O_RDWR);
    assert(fd2 != fd1 && fd2 >= 0);

    // Validate that they are the same file
    ftruncate(fd1, FILE_SIZE);
    ftruncate(fd2, FILE_SIZE);
    char* addr1 =
        mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 0);
    char* addr2 =
        mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd2, 0);
    assert(addr1 != MAP_FAILED && addr2 != MAP_FAILED);

    // Shouldn't pointer point to the same memory?
    assert(addr1 != addr2);

    printf("addr1=%p\naddr2=%p\n", addr1, addr2);

    // write to addr1 and read from addr2
    char content[] = "Hello, World!";
    strcpy(addr1, content);
    assert(0 == strcmp(addr1, content));
    assert(0 == strcmp(addr1, addr2));

    munmap(addr1, FILE_SIZE);
    munmap(addr2, FILE_SIZE);

    close(fd1);
    close(fd2);
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printUsage();
        exit(1);
    }

    int ret = 0;

    if (strcmp(argv[1], "basic") == 0)
    {
        ret = test_basic();
    }
    else if (strcmp(argv[1], "empty-file") == 0)
    {
        ret = test_empty_file();
    }
    else if (strcmp(argv[1], "share") == 0)
    {
        // test if mmap-ed pointer shared between parent and child works
        ret = test_share();
    }
    else if (strcmp(argv[1], "duplicate") == 0)
    {
        // test creating two fd given the same name
        ret = test_duplicate();
    }
    else if (strcmp(argv[1], "cloexec") == 0)
    {
        // test if fd is close after exec if flag is set
        ret = test_cloexec();
    }
    else if (strcmp(argv[1], "child-write") == 0)
    {
        assert(argc >= 4);
        // only used by child process created in cloexec
        int fd = atoi(argv[2]);
        int shouldFail = atoi(argv[3]);
        ret = test_child_write(fd, shouldFail);
    }
    else if (strcmp(argv[1], "proc") == 0)
    {
        // test open /proc/self/fd/[fd]
        ret = test_proc();
    }
    else
    {
        printf("Unsupported test arg: %s\n", argv[1]);
        ret = 1;
    }

    if (ret == 0)
        printf("%s passed\n", argv[1]);
    else
        printf("%s failed\n", argv[1]);

    return ret;
}