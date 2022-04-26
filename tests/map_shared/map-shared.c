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

#define FILE_SIZE 10
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

bool myst_run;
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

    myst_run = is_running_on_myst();
    char* data_file_name = "/tmp/shm-fun-1";
    if (argc == 3)
    {
        data_file_name = argv[2];
    }

    if (strcmp(argv[1], "basic") == 0)
    {
        int fd = open(data_file_name, O_CREAT | O_RDWR, (S_IRUSR | S_IWUSR));
        assert(fd >= 0);

        assert(ftruncate(fd, FILE_SIZE) != -1);

        char* addr =
            mmap(0, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        assert(addr != MAP_FAILED);

        printf("addr=%p\n", addr);
        printf("mem before copy: %s\n", addr);
        strcpy(addr, "hellowrld");
        printf("mem after copy: %s\n", addr);
        assert(!strcmp(addr, "hellowrld"));

        /* Check we don't write beyond mapped range [offset, offset+length] into
         * the file */
        {
            /* Even though we requested 10 bytes of memory in mmap(), we are
             * attempting to write 30. This does not fail either on Linux or
             * Mystikos because the kernel allocates a whole page for the
             * allocation. However, mmap() behavior dicates that modification
             * beyond the end of the file should not be carried back to the file
             */
            strcpy(addr, "astringlongerthan10characters");
            // sync whole page
            assert(msync(addr, PAGE_SIZE, MS_ASYNC) == 0);
            char buf[20];
            int nbytes = read(fd, buf, 20);
            printf("nbytes in file=%d\n", nbytes);
            // assert file did not grow beyond the limits specificied in mmap()
            // call.
            assert(nbytes == 10);
            if (nbytes)
                printf("data: %s\n", buf);
        }

        assert(unlink(data_file_name) != -1);
    }
    else if (strcmp(argv[1], "empty-file") == 0)
    {
        int fd = open(data_file_name, O_CREAT | O_RDWR, (S_IRUSR | S_IWUSR));
        assert(fd >= 0);

        char* addr =
            mmap(0, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        printf("addr=%p errno=%d\n", addr, errno);

        /* Linux allows mapping a zero-sized file or generally beyond the end of
           file. However accessing the memory generates a SIGBUS. Mystikos can't
           serve SIGBUS. We can only guarantee modifications for that range will
           not be reflected back in file.
        */
        if (myst_run)
        {
            printf("mem before copy: %s\n", addr);
            strcpy(addr, "astringlongerthan10characters");
            printf("mem after copy: %s\n", addr);
            assert(!strcmp(addr, "astringlongerthan10characters"));
        }

        assert(munmap(addr, FILE_SIZE) == 0);

        if (myst_run)
        {
            // read file
            char buf[20];
            int nbytes = read(fd, buf, 10);
            printf("nbytes in file=%d\n", nbytes);
            // assert file did not grow
            assert(nbytes == 0);
            if (nbytes)
                printf("data: %s\n", buf);
        }

        assert(unlink(data_file_name) == 0);
    }
    else if (strcmp(argv[1], "share") == 0)
    {
        char* addr;
        int fd = -1;

        {
            fd = open(data_file_name, O_CREAT | O_RDWR, (S_IRUSR | S_IWUSR));
            assert(fd >= 0);

            assert(ftruncate(fd, FILE_SIZE) != -1);

            addr =
                mmap(0, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            assert(addr != MAP_FAILED);
            close(fd);

            printf("addr=%p contents before fork=%s\n", addr, addr);
        }

        pid_t cpid = fork();
        assert(cpid != -1);

        if (cpid == 0) // child writes to shared memory
        {
            strcpy(addr, "wrldhello");
            assert(munmap(addr, FILE_SIZE) == 0);
        }
        else // parent waits on child and then verifies write
        {
            int wstatus;
            assert(waitpid(cpid, &wstatus, 0) == cpid && WIFEXITED(wstatus));
            printf("addr=%p contents after fork=%s\n", addr, addr);
            assert(!strcmp(addr, "wrldhello"));
            exit(0);
        }
    }
    else if (strcmp(argv[1], "restricted-mremap") == 0)
    {
        int fd = open(data_file_name, O_CREAT | O_RDWR, (S_IRUSR | S_IWUSR));
        assert(fd >= 0);
        assert(ftruncate(fd, FILE_SIZE) != -1);

        char* addr =
            mmap(0, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

        // check mremap() is allowed when a single Mystikos process thread has
        // the memory region mapped
        {
            char* new_addr =
                mremap(addr, FILE_SIZE, 2 * PAGE_SIZE, MREMAP_MAYMOVE);
            assert(new_addr != MAP_FAILED);
            addr = new_addr;
        }

        // Check failure of mremap when >1 Mystikos process threads share the
        // mapping. mremap() operation can potentially move the mapping to a
        // different virtual address range. Mystikos manages a linear virtual
        // address space. And so can't provide aliases within that space. Ring 0
        // kernels control the virtual to physical mapping, and therefore can
        // allow same physical memory region to be addressed with different
        // virtual addresses within a process or across processes.
        {
            pid_t cpid = fork();
            assert(cpid != -1);

            if (cpid == 0)
            {
                char* new_addr =
                    mremap(addr, FILE_SIZE, 2 * PAGE_SIZE, MREMAP_MAYMOVE);
                assert(new_addr == MAP_FAILED);
            }
            else
            {
                int wstatus;
                assert(waitpid(cpid, &wstatus, 0) == cpid);
                assert(WIFEXITED(wstatus));

                // check mremap is allowed now that we are single process again
                {
                    char* new_addr2 = mremap(
                        addr, 2 * PAGE_SIZE, 4 * PAGE_SIZE, MREMAP_MAYMOVE);
                    assert(new_addr2 != MAP_FAILED);
                }
                assert(unlink(data_file_name) != -1);
                exit(0);
            }
        }
    }
    else if (strcmp(argv[1], "restricted-mprotect") == 0)
    {
        int fd = open(data_file_name, O_CREAT | O_RDWR, (S_IRUSR | S_IWUSR));
        assert(fd >= 0);
        assert(ftruncate(fd, FILE_SIZE) != -1);

        char* addr =
            mmap(0, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

        // check mprotect() is allowed if single user
        {
            int ret = mprotect(addr, FILE_SIZE, PROT_READ);
            assert(ret == 0);
        }

        // Check failure of mprotect when >1 Mystikos process threads sharing a
        // mapping. Mystikos runs single process on the host OS(Linux in our
        // case). On Linux, page protections are at the granularity of process.
        // Because of this limitation, Mystikos panics when it detects a
        // mprotect on an address range which is shared by multiple Mystikos
        // process threads.
        {
            pid_t cpid = fork();
            assert(cpid != -1);

            if (cpid == 0)
            {
                // try to change page permission to write only
                int ret = mprotect(addr, FILE_SIZE, PROT_WRITE);
                assert(ret != 0 && errno == EINVAL);
            }
            else
            {
                int wstatus;
                assert(waitpid(cpid, &wstatus, 0) == cpid);
                assert(WIFEXITED(wstatus));

                // check mprotect is allowed now that we are single process
                // again
                {
                    int ret = mprotect(addr, FILE_SIZE, PROT_WRITE);
                    assert(ret == 0);
                }

                assert(unlink(data_file_name) != -1);
                exit(0);
            }
        }
    }
    else if (strcmp(argv[1], "partial-ops-unsupported") == 0)
    {
        char* addr;
        int fd = open(data_file_name, O_CREAT | O_RDWR, (S_IRUSR | S_IWUSR));
        assert(fd >= 0);
        assert(ftruncate(fd, 2 * PAGE_SIZE) != -1);

        // musl checks for page alignment of offset
        addr = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 15);
        printf("misaligned offset addr=%p errno=%s\n", addr, strerror(errno));
        assert(addr == MAP_FAILED && errno == EINVAL);

        addr =
            mmap(0, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        assert(addr != MAP_FAILED);

        /*
        Current design does not support mremap or mprotect operations at a
        non-zero offset from the start of a shared memory region. This is to
        avoid complexity in tracking of shared memory regions. None of the
        programs we run in our CI exhibit such usage. We fail loudly with a
        SIGSEGV, so that if we ever run such a situation its noticeable.
        */

        // check failure of partial mremap
        {
            pid_t cpid = fork();
            assert(cpid != -1);

            if (cpid == 0)
            {
                // partial mremap should throw SIGSEGV
                mremap(
                    addr + PAGE_SIZE, PAGE_SIZE, 2 * PAGE_SIZE, MREMAP_MAYMOVE);
            }
            else
            {
                int wstatus;
                assert(waitpid(cpid, &wstatus, 0) == cpid);
                // check child was killed with SIGSEGV
                printf("wstatus=%d\n", wstatus);
                assert(WIFSIGNALED(wstatus) && WTERMSIG(wstatus) == SIGSEGV);
            }
        }

        // check failure of partial mprotect
        {
            pid_t cpid = fork();
            assert(cpid != -1);

            if (cpid == 0)
            {
                // partial mprotect should throw SIGSEGV
                mprotect(addr + PAGE_SIZE, PAGE_SIZE, PROT_WRITE);
            }
            else
            {
                int wstatus;
                waitpid(cpid, &wstatus, 0);
                // check child was killed with SIGSEGV
                printf("wstatus=%d\n", wstatus);
                assert(WIFSIGNALED(wstatus) && WTERMSIG(wstatus) == SIGSEGV);
            }
        }

        assert(unlink(data_file_name) != -1);
    }
    else
    {
        printf("Unsupported test arg: %s\n", argv[1]);
    }
}
