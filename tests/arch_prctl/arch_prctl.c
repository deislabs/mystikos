#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004
#define ARCH_GET_CPUID 0x1011
#define ARCH_SET_CPUID 0x1012

int arch_prctl(int code, ...)
{
    va_list ap;
    va_start(ap, code);
    long arg = va_arg(ap, long);
    va_end(ap);

    return syscall(SYS_arch_prctl, code, arg);
}

/* Assumes fs:0 will be a self pointer */
const void* read_fs_base(void)
{
    void* p = 0;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(p));
    return p;
}

/* Assumes gs:0 will be a self pointer */
const void* read_gs_base(void)
{
    void* p = 0;
    __asm__ volatile("mov %%gs:0, %0" : "=r"(p));
    return p;
}

int main(int argc, const char* argv[])
{
    struct thread_descriptor
    {
        void* self;
        uint64_t reserved1;
        uint64_t reserved2;
        uint64_t reserved3;
        uint64_t reserved4;
        uint64_t canary;
    };

    /* test ARCH_GET_FS */
    {
        void* addr;
        int ret = arch_prctl(ARCH_GET_FS, &addr);
        assert(ret == 0);
        assert(addr == read_fs_base());
    }

    /* test ARCH_GET_GS */
    {
        void* addr;
        int ret = arch_prctl(ARCH_GET_GS, &addr);
        assert(ret == 0);
        assert(addr == read_gs_base());
    }

    /* test ARCH_SET_GS */
    {
        struct thread_descriptor td;
        td.self = (void*)&td;
        int ret = arch_prctl(ARCH_SET_GS, &td);
        assert(ret == -1);
        assert(errno == EINVAL);
    }

    /* test ARCH_SET_FS */
    {
        struct thread_descriptor td;
        td.self = (void*)&td;
        struct thread_descriptor* fs1 = (void*)read_fs_base();

        int ret1 = arch_prctl(ARCH_SET_FS, (void*)&td);
        assert(ret1 == 0);
        void* fs2 = (void*)read_fs_base();
        assert(fs1 != fs2);
        assert(fs2 == (void*)&td);

        int ret2 = arch_prctl(ARCH_SET_FS, (void*)fs1);
        assert(ret2 == 0);
        assert((void*)read_fs_base() == fs1);
    }

    printf("=== passed test (%s)\n", argv[0]);
    return 0;
}
