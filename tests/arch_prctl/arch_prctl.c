#include <assert.h>
#include <errno.h>
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

struct test_case
{
    int code;
    int ret;
    int errno_val;
} test_cases[] = {
    {ARCH_GET_FS, 0, 0},
    {ARCH_GET_GS, 0, 0},
    {ARCH_SET_FS, -1, EINVAL},
    {ARCH_SET_GS, -1, EINVAL},
    {ARCH_GET_CPUID, -1, EINVAL},
    {ARCH_SET_CPUID, -1, EINVAL},
};
int ntests = sizeof(test_cases) / sizeof(struct test_case);

int arch_prctl(int code, unsigned long* addr)
{
    int ret;
    ret = syscall(SYS_arch_prctl, code, addr);
    // printf("ret= %d code= %x addr= %lx errno= %d \n", ret, code, *addr,
    // errno);
    return ret;
}

/* Assumes fs:0 will be a self pointer */
long read_fs_base()
{
    long x0 = 0;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(x0));
    // printf("fs=%lx\n", x0);
    return x0;
}

/* Assumes gs:0 will be a self pointer */
long read_gs_base()
{
    long x0 = 0;
    __asm__ volatile("mov %%gs:0, %0" : "=r"(x0));
    // printf("gs=%lx\n", x0);
    return x0;
}

int main(int argc, const char* argv[])
{
    for (int i = 0; i < ntests; i++)
    {
        struct test_case tc = test_cases[i];
        long addr;
        int ret = arch_prctl(tc.code, &addr);
        assert(ret == tc.ret);
        if (ret != 0)
            assert(errno == tc.errno_val);
        if (tc.code == ARCH_GET_FS)
            assert(addr == read_fs_base());
        if (tc.code == ARCH_GET_GS)
            assert(addr == read_gs_base());
    }
    printf("=== passed test (%s)\n", argv[0]);
    return 0;
}
