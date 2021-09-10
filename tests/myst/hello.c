// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

/* non-public OE functions */
extern const void* __oe_get_enclave_start_address(void);
extern const void* __oe_get_enclave_base_address(void);

#define OFFSET 5

static int _segv_handled = 0;
static uint64_t faulting_address;

static void _sigsegv_handler(int signum, siginfo_t* siginfo, void* context)
{
    ucontext_t* ucontext = (ucontext_t*)context;
    faulting_address = (uint64_t)siginfo->si_addr;
    if (siginfo->si_signo == SIGSEGV)
        _segv_handled = 1;
    ucontext->uc_mcontext.gregs[REG_RIP] += 3; // non-portable.
}

void test_pf_exception(void)
{
    struct sigaction act = {0};
    const size_t PAGE_SIZE = 4096;
    size_t length = PAGE_SIZE;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    uint8_t data = 0;

    /* register signal handler */
    act.sa_sigaction = _sigsegv_handler;
    act.sa_flags = SA_SIGINFO | SA_NODEFER;
    if (sigaction(SIGSEGV, &act, NULL) < 0)
    {
        printf("sigaction failed\n");
        return;
    }

    uint8_t* addr = mmap(NULL, length, PROT_NONE, flags, -1, 0);
    if (addr == MAP_FAILED)
    {
        printf("mmap failed\n");
        return;
    }

    /* Explicitly set a non-page-aligned address */
    uint64_t expected_faulting_address = (uint64_t)addr + OFFSET;
    uint64_t expected_faulting_address_aligned =
        expected_faulting_address & ~(PAGE_SIZE - 1);

    data = *(uint64_t*)expected_faulting_address;

    if (_segv_handled != 1)
    {
        printf("handler is not invoked\n");
        return;
    }

    /* This test only works on the icelake machine. */
    if (expected_faulting_address == faulting_address)
        printf("Got the faulting address as expected\n");
    /* This test only works on the coffelake machine (debug mode) as
     * the faulting address is always with lower 12-bit cleared. */
    else if (expected_faulting_address_aligned == faulting_address)
        printf("Got the faulting address as expected\n");
    else
        printf("test failed\n");
}

void test_zerobase(void)
{
    const void* start_address = __oe_get_enclave_start_address();
    printf("=== enclave_start_address=%p\n", start_address);

    const void* base_address = __oe_get_enclave_base_address();
    printf("=== enclave_base_address=%p\n", base_address);
}

void test_disable_zerobase(void)
{
    const void* base_address = __oe_get_enclave_base_address();

    if (base_address == 0)
        printf("=== enclave_base_address=%p. Test failed.\n", base_address);
    else
        printf("=== enclave_base_address != 0x0\n");
}

int main(int argc, const char* argv[], const char* envp[])
{
    printf("\n");

    for (int i = 0; i < argc; i++)
        printf("argv[%d]=%s\n", i, argv[i]);

    printf("\n");

    for (int i = 0; envp[i] != NULL; i++)
        printf("envp[%d]=%s\n", i, envp[i]);

    printf("\n");

    printf("=== Hello World!\n\n");

    if (strstr(argv[1], "disable-zero-base"))
        test_disable_zerobase();
    else if (strstr(argv[1], "test-zero-base"))
        test_zerobase();
    else if (strstr(argv[1], "test-pf-exception"))
        test_pf_exception();

    return 0;
}
