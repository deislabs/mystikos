#include <echo_t.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int echo_ecall(const char* msg)
{
    printf("echo_ecall: msg=%s\n", msg);
    return 0;
}

int main(int argc, const char* argv[])
{
    int retval;
    oe_result_t result;

    if ((result = echo_ocall(&retval, "calling home")) != OE_OK)
    {
        fprintf(stderr, "echo_ocall() failed: result=%u\n", result);
        exit(1);
    }

    return 0;
}
