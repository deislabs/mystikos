#include <openenclave/host.h>
#include <assert.h>
#include <app_u.h>

#define EXPORT __attribute__((visibility("default")))

int app_ocall(const char* str)
{
    printf("app_ecall(): str=%s\n", str);
    return 0;
}

EXPORT
int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    int retval;

    if ((r = oe_create_app_enclave(
        "[libos]",
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave)) != OE_OK)
    {
        fprintf(stderr, "%s: oe_create_enclave() failed: %u\n", argv[0], r);
        exit(1);
    }

    if ((r = app_ecall(enclave, &retval, "hello")) != OE_OK)
    {
        fprintf(stderr, "%s: app_ecall() failed: %u\n", argv[0], r);
        exit(1);
    }

    if ((r = oe_terminate_enclave(enclave)) != OE_OK)
    {
        fprintf(stderr, "%s: app_ecall() failed: %u\n", argv[0], r);
        exit(1);
    }

    return 1;
}
