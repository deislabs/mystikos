#include <openenclave/host.h>
#include <openenclave/edger8r/host.h>
#include <string.h>

struct _oe_enclave
{
    const oe_ocall_func_t* ocall_table;
    uint32_t ocall_count;
};

oe_result_t oe_create_enclave(
    const char* path,
    oe_enclave_type_t type,
    uint32_t flags,
    const oe_enclave_setting_t* settings,
    uint32_t setting_count,
    const oe_ocall_func_t* ocall_table,
    uint32_t ocall_count,
    oe_enclave_t** enclave_out)
{
    oe_result_t result = OE_OK;
    oe_enclave_t* enclave = NULL;

    if (enclave_out)
        *enclave_out = NULL;

    if (!path || !enclave_out)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    if (strcmp(path, "[libos]") != 0)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    if (!ocall_table && ocall_count)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    if (!settings && setting_count)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    if (flags & OE_ENCLAVE_FLAG_RESERVED)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    if (!(enclave = (oe_enclave_t*)calloc(1, sizeof(oe_enclave_t))))
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }

    enclave->ocall_table = ocall_table;
    enclave->ocall_count = ocall_count;

    *enclave_out = enclave;
    enclave = NULL;

done:

    if (enclave)
        free(enclave);

    return result;
}

oe_result_t oe_terminate_enclave(oe_enclave_t* enclave)
{
    oe_result_t result = OE_OK;

    if (!enclave)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    free(enclave);

done:
    return result;
}

oe_result_t oe_call_enclave_function(
    oe_enclave_t* enclave,
    uint32_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    (void)enclave;
    (void)input_buffer;
    (void)input_buffer_size;
    (void)output_buffer;
    (void)output_buffer_size;
    (void)output_bytes_written;

    printf("oe_call_enclave_function()\n");

    memset(output_buffer, 0, output_buffer_size);
    *output_bytes_written = output_buffer_size;

    return OE_OK;
}
