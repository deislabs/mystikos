#include <openenclave/edger8r/host.h>
#include <openenclave/host.h>
#include <string.h>

/* Only singleton enclave supported for now */
oe_enclave_t* _enclave;

typedef struct ocall_table
{
    const oe_ocall_func_t* functions;
    size_t count;
} ocall_table_t;

struct _oe_enclave
{
    ocall_table_t ocalls;
};

oe_result_t oe_create_enclave(
    const char* path,
    oe_enclave_type_t type,
    uint32_t flags,
    const oe_enclave_setting_t* settings,
    uint32_t setting_count,
    const oe_ocall_func_t* ocall_table,
    uint32_t ocall_count,
    const oe_ecall_info_t* ecall_name_table,
    uint32_t ecall_count,
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

    if (_enclave)
    {
        result = OE_FAILURE;
        goto done;
    }

    if (!(enclave = (oe_enclave_t*)calloc(1, sizeof(oe_enclave_t))))
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }

    enclave->ocalls.functions = ocall_table;
    enclave->ocalls.count = ocall_count;

    _enclave = enclave;

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
    uint64_t* global_id,
    const char* name,
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

    if (output_bytes_written)
        *output_bytes_written = 0;

    printf("=== oe_call_enclave_function()\n");
    printf("enclave=%p\n", enclave);
    printf("input_buffer=%p\n", input_buffer);
    printf("input_buffer_size=%zu\n", input_buffer_size);
    printf("output_buffer=%p\n", output_buffer);
    printf("output_buffer_size=%zu\n", output_buffer_size);

    memset(output_buffer, 0, output_buffer_size);
    *output_bytes_written = output_buffer_size;

    return OE_OK;
}

/* called from enclave as an ocall */
OE_EXPORT
oe_result_t oe_dispatch_host_function(
    size_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    oe_result_t result = OE_OK;
    ocall_table_t ocalls;

    if (!input_buffer || !output_buffer || !output_bytes_written || !_enclave)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    ocalls = _enclave->ocalls;

    if (function_id >= ocalls.count || !ocalls.functions ||
        !ocalls.functions[function_id])
    {
        result = OE_FAILURE;
        goto done;
    }

    (*ocalls.functions[function_id])(
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written);

done:
    return result;
}
