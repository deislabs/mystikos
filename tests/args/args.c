// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <libos/args.h>
#include <libos/defs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

void dump(const char* args[], size_t size)
{
    for (size_t i = 0; i < size; i++)
        printf("args[%zu]={%s}\n", i, args[i]);

    printf("\n");
}

void test_pack_unpack(void)
{
    libos_args_t args;

    assert(libos_args_init(&args) == 0);
    assert(args.size == 0);
    assert(args.data[0] == NULL);

    assert(libos_args_append(&args, NULL, 0) == 0);

    assert(libos_args_append1(&args, "red") == 0);
    assert(args.size == 1);
    assert(strcmp(args.data[0], "red") == 0);
    assert(args.data[1] == NULL);

    assert(libos_args_append1(&args, "green") == 0);
    assert(args.size == 2);
    assert(strcmp(args.data[0], "red") == 0);
    assert(strcmp(args.data[1], "green") == 0);
    assert(args.data[2] == NULL);

    assert(libos_args_append1(&args, "blue") == 0);
    assert(args.size == 3);
    assert(strcmp(args.data[0], "red") == 0);
    assert(strcmp(args.data[1], "green") == 0);
    assert(strcmp(args.data[2], "blue") == 0);
    assert(args.data[3] == NULL);

    assert(libos_args_prepend1(&args, "yellow") == 0);
    assert(args.size == 4);
    assert(strcmp(args.data[0], "yellow") == 0);
    assert(strcmp(args.data[1], "red") == 0);
    assert(strcmp(args.data[2], "green") == 0);
    assert(strcmp(args.data[3], "blue") == 0);
    assert(args.data[4] == NULL);

    void* packed_data;
    size_t packed_size;
    assert(libos_args_pack(&args, &packed_data, &packed_size) == 0);
    assert(packed_data != NULL);
    assert(packed_size != 0);

    libos_args_t out;
    assert(libos_args_unpack(&out, packed_data, packed_size) == 0);
    assert(out.size == 4);
    assert(strcmp(out.data[0], "yellow") == 0);
    assert(strcmp(out.data[1], "red") == 0);
    assert(strcmp(out.data[2], "green") == 0);
    assert(strcmp(out.data[3], "blue") == 0);
    assert(out.data[4] == NULL);

    assert(libos_args_prepend(&args, args.data, args.size) == 0);
    assert(args.size == 8);
    assert(strcmp(args.data[0], "yellow") == 0);
    assert(strcmp(args.data[1], "red") == 0);
    assert(strcmp(args.data[2], "green") == 0);
    assert(strcmp(args.data[3], "blue") == 0);
    assert(strcmp(args.data[4], "yellow") == 0);
    assert(strcmp(args.data[5], "red") == 0);
    assert(strcmp(args.data[6], "green") == 0);
    assert(strcmp(args.data[7], "blue") == 0);
    assert(args.data[8] == NULL);

    assert(libos_args_remove(&args, 1, 6) == 0);
    assert(args.size == 2);
    assert(strcmp(args.data[0], "yellow") == 0);
    assert(strcmp(args.data[1], "blue") == 0);
    assert(args.data[2] == NULL);

    assert(libos_args_remove(&args, 1, 1) == 0);
    assert(args.size == 1);
    assert(strcmp(args.data[0], "yellow") == 0);
    assert(args.data[1] == NULL);

    assert(libos_args_remove(&args, 0, 1) == 0);
    assert(args.size == 0);
    assert(args.data[0] == NULL);

    free(args.data);
    free(out.data);
    free(packed_data);
}

void test_missing_null_terminator(void)
{
    libos_args_t args;

    assert(libos_args_init(&args) == 0);
    assert(args.size == 0);
    assert(args.data[0] == NULL);

    assert(libos_args_append(&args, NULL, 0) == 0);

    assert(libos_args_append1(&args, "arg0") == 0);
    assert(args.size == 1);

    assert(strcmp(args.data[0], "arg0") == 0);
    assert(args.data[1] == NULL);

    assert(libos_args_append1(&args, "arg1") == 0);
    assert(args.size == 2);

    assert(strcmp(args.data[1], "arg1") == 0);
    assert(args.data[2] == NULL);

    void* packed_data;
    size_t packed_size;
    assert(libos_args_pack(&args, &packed_data, &packed_size) == 0);
    assert(packed_data != NULL);
    assert(packed_size != 0);

    /* replace the null terminator of "arg1" with "x" */
    {
        bool found = false;
        uint8_t* start = packed_data;
        uint8_t* end = (uint8_t*)packed_data + packed_size;

        for (uint8_t* p = start; p != end; p++)
        {
            if (memcmp(p, "arg1", 5) == 0)
            {
                p[4] = 'x';
                found = true;
                break;
            }
        }

        assert(found);
    }

    /* unpacking should detect the missing null byte and fail */
    libos_args_t out;
    assert(libos_args_unpack(&out, packed_data, packed_size) == -1);

    free(args.data);
    free(packed_data);
}

void test_bounds_violation(void)
{
    libos_args_t args;

    assert(libos_args_init(&args) == 0);
    assert(args.size == 0);
    assert(args.data[0] == NULL);

    assert(libos_args_append(&args, NULL, 0) == 0);

    assert(libos_args_append1(&args, "arg0") == 0);
    assert(args.size == 1);

    assert(strcmp(args.data[0], "arg0") == 0);
    assert(args.data[1] == NULL);

    void* packed_data;
    size_t packed_size;
    assert(libos_args_pack(&args, &packed_data, &packed_size) == 0);
    assert(packed_data != NULL);
    assert(packed_size != 0);

    /* enlarge the packed data by one byte */
    assert((packed_data = realloc(packed_data, packed_size + 1)) != NULL);

    /* replace "arg0" with a longer string that extends beyond the end of buf */
    {
        bool found = false;
        uint8_t* start = packed_data;
        uint8_t* end = (uint8_t*)packed_data + packed_size;

        for (uint8_t* p = start; p != end; p++)
        {
            const size_t r = end - p;

            if (memcmp(p, "arg0", 5) == 0)
            {
                memset(p, 'x', r + 1);
                p[r] = '\0';

                /* change the size to be one larger than the remaining bytes */
                *((size_t*)p - 1) = r + 1;
                found = true;
                break;
            }
        }

        assert(found);
    }

    /* unpacking should detect the missing null byte and fail */
    libos_args_t out;
    assert(libos_args_unpack(&out, packed_data, packed_size) == -1);

    free(args.data);
    free(packed_data);
}

int main(int argc, const char* argv[])
{
    test_pack_unpack();
    test_missing_null_terminator();
    test_bounds_violation();

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
