// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <libos/buf.h>
#include <libos/defs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void test_packing()
{
    libos_buf_t buf = LIBOS_BUF_INITIALIZER;
    const char* argv[] = {"red", "green", "blue"};
    size_t argc = LIBOS_COUNTOF(argv);

    /* pack */
    {
        assert(libos_buf_pack_u64(&buf, 12345) == 0);
        assert(libos_buf_pack_str(&buf, "hello world") == 0);
        assert(libos_buf_pack_str(&buf, "") == 0);
        assert(libos_buf_pack_strings(&buf, argv, argc) == 0);
    }

    /* unpack */
    {
        uint64_t x;
        const char* str1;
        const char* str2;
        size_t len;
        const char** strings;
        size_t count;

        assert(libos_buf_unpack_u64(&buf, &x) == 0);
        assert(x == 12345);

        assert(libos_buf_unpack_str(&buf, &str1, &len) == 0);
        assert(str1 != NULL);
        assert(len == 11);
        assert(strcmp(str1, "hello world") == 0);

        assert(libos_buf_unpack_str(&buf, &str2, &len) == 0);
        assert(str2 != NULL);
        assert(len == 0);
        assert(strcmp(str2, "") == 0);

        assert(libos_buf_unpack_strings(&buf, &strings, &count) == 0);
        assert(count == argc);

        for (size_t i = 0; i < count; i++)
        {
            assert(strings[i] != NULL);
            assert(strcmp(strings[i], argv[i]) == 0);
        }

        assert(strings[count] == NULL);

        free(strings);
    }

    free(buf.data);
}

void test_basic_operations()
{
    libos_buf_t buf = LIBOS_BUF_INITIALIZER;

    assert(libos_buf_append(&buf, "red", 3) == 0);
    assert(libos_buf_append(&buf, " ", 1) == 0);
    assert(libos_buf_append(&buf, "blue", 4) == 0);
    assert(libos_buf_append(&buf, "", 1) == 0);
    assert(buf.size == 9);
    assert(strcmp((char*)buf.data, "red blue") == 0);

    assert(libos_buf_insert(&buf, 3, " green", 6) == 0);
    assert(buf.size == 15);
    assert(strcmp((char*)buf.data, "red green blue") == 0);

    assert(libos_buf_insert(&buf, 14, " yellow", 7) == 0);
    assert(buf.size == 15 + 7);
    assert(strcmp((char*)buf.data, "red green blue yellow") == 0);

    free(buf.data);
}

int main(int argc, const char* argv[])
{
    test_basic_operations();
    test_packing();

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
