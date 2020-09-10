// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <libos/buf.h>
#include <stdio.h>
#include <string.h>

int main(int argc, const char* argv[])
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

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
