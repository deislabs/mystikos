// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <libos/string.h>
#include <stdio.h>
#include <string.h>

int main(int argc, const char* argv[])
{
    string_t s;
    char buf[16 + 1];

    string_init(&s, buf, sizeof(buf));
    assert(string_cap(&s) == sizeof(buf) - 1);
    assert(string_cpy(&s, "red") == 0);
    assert(string_cat(&s, " ") == 0);
    assert(string_cat(&s, "green") == 0);
    assert(string_cat(&s, " ") == 0);
    assert(string_cat(&s, "blue") == 0);
    assert(string_cat(&s, "overflow") == -1);
    assert(string_cat(&s, "xy") == 0);
    assert(string_len(&s) == 16);

    printf("%s\n", s.ptr);

    assert(strcmp(string_ptr(&s), "red green bluexy") == 0);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
