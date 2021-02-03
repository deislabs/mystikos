// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <myst/file.h>
#include <myst/json.h>

const char* arg0;

static void _write(void* stream, const void* buf, size_t count)
{
    fwrite(buf, 1, count, (FILE*)stream);
}

static void _trace(
    json_parser_t* parser,
    const char* file,
    unsigned int line,
    const char* func,
    const char* message)
{
    printf("trace: %s(%u): %s(): %s\n", file, line, func, message);
}

int main(int argc, char** argv)
{
    static json_allocator_t allocator = {
        malloc,
        free,
    };
    char* data;
    size_t size;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s path\n", argv[0]);
        exit(1);
    }

    if (myst_load_file(argv[1], (void**)&data, &size) != 0)
    {
        fprintf(stderr, "%s: failed to access '%s'\n", argv[0], argv[1]);
        exit(1);
    }

    if (json_print(_write, stdout, _trace, data, size, &allocator) != JSON_OK)
    {
        fprintf(stderr, "%s: json_print() failed\n", argv[0]);
        exit(1);
    }

    return 0;
}
