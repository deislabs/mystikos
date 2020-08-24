// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <libos/conf.h>
#include <libos/loadfile.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

static char _name[64];
static char _number[64];

static int _callback(
    const char* name,
    const char* value,
    void* callback_data,
    libos_conf_err_t* err)
{
    if (strcmp(name, "name") == 0)
    {
        snprintf(_name, sizeof(_name), "%s", value);
        return 0;
    }

    if (strcmp(name, "number") == 0)
    {
        snprintf(_number, sizeof(_number), "%s", value);
        return 0;
    }

    snprintf(err->buf, sizeof(err->buf), "unknown: %s=%s", name, value);

    return -1;
}

int main(int argc, const char* argv[])
{
    void* data = NULL;
    size_t size;
    size_t line;
    libos_conf_err_t err;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <config-file>\n", argv[0]);
        exit(1);
    }

    if (libos_load_file(argv[1], &data, &size) != 0)
    {
        fprintf(stderr, "failed to open: %s\n", argv[1]);
        exit(1);
    }

    if (libos_conf_parse(data, size, _callback, NULL, &line, &err) != 0)
    {
        fprintf(stderr, "parse failed: %s\n", err.buf);
        exit(1);
    }

    assert(strcmp(_name, "Fred") == 0);
    assert(strcmp(_number, "12345") == 0);

    free(data);

    return 0;
}
