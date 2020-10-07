#include <ctype.h>
#include <libos/json.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STRLIT(STR) STR, sizeof(STR) - 1

#define RAISE(RESULT)                                                 \
    do                                                                \
    {                                                                 \
        json_result_t _r_ = RESULT;                                   \
        result = _r_;                                                 \
        _trace_result(parser, __FILE__, __LINE__, __FUNCTION__, _r_); \
        goto done;                                                    \
    } while (0)

static void _Indent(json_write_t write, void* stream, size_t depth)
{
    size_t i;

    for (i = 0; i < depth; i++)
        (*write)(stream, STRLIT("  "));
}

static void _trace(
    json_parser_t* parser,
    const char* file,
    uint32_t line,
    const char* func,
    const char* message)
{
    if (parser && parser->trace)
        (*parser->trace)(parser, file, line, func, message);
}

static void _trace_result(
    json_parser_t* parser,
    const char* file,
    uint32_t line,
    const char* func,
    json_result_t result)
{
    if (parser && parser->trace)
    {
        char buf[64];
        snprintf(buf, sizeof(buf), "result: %s", json_result_string(result));
        _trace(parser, file, line, func, buf);
    }
}

static void _PrintString(json_write_t write, void* stream, const char* str)
{
    (*write)(stream, STRLIT("\""));

    while (*str)
    {
        char c = *str++;

        switch (c)
        {
            case '"':
                (*write)(stream, STRLIT("\\\""));
                break;
            case '\\':
                (*write)(stream, STRLIT("\\\\"));
                break;
            case '/':
                (*write)(stream, STRLIT("\\/"));
                break;
            case '\b':
                (*write)(stream, STRLIT("\\b"));
                break;
            case '\f':
                (*write)(stream, STRLIT("\\f"));
                break;
            case '\n':
                (*write)(stream, STRLIT("\\n"));
                break;
            case '\r':
                (*write)(stream, STRLIT("\\r"));
                break;
            case '\t':
                (*write)(stream, STRLIT("\\t"));
                break;
            default:
            {
                if (isprint(c))
                {
                    (*write)(stream, &c, 1);
                }
                else
                {
                    char buf[3];
                    snprintf(buf, sizeof(buf), "%02x", c);
                    (*write)(stream, STRLIT("\\u00"));
                    (*write)(stream, buf, 2);
                }
            }
        }
    }

    (*write)(stream, STRLIT("\""));
}

void json_print_value(
    json_write_t write,
    void* stream,
    json_type_t type,
    const json_union_t* un)
{
    switch (type)
    {
        case JSON_TYPE_NULL:
        {
            (*write)(stream, STRLIT("null"));
            break;
        }
        case JSON_TYPE_BOOLEAN:
        {
            if (un->boolean)
                (*write)(stream, STRLIT("true"));
            else
                (*write)(stream, STRLIT("false"));
            break;
        }
        case JSON_TYPE_INTEGER:
        {
            char buf[32];
            int size = snprintf(buf, sizeof(buf), "%ld", un->integer);
            (*write)(stream, buf, size);
            break;
        }
        case JSON_TYPE_REAL:
        {
            char buf[64];
            int size = snprintf(buf, sizeof(buf), "%lf", un->real);
            (*write)(stream, buf, size);
            break;
        }
        case JSON_TYPE_STRING:
            _PrintString(write, stream, un->string);
            break;
        default:
            break;
    }
}

typedef struct callback_data
{
    int depth;
    int newline;
    int comma;
    json_write_t write;
    void* stream;
} callback_data_t;

json_result_t _json_print_callback(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un,
    void* callback_data)
{
    callback_data_t* data = callback_data;
    json_write_t write = data->write;
    void* stream = data->stream;

    (void)parser;

    /* Print commas */
    if (reason != JSON_REASON_END_ARRAY && reason != JSON_REASON_END_OBJECT &&
        data->comma)
    {
        data->comma = 0;
        (*write)(stream, STRLIT(","));
    }

    /* Decrease depth */
    if (reason == JSON_REASON_END_OBJECT || reason == JSON_REASON_END_ARRAY)
    {
        data->depth--;
    }

    /* Print newline */
    if (data->newline)
    {
        data->newline = 0;
        (*write)(stream, STRLIT("\n"));
        _Indent(write, stream, (size_t)(data->depth));
    }

    switch (reason)
    {
        case JSON_REASON_NONE:
        {
            /* Unreachable */
            break;
        }
        case JSON_REASON_NAME:
        {
            _PrintString(write, stream, un->string);
            (*write)(stream, STRLIT(": "));
            data->comma = 0;
            break;
        }
        case JSON_REASON_BEGIN_OBJECT:
        {
            data->depth++;
            data->newline = 1;
            data->comma = 0;
            (*write)(stream, STRLIT("{"));
            break;
        }
        case JSON_REASON_END_OBJECT:
        {
            data->newline = 1;
            data->comma = 1;
            (*write)(stream, STRLIT("}"));
            break;
        }
        case JSON_REASON_BEGIN_ARRAY:
        {
            data->depth++;
            data->newline = 1;
            data->comma = 0;
            (*write)(stream, STRLIT("["));
            break;
        }
        case JSON_REASON_END_ARRAY:
        {
            data->newline = 1;
            data->comma = 1;
            (*write)(stream, STRLIT("]"));
            break;
        }
        case JSON_REASON_VALUE:
        {
            data->newline = 1;
            data->comma = 1;
            json_print_value(write, stream, type, un);
            break;
        }
    }

    /* Final newline */
    if (reason == JSON_REASON_END_OBJECT || reason == JSON_REASON_END_ARRAY)
    {
        if (data->depth == 0)
            (*write)(stream, STRLIT("\n"));
    }

    return JSON_OK;
}

json_result_t json_print(
    json_write_t write,
    void* stream,
    const char* json_data,
    size_t json_size,
    json_allocator_t* allocator)
{
    json_result_t result = JSON_UNEXPECTED;
    char* data = NULL;
    json_parser_t parser_buf;
    json_parser_t* parser = &parser_buf;
    callback_data_t callback_data = {0, 0, 0, write, stream};

    extern int printf(const char* fmt, ...);
    memset(&parser_buf, 0, sizeof(parser_buf));

    if (!write || !json_data || !json_size)
        RAISE(JSON_BAD_PARAMETER);

    if (!allocator || !allocator->ja_malloc || !allocator->ja_free)
        return JSON_BAD_PARAMETER;

    if (!(data = allocator->ja_malloc(json_size)))
        RAISE(JSON_OUT_OF_MEMORY);

    memcpy(data, json_data, json_size);

    if (json_parser_init(
            parser,
            data,
            json_size,
            _json_print_callback,
            &callback_data,
            allocator,
            NULL) != JSON_OK)
    {
        RAISE(JSON_FAILED);
    }

    if (json_parser_parse(parser) != JSON_OK)
    {
        RAISE(JSON_BAD_SYNTAX);
    }

    if (callback_data.depth != 0)
    {
        RAISE(JSON_BAD_SYNTAX);
    }

    result = JSON_OK;

done:

    if (data)
        allocator->ja_free(data);

    return result;
}

void json_dump_path(json_write_t write, void* stream, json_parser_t* parser)
{
    if (write && parser)
    {
        size_t depth = parser->depth;

        for (size_t i = 0; i < depth; i++)
        {
            (*write)(
                stream, parser->path[i].name, strlen(parser->path[i].name));

            if (parser->path[i].size)
            {
                char buf[32];
                int size;

                size = snprintf(buf, sizeof(buf), "%ld", parser->path[i].size);
                (*write)(stream, STRLIT("["));
                (*write)(stream, buf, size);
                (*write)(stream, STRLIT("]"));
            }

            if (i + 1 != depth)
                (*write)(stream, STRLIT("."));
        }

        (*write)(stream, STRLIT("\n"));
    }
}

unsigned long json_get_array_index(json_parser_t* parser)
{
    if (parser->depth < 2)
        return (unsigned long)-1;
    return parser->path[parser->depth - 2].index;
}
