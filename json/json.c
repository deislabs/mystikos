/*
**==============================================================================
**
** Copyright (c) Microsoft Corporation
**
** All rights reserved.
**
** MIT License
**
** Permission is hereby granted, free of charge, to any person obtaining a copy
** of this software and associated documentation files (the ""Software""), to
** deal in the Software without restriction, including without limitation the
** rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
** sell copies of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions: The above copyright
** notice and this permission notice shall be included in all copies or
** substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
** THE SOFTWARE.
**
**==============================================================================
*/

#include <ctype.h>
#include <libos/json.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
**==============================================================================
**
** JSON parser implementation:
**
**==============================================================================
*/

#define STRLIT(STR) STR, sizeof(STR) - 1

#define RAISE(RESULT)                                                 \
    do                                                                \
    {                                                                 \
        json_result_t _r_ = RESULT;                                   \
        result = _r_;                                                 \
        _trace_result(parser, __FILE__, __LINE__, __FUNCTION__, _r_); \
        goto done;                                                    \
    } while (0)

#define CHECK(RESULT)                                                     \
    do                                                                    \
    {                                                                     \
        json_result_t _r_ = RESULT;                                       \
        if (_r_ != JSON_OK)                                               \
        {                                                                 \
            result = _r_;                                                 \
            _trace_result(parser, __FILE__, __LINE__, __FUNCTION__, _r_); \
            goto done;                                                    \
        }                                                                 \
    } while (0)

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

static void* _malloc(json_parser_t* parser, size_t size)
{
    if (!parser || !parser->allocator || !parser->allocator->ja_malloc)
        return NULL;

    return (*parser->allocator->ja_malloc)(size);
}

static void _free(json_parser_t* parser, void* ptr)
{
    if (!parser || !parser->allocator || !parser->allocator->ja_free || !ptr)
        return;

    return (*parser->allocator->ja_free)(ptr);
}

static size_t _split(
    char* s,
    const char sep,
    const char* tokens[],
    size_t num_tokens)
{
    size_t n = 0;

    for (;;)
    {
        if (n == num_tokens)
            return (size_t)-1;

        tokens[n++] = s;

        /* Skip non-separator characters */
        while (*s && *s != sep)
            s++;

        if (!*s)
            break;

        *s++ = '\0';
    }

    return n;
}

static unsigned char _char_to_nibble(char c)
{
    c = (char)tolower(c);

    if (c >= '0' && c <= '9')
        return (unsigned char)(c - '0');
    else if (c >= 'a' && c <= 'f')
        return (unsigned char)(0xa + (c - 'a'));

    return 0xFF;
}

static int _is_number_char(char c)
{
    return isdigit(c) || c == '-' || c == '+' || c == 'e' || c == 'E' ||
           c == '.';
}

static int _is_decimal_or_exponent(char c)
{
    return c == '.' || c == 'e' || c == 'E';
}

static int _hex_str4_to_u32(const char* s, uint32_t* x)
{
    uint32_t n0 = _char_to_nibble(s[0]);
    uint32_t n1 = _char_to_nibble(s[1]);
    uint32_t n2 = _char_to_nibble(s[2]);
    uint32_t n3 = _char_to_nibble(s[3]);

    if ((n0 | n1 | n2 | n3) & 0xF0)
        return -1;

    *x = (n0 << 12) | (n1 << 8) | (n2 << 4) | n3;
    return 0;
}

static json_result_t _invoke_callback(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un)
{
    if (parser->scan)
        return JSON_OK;

    return parser->callback(parser, reason, type, un, parser->callback_data);
}

static json_result_t skip_whitespace(json_parser_t* parser)
{
    while (parser->ptr != parser->end && isspace(*parser->ptr))
    {
        if (!parser->options.allow_whitespace)
            return JSON_BAD_SYNTAX;
        parser->ptr++;
    }
    return JSON_OK;
}

static json_result_t skip_comment(json_parser_t* parser)
{
    json_result_t result = JSON_OK;
    size_t nchars = parser->end - parser->ptr;

    /* Skip comment lines */
    if (nchars >= 2 && parser->ptr[0] == '/' && parser->ptr[1] == '/')
    {
        char* p = parser->ptr;

        while (p != parser->end && *p != '\n' && *p != '\r')
            p++;

        parser->ptr = p;

        CHECK(skip_whitespace(parser));
    }

done:
    return result;
}

static json_result_t _get_string(json_parser_t* parser, char** str)
{
    json_result_t result = JSON_OK;
    char* start = parser->ptr;
    char* p = start;
    const char* end = parser->end;
    int escaped = 0;

    /* Save the start of the string */
    *str = p;

    /* Find the closing quote */
    while (p != end && *p != '"')
    {
        if (*p++ == '\\')
        {
            escaped = 1;

            if (*p == 'u')
            {
                if (end - p < 4)
                    RAISE(JSON_EOF);
                p += 4;
            }
            else
            {
                if (p == end)
                    RAISE(JSON_EOF);
                p++;
            }
        }
    }

    if (p == end || *p != '"')
        RAISE(JSON_EOF);

    /* Update the os */
    parser->ptr += p - start + 1;

    /* Skip modification of text if only scanning */
    if (parser->scan)
    {
        result = JSON_OK;
        goto done;
    }

    /* Overwrite the '"' character */
    *p = '\0';
    end = p;

    /* Process escaped characters (if any) */
    if (escaped)
    {
        p = start;

        while (*p)
        {
            /* Handled escaped characters */
            if (*p == '\\')
            {
                p++;

                if (!*p)
                    RAISE(JSON_EOF);

                switch (*p)
                {
                    case '"':
                        p[-1] = '"';
                        memmove(p, p + 1, (size_t)(end - p));
                        end--;
                        break;
                    case '\\':
                        p[-1] = '\\';
                        memmove(p, p + 1, (size_t)(end - p));
                        end--;
                        break;
                    case '/':
                        p[-1] = '/';
                        memmove(p, p + 1, (size_t)(end - p));
                        end--;
                        break;
                    case 'b':
                        p[-1] = '\b';
                        memmove(p, p + 1, (size_t)(end - p));
                        end--;
                        break;
                    case 'f':
                        p[-1] = '\f';
                        memmove(p, p + 1, (size_t)(end - p));
                        end--;
                        break;
                    case 'n':
                        p[-1] = '\n';
                        memmove(p, p + 1, (size_t)(end - p));
                        end--;
                        break;
                    case 'r':
                        p[-1] = '\r';
                        memmove(p, p + 1, (size_t)(end - p));
                        end--;
                        break;
                    case 't':
                        p[-1] = '\t';
                        memmove(p, p + 1, (size_t)(end - p));
                        end--;
                        break;
                    case 'u':
                    {
                        uint32_t x;

                        p++;

                        /* Expecting 4 hex digits: XXXX */
                        if (end - p < 4)
                            RAISE(JSON_EOF);

                        if (_hex_str4_to_u32(p, &x) != 0)
                            RAISE(JSON_BAD_SYNTAX);

                        if (x >= 256)
                        {
                            /* ATTN.B: UTF-8 not supported yet! */
                            RAISE(JSON_UNSUPPORTED);
                        }

                        /* Overwrite '\' character */
                        p[-2] = (char)x;

                        /* Remove "uXXXX" */
                        memmove(p - 1, p + 4, (size_t)(end - p - 3));

                        p = p - 1;
                        end -= 5;
                        break;
                    }
                    default:
                    {
                        RAISE(JSON_FAILED);
                    }
                }
            }
            else
            {
                p++;
            }
        }
    }

#if 0
    Dump(stdout, "GETSTRING", *str, strlen(*str));
#endif

done:
    return result;
}

static int _expect(json_parser_t* parser, const char* str, size_t len)
{
    if (parser->end - parser->ptr >= (ptrdiff_t)len &&
        memcmp(parser->ptr, str, len) == 0)
    {
        parser->ptr += len;
        return 0;
    }

    return -1;
}

static json_result_t _get_value(json_parser_t* parser);

static json_result_t _get_array(json_parser_t* parser, size_t* array_size)
{
    json_result_t result = JSON_OK;
    char c;
    size_t index = 0;

    /* array = begin-array [ value *( value-separator value ) ] end-array */
    for (;;)
    {
        /* Skip whitespace */
        CHECK(skip_whitespace(parser));

        /* Skip comment lines */
        CHECK(skip_comment(parser));

        /* Fail if output exhausted */
        if (parser->ptr == parser->end)
            RAISE(JSON_EOF);

        /* Read the next character */
        c = *parser->ptr++;

        if (c == ',')
        {
            continue;
        }
        else if (c == ']')
        {
            break;
        }
        else
        {
            parser->path[parser->depth - 1].index = index++;

            parser->ptr--;
            CHECK(_get_value(parser));

            if (array_size)
                (*array_size)++;
        }
    }

done:
    return result;
}

static int strtou64(uint64_t* x, const char* str)
{
    char* end;

    *x = strtoul(str, &end, 10);

    if (!end || *end != '\0')
        return -1;

    return 0;
}

static json_result_t _get_object(json_parser_t* parser)
{
    json_result_t result = JSON_OK;
    char c;

    CHECK(_invoke_callback(
        parser, JSON_REASON_BEGIN_OBJECT, JSON_TYPE_NULL, NULL));

    if (parser->depth++ == JSON_MAX_NESTING)
        RAISE(JSON_NESTING_OVERFLOW);

    /* Expect: member = string name-separator value */
    for (;;)
    {
        /* Skip whitespace */
        CHECK(skip_whitespace(parser));

        /* Skip comment lines */
        CHECK(skip_comment(parser));

        /* Fail if output exhausted */
        if (parser->ptr == parser->end)
            RAISE(JSON_EOF);

        /* Read the next character */
        c = *parser->ptr++;

        if (c == '"')
        {
            json_union_t un;

            /* Get name */
            CHECK(_get_string(parser, (char**)&un.string));

            /* Insert node */
            {
                uint64_t n;
                json_node_t node = {un.string, 0, 0, 0};

                if (strtou64(&n, un.string) == 0)
                    node.number = n;
                else
                    node.number = UINT64_MAX;

                parser->path[parser->depth - 1] = node;
            }

            CHECK(_invoke_callback(
                parser, JSON_REASON_NAME, JSON_TYPE_STRING, &un));

            /* Expect: name-separator(':') */
            {
                /* Skip whitespace */
                CHECK(skip_whitespace(parser));

                /* Skip comment lines */
                CHECK(skip_comment(parser));

                /* Fail if output exhausted */
                if (parser->ptr == parser->end)
                    RAISE(JSON_EOF);

                /* Read the next character */
                c = *parser->ptr++;

                if (c != ':')
                    RAISE(JSON_BAD_SYNTAX);
            }

            /* Expect: value */
            CHECK(_get_value(parser));

            /* Ignore whitespace afer the value */
            CHECK(skip_whitespace(parser));

            /* A value must be followed by a comma or closing brace */
            if (*parser->ptr != ',' && *parser->ptr != '}')
                RAISE(JSON_BAD_SYNTAX);
        }
        else if (c == '}')
        {
            break;
        }
    }

    if (parser->depth == 0)
        RAISE(JSON_NESTING_UNDERFLOW);

    CHECK(
        _invoke_callback(parser, JSON_REASON_END_OBJECT, JSON_TYPE_NULL, NULL));

    parser->depth--;

done:
    return result;
}

static json_result_t _get_number(
    json_parser_t* parser,
    json_type_t* type,
    json_union_t* un)
{
    json_result_t result = JSON_OK;
    char c;
    int isInteger = 1;
    char* end;
    const char* start = parser->ptr;

    /* Skip over any characters that can comprise a number */
    while (parser->ptr != parser->end && _is_number_char(*parser->ptr))
    {
        c = *parser->ptr;
        parser->ptr++;

        if (_is_decimal_or_exponent(c))
            isInteger = 0;
    }

    if (isInteger)
    {
        *type = JSON_TYPE_INTEGER;
        un->integer = strtol(start, &end, 10);
    }
    else
    {
        *type = JSON_TYPE_REAL;
        un->real = strtod(start, &end);
    }

    if (!end || end != parser->ptr || start == end)
        RAISE(JSON_BAD_SYNTAX);

done:
    return result;
}

/* value = false / null / true / object / array / number / string */
static json_result_t _get_value(json_parser_t* parser)
{
    json_result_t result = JSON_OK;
    char c;
    json_parser_t* scanner = NULL;

    /* Skip whitespace */
    CHECK(skip_whitespace(parser));

    /* Skip comment lines */
    CHECK(skip_comment(parser));

    /* Fail if output exhausted */
    if (parser->ptr == parser->end)
        RAISE(JSON_EOF);

    /* Read the next character */
    c = (char)tolower(*parser->ptr++);

    switch (c)
    {
        case 'f':
        {
            json_union_t un;

            if (_expect(parser, STRLIT("alse")) != 0)
                RAISE(JSON_BAD_SYNTAX);

            un.boolean = 0;

            CHECK(_invoke_callback(
                parser, JSON_REASON_VALUE, JSON_TYPE_BOOLEAN, &un));

            break;
        }
        case 'n':
        {
            if (_expect(parser, STRLIT("ull")) != 0)
                RAISE(JSON_BAD_SYNTAX);

            CHECK(_invoke_callback(
                parser, JSON_REASON_VALUE, JSON_TYPE_NULL, NULL));

            break;
        }
        case 't':
        {
            json_union_t un;

            if (_expect(parser, STRLIT("rue")) != 0)
                RAISE(JSON_BAD_SYNTAX);

            un.boolean = 1;

            CHECK(_invoke_callback(
                parser, JSON_REASON_VALUE, JSON_TYPE_BOOLEAN, &un));

            break;
        }
        case '{':
        {
            CHECK(_get_object(parser));
            break;
        }
        case '[':
        {
            json_union_t un;

            /* Scan ahead to determine the size of the array */
            {
                size_t array_size = 0;

                if (!(scanner = _malloc(parser, sizeof(json_parser_t))))
                    RAISE(JSON_OUT_OF_MEMORY);

                memcpy(scanner, parser, sizeof(json_parser_t));
                scanner->scan = 1;

                if (_get_array(scanner, &array_size) != JSON_OK)
                    RAISE(JSON_BAD_SYNTAX);

                _free(parser, scanner);
                scanner = NULL;

                un.integer = (signed long long)array_size;

                parser->path[parser->depth - 1].size = array_size;
            }

            CHECK(_invoke_callback(
                parser, JSON_REASON_BEGIN_ARRAY, JSON_TYPE_INTEGER, &un));

            if (_get_array(parser, NULL) != JSON_OK)
                RAISE(JSON_BAD_SYNTAX);

            CHECK(_invoke_callback(
                parser, JSON_REASON_END_ARRAY, JSON_TYPE_INTEGER, &un));

            break;
        }
        case '"':
        {
            json_union_t un;

            if (_get_string(parser, (char**)&un.string) != JSON_OK)
                RAISE(JSON_BAD_SYNTAX);

            CHECK(_invoke_callback(
                parser, JSON_REASON_VALUE, JSON_TYPE_STRING, &un));
            break;
        }
        default:
        {
            json_type_t type;
            json_union_t un;

            parser->ptr--;

            if (_get_number(parser, &type, &un) != JSON_OK)
                RAISE(JSON_BAD_SYNTAX);

            CHECK(_invoke_callback(parser, JSON_REASON_VALUE, type, &un));
            break;
        }
    }

done:

    if (scanner)
        _free(parser, scanner);

    return result;
}

json_result_t json_parser_init(
    json_parser_t* parser,
    char* data,
    size_t size,
    json_parser_callback_t callback,
    void* callback_data,
    json_allocator_t* allocator,
    const json_parser_options_t* options)
{
    if (!parser || !data || !size || !callback)
        return JSON_BAD_PARAMETER;

    if (!allocator || !allocator->ja_malloc || !allocator->ja_free)
        return JSON_BAD_PARAMETER;

    memset(parser, 0, sizeof(json_parser_t));
    parser->data = data;
    parser->ptr = data;
    parser->end = data + size;
    parser->callback = callback;
    parser->callback_data = callback_data;
    parser->allocator = allocator;

    if (options)
        parser->options = *options;

    return JSON_OK;
}

json_result_t json_parser_parse(json_parser_t* parser)
{
    json_result_t result = JSON_OK;
    char c;

    /* Check parameters */
    if (!parser)
        return JSON_BAD_PARAMETER;

    /* Expect '{' */
    {
        /* Skip whitespace */
        CHECK(skip_whitespace(parser));

        /* Skip comment lines */
        CHECK(skip_comment(parser));

        /* Fail if output exhausted */
        if (parser->ptr == parser->end)
            RAISE(JSON_EOF);

        /* Read the next character */
        c = *parser->ptr++;

        /* Expect object-begin */
        if (c != '{')
            return JSON_BAD_SYNTAX;
    }

    CHECK(_get_object(parser));

done:
    return result;
}

json_result_t json_match(json_parser_t* parser, const char* pattern)
{
    json_result_t result = JSON_UNEXPECTED;
    char buf[256];
    char* ptr = NULL;
    const char* pattern_path[JSON_MAX_NESTING];
    size_t pattern_depth = 0;
    unsigned long n = 0;
    size_t pattern_len;

    if (!parser || !pattern)
        RAISE(JSON_BAD_PARAMETER);

    /* Make a copy of the pattern that can be modified */
    {
        pattern_len = strlen(pattern);

        if (pattern_len < sizeof(buf))
            ptr = buf;
        else if (!(ptr = _malloc(parser, pattern_len + 1)))
            RAISE(JSON_OUT_OF_MEMORY);

        strcpy(ptr, pattern);
    }

    /* Split the pattern into tokens */
    if ((pattern_depth = _split(ptr, '.', pattern_path, JSON_MAX_NESTING)) ==
        (size_t)-1)
    {
        RAISE(JSON_NESTING_OVERFLOW);
    }

    /* Return false if the path sizes are different */
    if (parser->depth != pattern_depth)
    {
        result = JSON_NO_MATCH;
        goto done;
    }

    /* Compare the elements */
    for (size_t i = 0; i < pattern_depth; i++)
    {
        if (strcmp(pattern_path[i], "#") == 0)
        {
            if (strtou64(&n, parser->path[i].name) != 0)
                RAISE(JSON_TYPE_MISMATCH);
        }
        else if (strcmp(pattern_path[i], parser->path[i].name) != 0)
        {
            result = JSON_NO_MATCH;
            goto done;
        }
    }

    result = JSON_OK;

done:

    if (ptr && ptr != buf)
        _free(parser, ptr);

    return result;
}

const char* json_result_string(json_result_t result)
{
    switch (result)
    {
        case JSON_OK:
            return "JSON_OK";
        case JSON_FAILED:
            return "JSON_FAILED";
        case JSON_UNEXPECTED:
            return "JSON_UNEXPECTED";
        case JSON_BAD_PARAMETER:
            return "JSON_BAD_PARAMETER";
        case JSON_OUT_OF_MEMORY:
            return "JSON_OUT_OF_MEMORY";
        case JSON_EOF:
            return "JSON_EOF";
        case JSON_UNSUPPORTED:
            return "JSON_UNSUPPORTED";
        case JSON_BAD_SYNTAX:
            return "JSON_BAD_SYNTAX";
        case JSON_TYPE_MISMATCH:
            return "JSON_TYPE_MISMATCH";
        case JSON_NESTING_OVERFLOW:
            return "JSON_NESTING_OVERFLOW";
        case JSON_NESTING_UNDERFLOW:
            return "JSON_NESTING_UNDERFLOW";
        case JSON_BUFFER_OVERFLOW:
            return "JSON_BUFFER_OVERFLOW";
        case JSON_UNKNOWN_VALUE:
            return "JSON_UNKNOWN_VALUE";
        case JSON_OUT_OF_BOUNDS:
            return "JSON_OUT_OF_BOUNDS";
        case JSON_NO_MATCH:
            return "JSON_NO_MATCH";
    }

    /* Unreachable */
    return "UNKNOWN";
}
