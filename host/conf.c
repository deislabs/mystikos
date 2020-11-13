// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ctype.h>
#include <libos/conf.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void _set_err(libos_conf_err_t* err, const char* format, ...)
{
    if (err)
    {
        va_list ap;
        va_start(ap, format);
        vsnprintf(err->buf, sizeof(err->buf), format, ap);
        va_end(ap);
    }
}

static void _clear_err(libos_conf_err_t* err)
{
    if (err)
        memset(err, 0, sizeof(libos_conf_err_t));
}

static const char* _get_line(const char** pp, const char* end)
{
    const char* p = *pp;
    const char* start = p;

    if (p == end)
        return NULL;

    while (p != end && *p++ != '\n')
        ;

    *pp = p;

    return start;
}

static const char* _skip_identifier(const char* p, const char* end)
{
    if (p == end)
        return p;

    if (!isalpha(*p) || *p == '_')
        return p;

    p++;

    while (p != end && isalnum(*p))
        p++;

    return p;
}

static const char* _skip_whitespace(const char* p, const char* end)
{
    while (p != end && isspace(*p))
        p++;

    return p;
}

int libos_conf_parse(
    const char* text,
    size_t text_size,
    libos_conf_callback_t callback,
    void* callback_data,
    size_t* error_line,
    libos_conf_err_t* err)
{
    int status = 0;
    const char* line;
    const char* textEnd;
    size_t line_num = 0;
    char* name_ptr = NULL;
    char* value_ptr = NULL;

    if (error_line)
        *error_line = 0;

    /* Check parameters */
    if (!text || !text_size || !error_line || !err)
    {
        _set_err(err, "invalid parameter");
        status = -1;
        goto done;
    }

    /* Clear error state */
    *error_line = 0;
    _clear_err(err);

    /* Set pointer to the end of the text */
    textEnd = text + text_size;

    /* Process lines of the format NAME=SHA1:SHA256 */
    while ((line = _get_line(&text, textEnd)))
    {
        const char* p = line;
        const char* end = text;
        const char* name = NULL;
        size_t nameLen = 0;
        const char* value = NULL;
        size_t valueLen = 0;

        /* Increment the line number */
        line_num++;

        /* Strip horizontal whitespace */
        p = _skip_whitespace(p, end);

        /* Skip blank lines and comment lines */
        if (p == end || *p == '#')
            continue;

        /* Remove trailing whitespace */
        while (end != p && isspace(end[-1]))
            end--;

        /* Recognize the name: [A-Za-z_][A-Za-z_0-9] */
        {
            const char* start = p;

            p = _skip_identifier(p, end);

            if (p == start)
            {
                _set_err(err, "expected name");
                status = -1;
                goto done;
            }

            /* Save the name */
            name = start;
            nameLen = p - start;
        }

        /* Expect a '=' */
        {
            p = _skip_whitespace(p, end);

            if (p == end || *p++ != '=')
            {
                _set_err(err, "syntax error: expected '='");
                status = -1;
                goto done;
            }

            p = _skip_whitespace(p, end);
        }

        /* Get the value */
        {
            value = p;
            valueLen = end - p;
        }

        /* Invoke the callback */
        if (callback)
        {
            if (!(name_ptr = strndup(name, nameLen)))
            {
                _set_err(err, "out of memory");
                status = -1;
                goto done;
            }

            if (!(value_ptr = strndup(value, valueLen)))
            {
                _set_err(err, "out of memory");
                status = -1;
                goto done;
            }

            if ((*callback)(name_ptr, value_ptr, callback_data, err) != 0)
            {
                status = -1;
                goto done;
            }

            free(name_ptr);
            name_ptr = NULL;
            free(value_ptr);
            value_ptr = NULL;
        }
    }

done:

    if (status != 0)
        *error_line = line_num;

    if (name_ptr)
        free(name_ptr);

    if (value_ptr)
        free(value_ptr);

    return status;
}
