// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <myst/args.h>
#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/fsgs.h>
#include <myst/json.h>
#include <myst/kernel.h>
#include <myst/printf.h>

#define APPENV_FILENAME "appenv.json"

typedef struct json_callback_data
{
    myst_args_t env;
} json_callback_data_t;

static int _concat_env_variables(
    const char* value,
    myst_args_t* new_envp,
    int pos)
{
    char* tuple;
    const char* curr = new_envp->data[pos];

    if (!curr)
        return -EINVAL;

    /* Append the appenv value of the var to the value already present in envp
     */
    asprintf(&tuple, "%s:%s", new_envp->data[pos], value);

    new_envp->data[pos] = tuple;

    free((char*)curr);
    return 0;
}

static void _trace(
    json_parser_t* parser,
    const char* file,
    unsigned int line,
    const char* func,
    const char* message)
{
    (void)parser;
    printf("%s(%u): %s(): %s\n", file, line, func, message);
}

static json_result_t _json_read_callback(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un,
    void* callback_data)
{
    json_result_t result = JSON_UNEXPECTED;
    json_callback_data_t* cbdata = (json_callback_data_t*)callback_data;

    switch (reason)
    {
        case JSON_REASON_NONE:
        {
            result = JSON_UNEXPECTED;
            goto done;
        }
        case JSON_REASON_NAME:
        {
            break;
        }
        case JSON_REASON_BEGIN_OBJECT:
        {
            break;
        }
        case JSON_REASON_END_OBJECT:
        {
            break;
        }
        case JSON_REASON_BEGIN_ARRAY:
        {
            break;
        }
        case JSON_REASON_END_ARRAY:
        {
            break;
        }
        case JSON_REASON_VALUE:
        {
            if (json_match(parser, "Env") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                {
                    if (myst_args_append1(&cbdata->env, un->string) != 0)
                    {
                        result = JSON_OUT_OF_MEMORY;
                        goto done;
                    }
                }
                else
                {
                    result = JSON_BAD_SYNTAX;
                    goto done;
                }
            }
            else
            {
                result = JSON_OK;
                goto done;
            }

            break;
        }
    }

    result = JSON_OK;

done:
    return result;
}

int myst_create_appenv(myst_kernel_args_t* args)
{
    int ret = 0;
    size_t size;
    char* data = NULL;
    char* path = APPENV_FILENAME;
    json_parser_t* parser = NULL;

    /* open the APPENV_FILENAME */
    ECHECK(myst_load_file(path, (void**)&data, &size));

    /* read all the env vars and values */
    parser = calloc(1, sizeof(json_parser_t));
    if (parser == NULL)
    {
        return -ENOMEM;
    }

    json_result_t r;
    json_callback_data_t callback_data;
    static json_allocator_t allocator = {
        malloc,
        free,
    };

    memset(&callback_data, 0, sizeof(json_callback_data_t));
    myst_args_init(&callback_data.env);

    const json_parser_options_t options = {1};

    if ((r = json_parser_init(
             parser,
             data,
             size,
             _json_read_callback,
             &callback_data,
             &allocator,
             &options)) != JSON_OK)
    {
        myst_eprintf("json_parser_init() failed: %d\n", r);
        ERAISE(-EINVAL);
    }

    parser->trace = _trace;

    if ((r = json_parser_parse(parser)) != JSON_OK)
    {
        myst_eprintf("json_parser_parse() failed: %d\n", r);
        ERAISE(-EINVAL);
    }

    if (parser->depth != 0)
    {
        myst_eprintf("unterminated objects\n");
        ERAISE(-EINVAL);
    }

    if (callback_data.env.size == 0)
    {
        ERAISE(-EINVAL);
    }

    myst_args_t new_envp;
    size_t new_envc = args->envc;

    if (myst_args_init(&new_envp) != 0)
        ERAISE(-ENOMEM);

    /* store a copy of all the current env vars in new_env */
    for (size_t i = 0; i < args->envc; i++)
    {
        char* nv = NULL;
        if (asprintf(&nv, "%s", args->envp[i]) == -1)
            ERAISE(-ENOMEM);

        if (myst_args_append1(&new_envp, nv) != 0)
            ERAISE(-EINVAL);
    }

    /* store the appenv variables in the env vector according to rules */
    for (size_t i = 0; i < callback_data.env.size; i++)
    {
        char* nv = NULL;
        if (asprintf(&nv, "%s", callback_data.env.data[i]) == -1)
            ERAISE(-ENOMEM);

        const char* value = strchr(nv, '=');
        if (!value)
        {
            myst_eprintf("Environment variable does not have '='\n");
            ERAISE(-EINVAL);
        }

        size_t name_len = value - nv;
        value++;

        /* if environment variable is not already defined, add it to envp */
        int pos;
        if ((pos = myst_args_find(&new_envp, nv, name_len)) <= 0)
        {
            if (myst_args_append1(&new_envp, nv) != 0)
                ERAISE(-EINVAL);
            new_envc++;
        }
        else
        {
            const char* pattern[2] = {"PATH=", "LD_LIBRARY_PATH"};

            /* if the environment variable is already defined, skip or concat to
             * its current value if it is PATH or LD_LIBRARY_PATH */
            if (strncmp(new_envp.data[pos], pattern[0], strlen(pattern[0])) ==
                0)
            {
                _concat_env_variables(value, &new_envp, pos);
            }
            else if (
                strncmp(new_envp.data[pos], pattern[1], strlen(pattern[1])) ==
                0)
            {
                _concat_env_variables(value, &new_envp, pos);
            }
            if (nv)
                free(nv);
        }
    }

    myst_args_release(&callback_data.env);

    args->envc = new_envc;
    args->envp = new_envp.data;

done:

    if (parser)
        free(parser);

    if (data)
        free(data);

    return ret;
}

int myst_appenv_free(myst_kernel_args_t* args)
{
    for (size_t i = 0; i < args->envc; i++)
    {
        if (args->envp[i])
            free((char*)args->envp[i]);
    }
    free(args->envp);
    return 0;
}