#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <myst/buf.h>
#include <myst/file.h>
#include <myst/json.h>
#include <myst/paths.h>
#include <myst/which.h>
#include <sys/stat.h>

static const char* arg0;

__attribute__((format(printf, 1, 2))) void _err(const char* fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: error: ", arg0);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");

    exit(1);
}

static int _exec(myst_buf_t* out, const char* fmt, ...)
{
    int ret = 0;
    FILE* is = NULL;
    char* cmd = NULL;
    int c;

    myst_buf_clear(out);

    /* format the command */
    {
        va_list ap;
        va_start(ap, fmt);

        if (vasprintf(&cmd, fmt, ap) < 0)
            ret = -ENOMEM;

        va_end(ap);
    }

#if 0
    printf("cmd: %s\n", cmd);
#endif

    /* execute the command */
    if (!(is = popen(cmd, "r")))
    {
        ret = -errno;
        goto done;
    }

    /* read standard output into the output buffer */
    while ((c = fgetc(is)) != EOF)
    {
        myst_buf_append(out, &c, 1);
    }

done:

    if (cmd)
        free(cmd);

    if (is)
        pclose(is);

    return ret;
}

typedef struct
{
    char* lowerdir;
    char* upperdir;
    char* workdir;
} parse_results_t;

static json_result_t _json_read_callback(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un,
    void* callback)
{
    json_result_t result = JSON_UNEXPECTED;
    parse_results_t* data = (parse_results_t*)callback;

    switch (reason)
    {
        case JSON_REASON_NONE:
        {
            /* Unreachable */
            assert(false);
            break;
        }
        case JSON_REASON_NAME:
        case JSON_REASON_BEGIN_OBJECT:
        case JSON_REASON_END_OBJECT:
        case JSON_REASON_BEGIN_ARRAY:
        case JSON_REASON_END_ARRAY:
        {
            /* ignore these */
            break;
        }
        case JSON_REASON_VALUE:
        {
            if (json_match(parser, "GraphDriver.Data.LowerDir") == JSON_OK)
            {
                if (type != JSON_TYPE_STRING)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                if (!(data->lowerdir = strdup(un->string)))
                    _err("out of memory");
            }
            else if (json_match(parser, "GraphDriver.Data.UpperDir") == JSON_OK)
            {
                if (type != JSON_TYPE_STRING)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                if (!(data->upperdir = strdup(un->string)))
                    _err("out of memory");
            }
            else if (json_match(parser, "GraphDriver.Data.WorkDir") == JSON_OK)
            {
                if (type != JSON_TYPE_STRING)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                if (!(data->workdir = strdup(un->string)))
                    _err("out of memory");
            }
            else
            {
                /* ignore unknown tags */
            }

            break;
        }
    }

    result = JSON_OK;

done:
    return result;
}

static void _parse(char* data, size_t size, parse_results_t* results)
{
    json_parser_t parser;
    json_result_t r;
    static json_allocator_t allocator = {
        malloc,
        free,
    };

    const json_parser_options_t options = {1};

    if ((r = json_parser_init(
             &parser,
             data,
             size,
             _json_read_callback,
             results,
             &allocator,
             &options)) != JSON_OK)
    {
        _err("json_parser_init() failed");
    }

    if ((r = json_parser_parse(&parser)) != JSON_OK)
        _err("json_parser_parse() failed");

    if (parser.depth != 0)
        _err("json parsing failed");

    if (!results->upperdir)
        _err("UpperDir JSON element not found");

    if (!results->workdir)
        _err("WorkDir JSON element not found");
}

static void _find_emptydir(const char* arg0, char emptydir[PATH_MAX])
{
    char fullpath[PATH_MAX];
    char path[PATH_MAX];
    char dirname[PATH_MAX];
    char basename[PATH_MAX];
    struct stat statbuf;

    /* resolve the location of this program */
    if (myst_which(arg0, fullpath) != 0)
        _err("failed to resolve full path of %s", arg0);

    if (myst_split_path(fullpath, dirname, PATH_MAX, basename, PATH_MAX) != 0)
    {
        _err("failed to split path: %s", fullpath);
    }

    int n = snprintf(path, PATH_MAX, "%s/../var/empty", dirname);

    if (n >= PATH_MAX)
        _err("path overflow");

    if (!realpath(path, emptydir))
        _err("realpath failed");

    if (stat(emptydir, &statbuf) != 0 && !S_ISDIR(statbuf.st_mode))
        _err("cannot find the empty directory: %s", emptydir);
}

int main(int argc, const char* argv[])
{
    arg0 = argv[0];
    void* data = NULL;
    size_t size = 0;

    /* check the command line arguments */
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <docker-image> <mount-dir>\n\n", argv[0]);
        exit(1);
    }

    const char* docker_image = argv[1];
    const char* mount_dir = argv[2];

    /* if docker image argument is a file, read image id from that file */
    assert(myst_validate_file_path(docker_image));
    if (myst_load_file(docker_image, &data, &size) == 0)
        docker_image = data;

    /* verify that the mount directory exists */
    {
        struct stat statbuf;

        if (stat(mount_dir, &statbuf) != 0 || !S_ISDIR(statbuf.st_mode))
            _err("no such directory: %s\n", mount_dir);
    }

    /* execute the "docker image inspect..." command */
    myst_buf_t buf = MYST_BUF_INITIALIZER;
    {
        int r = _exec(&buf, "docker image inspect %s", docker_image);

        if (r < 0)
        {
            fprintf(stderr, "docker image inspect failed: %s\n", strerror(-r));
            exit(1);
        }

        myst_buf_append(&buf, "", 1);
    }

    /* remove the "[...]" wrapper, leaving brace enclosed JSON  */
    char* start;
    char* end;
    {
        start = (char*)buf.data;
        end = (char*)(buf.data + buf.size - 1);

        while (isspace(*start))
            start++;

        if (*start != '[')
            _err("malformed JSON input: expected opening square bracket");

        start++;

        while (isspace(*start))
            start++;

        if (*start != '{')
            _err("malformed JSON input: expected opening brace");

        while (end != start && isspace(end[-1]))
            *--end = '\0';

        end--;

        if (*end != ']')
            _err("malformed JSON input: expected closing square bracket");

        *end-- = '\0';

        while (end != start && isspace(end[-1]))
            *--end = '\0';

        end--;

        if (*end != '}')
            _err("malformed JSON input: expected closing brace");
    }

    /* parse the json file */
    parse_results_t r;
    memset(&r, 0, sizeof(r));
    _parse(start, end - start + 1, &r);

    if (r.lowerdir)
    {
        char* layers;
        size_t malloc_size = strlen(r.upperdir) + strlen(r.lowerdir) + 1;

        if (!(layers = malloc(malloc_size)))
            _err("out of memory");

        strcat(layers, r.upperdir);
        strcat(layers, ":");
        strcpy(layers, r.lowerdir);

        /* print the mount command to standard output */
        printf(
            "mount -t overlay overlay -o lowerdir=%s %s\n", layers, mount_dir);

        free(layers);
    }
    else
    {
        char emptydir[PATH_MAX];
        _find_emptydir(argv[0], emptydir);

        /* print the mount command to standard output */
        printf(
            "mount -t overlay overlay -o lowerdir=%s:%s %s\n",
            r.upperdir,
            emptydir,
            mount_dir);
    }

    free(data);
    free(r.lowerdir);
    free(r.upperdir);
    free(r.workdir);

    return 0;
}
