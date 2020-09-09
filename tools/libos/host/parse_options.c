// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "parse_options.h"
#include "utils.h"

int parse_options(
    int argc, 
    const char* argv[], 
    int starting_index,
    struct _options *options)
{
    int ret = -1;

    // First parse the options and set the extra_parameter variables
    for (int argv_iteration = starting_index; argv_iteration < argc; argv_iteration++)
    {
        int found_current_argv = 0;
        for (int option_iter = 0; option_iter < options->num_options && !found_current_argv; option_iter++)
        {
            for (int option_name_iter = 0; option_name_iter < options->options[option_iter].option_names_count; option_name_iter++)
            {
                if (strcmp(argv[argv_iteration],options->options[option_iter].option_names[option_name_iter]) == 0)
                {
                    if (options->options[option_iter].num_extra_parameters > 0)
                    {
                        if ((argv_iteration+1) >= argc)
                        {
                            fprintf(stderr, "option \"%s\" must have an extra parameter", argv[argv_iteration]);
                            goto done;
                        }
                        assert(options->options[option_iter].extra_parameter);
                        *options->options[option_iter].extra_parameter = argv[argv_iteration+1];
                        argv_iteration ++;  //skip the extra parameter in the argv list
                    }
                    else
                    {
                        assert(options->options[option_iter].extra_parameter);
                        *options->options[option_iter].extra_parameter = "";
                    }
                    found_current_argv = 1;
                    break;
                }
            }
        }
        if (!found_current_argv)
        {
            fprintf(stderr, "invalid option \"%s\"", argv[argv_iteration]);
            goto done;
        }
    }

    // Now lets validate we got everything we were looking for
    for (int option_iter = 0; option_iter < options->num_options; option_iter++)
    {
        for (int option_name_iter = 0; option_name_iter < options->options[option_iter].option_names_count; option_name_iter++)
        {
            if (options->options[option_iter].num_extra_parameters && options->options[option_iter].extra_parameter_required && (*options->options[option_iter].extra_parameter == NULL))
            {
                fprintf(stderr, "option %s is required but not specified", options->options[option_iter].option_names[0]);
                goto done;
            }
        }
    }
    ret = 0;

done:
    return ret;
}
