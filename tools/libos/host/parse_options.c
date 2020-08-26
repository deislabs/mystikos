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
    // First parse the options and set the extra_parameter variables
    for (int argv_iteration = starting_index; argv_iteration < argc; argv_iteration++)
    {
        int found_current_argv = 0;
        fprintf(stdout, "validating argv[%d]=%s\n", argv_iteration, argv[argv_iteration]);
        for (int option_iter = 0; option_iter < options->num_options && !found_current_argv; option_iter++)
        {
            for (int option_name_iter = 0; option_name_iter < options->options[option_iter].option_names_count; option_name_iter++)
            {
                fprintf(stdout, "checking against %s\n", options->options[option_iter].option_names[option_name_iter]);
                if (strcmp(argv[argv_iteration],options->options[option_iter].option_names[option_name_iter]) == 0)
                {
                    fprintf(stdout, "found argv option %s\n", argv[argv_iteration]);
                    if (options->options[option_iter].num_extra_parameters > 0)
                    {
                        if ((argv_iteration+1) >= argc)
                        {
                            _err("option \"%s\" must have an extra parameter", argv[argv_iteration]);
                        }
                        assert(options->options[option_iter].extra_parameter);
                        *options->options[option_iter].extra_parameter = argv[argv_iteration+1];
                        fprintf(stdout, "Processed option \"%s\"=\"%s\" successfully\n", argv[argv_iteration], argv[argv_iteration+1]);
                        argv_iteration ++;  //skip the extra parameter in the argv list
                    }
                    else
                    {
                        assert(options->options[option_iter].extra_parameter);
                        *options->options[option_iter].extra_parameter = "";
                        fprintf(stdout, "Processed option \"%s\" successfully\n", argv[argv_iteration]);
                    }
                    found_current_argv = 1;
                    break;
                }
            }
        }
        if (!found_current_argv)
        {
            _err("invalid option \"%s\"", argv[argv_iteration]);
        }
    }

    // Now lets validate we got everything we were looking for
    for (int option_iter = 0; option_iter < options->num_options; option_iter++)
    {
        for (int option_name_iter = 0; option_name_iter < options->options[option_iter].option_names_count; option_name_iter++)
        {
            if (options->options[option_iter].num_extra_parameters && options->options[option_iter].extra_parameter_required && (*options->options[option_iter].extra_parameter == NULL))
            {
                _err("option %s is required but not specified", options->options[option_iter].option_names[0]);
            }
        }
    }
    fprintf(stdout, "All required options are present\n");
    return 0;
}
