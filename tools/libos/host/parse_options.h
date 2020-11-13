// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

struct _option
{
    const char** option_names;
    int option_names_count;
    int num_extra_parameters;
    const char** extra_parameter;
    int extra_parameter_required;
};

struct _options
{
    struct _option* options;
    int num_options;
};

int parse_options(
    int argc,
    const char* argv[],
    int starting_index,
    struct _options* options);
