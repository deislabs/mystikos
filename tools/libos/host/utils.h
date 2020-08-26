// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// print error and exit process with 1
void _err(const char* fmt, ...);

// sets the program file name of the process
const char *set_program_file(const char *program);

// gets the previously set program file
const char *get_program_file();
