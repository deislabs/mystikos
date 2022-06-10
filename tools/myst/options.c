// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <string.h>

#include <myst/eraise.h>
#include <myst/options.h>

#include "config.h"
#include "shared.h"

static bool _is_allowed_env_variable(
    const config_parsed_data_t* config,
    const char* env)
{
    for (size_t i = 0; i < config->host_environment_variables_count; i++)
    {
        const char* allowed = config->host_environment_variables[i];
        size_t len = strlen(allowed);

        if (strncmp(env, allowed, len) == 0 && env[len] == '=')
            return true;
    }

    return false;
}

long determine_final_options(
    struct myst_options* cmdline_opts,
    struct myst_final_options* final_opts,
    const myst_args_t* args,
    const myst_args_t* env,
    config_parsed_data_t* parsed_config,
    bool have_config,
    bool tee_debug_mode,
    const char* target_env_var,
    myst_args_t* mount_mappings)
{
    long ret = -1;

    /* make sure rootfs is null terminated. */
    if (strnlen(cmdline_opts->rootfs, PATH_MAX) == PATH_MAX)
    {
        fprintf(
            stderr,
            "rootfs path too long or not null terminated (> %u)\n",
            PATH_MAX);
        goto done;
    }
    memcpy(
        final_opts->base.rootfs,
        cmdline_opts->rootfs,
        sizeof(final_opts->base.rootfs));

    final_opts->base.host_enc_uid_gid_mappings =
        cmdline_opts->host_enc_uid_gid_mappings;
    final_opts->base.have_fsgsbase_instructions =
        cmdline_opts->have_fsgsbase_instructions;

    // Config always wins, even if it is the default value from config
    if (have_config)
    {
        final_opts->cwd = parsed_config->cwd;
        final_opts->hostname = parsed_config->hostname;
        final_opts->base.max_affinity_cpus = parsed_config->max_affinity_cpus;
        final_opts->base.main_stack_size = parsed_config->main_stack_size;
        final_opts->base.thread_stack_size = parsed_config->thread_stack_size;
        final_opts->base.fork_mode = parsed_config->fork_mode;
        final_opts->base.nobrk = parsed_config->no_brk;
        final_opts->base.exec_stack = parsed_config->exec_stack;
        final_opts->base.unhandled_syscall_enosys =
            parsed_config->unhandled_syscall_enosys;
        final_opts->base.host_uds = parsed_config->host_uds;

        // Some options should not be enabled unless running in debug mode
        if (tee_debug_mode)
        {
            final_opts->base.strace_config = cmdline_opts->strace_config;
            final_opts->base.trace_errors = cmdline_opts->trace_errors;
            final_opts->base.trace_times = cmdline_opts->trace_times;
            final_opts->base.shell_mode = cmdline_opts->shell_mode;
            final_opts->base.debug_symbols = cmdline_opts->debug_symbols;
            final_opts->base.memcheck = cmdline_opts->memcheck;
            final_opts->base.perf = cmdline_opts->perf;
            final_opts->base.report_native_tids =
                cmdline_opts->report_native_tids;
        }
        else
        {
            memset(
                &final_opts->base.strace_config,
                0,
                sizeof(final_opts->base.strace_config));
            final_opts->base.trace_errors = false;
            final_opts->base.trace_times = false;
            final_opts->base.shell_mode = false;
            final_opts->base.debug_symbols = false;
            final_opts->base.memcheck = false;
            final_opts->base.perf = false;
            final_opts->base.report_native_tids = false;
        }
    }
    else
    {
        // No config is only possible when we are in debug mode for SGX or linux
        // target
        final_opts->base = *cmdline_opts;
    }

    if (final_opts->cwd == NULL)
        final_opts->cwd = "/";

    // Process command line
    if (myst_args_init(&final_opts->args) != 0)
        ERAISE(-EINVAL);

    if (have_config && !parsed_config->allow_host_parameters)
    {
        if (myst_args_append1(
                &final_opts->args, parsed_config->application_path) != 0)
            ERAISE(-EINVAL);

        if (myst_args_append(
                &final_opts->args,
                (const char**)parsed_config->application_parameters,
                parsed_config->application_parameters_count) != 0)
            ERAISE(-EINVAL);
    }
    else
    {
        if (myst_args_append(&final_opts->args, args->data, args->size) != 0)
            ERAISE(-EINVAL);
    }

    // process environment
    if (myst_args_init(&final_opts->env) != 0)
        ERAISE(-EINVAL);
    if (have_config)
    {
        // append all enclave-side environment variables first
        if (myst_args_append(
                &final_opts->env,
                (const char**)parsed_config->enclave_environment_variables,
                parsed_config->enclave_environment_variables_count) != 0)
            ERAISE(-EINVAL);

        // now include host-side environment variables that are allowed
        if (parsed_config->host_environment_variables &&
            parsed_config->host_environment_variables_count)
        {
            for (size_t i = 0; i < env->size; i++)
            {
                if (_is_allowed_env_variable(parsed_config, env->data[i]))
                {
                    if (myst_args_append1(&final_opts->env, env->data[i]) != 0)
                    {
                        ERAISE(-EINVAL);
                    }
                }
            }
        }
    }

    /* Inject the MYST_TARGET environment variable */
    {
        const char val[] = "MYST_TARGET=";

        for (size_t i = 0; i < final_opts->env.size; i++)
        {
            if (strncmp(final_opts->env.data[i], val, sizeof(val) - 1) == 0)
            {
                fprintf(stderr, "environment already contains %s", val);
                ERAISE(-EINVAL);
            }
        }

        myst_args_append1(&final_opts->env, target_env_var);
    }

    /* Add mount source paths to config read mount points */
    if (!myst_merge_mount_mapping_and_config(
            &parsed_config->mounts, mount_mappings) ||
        !myst_validate_mount_config(&parsed_config->mounts))
        ERAISE(-EINVAL);

    ret = 0;

done:
    return ret;
}
