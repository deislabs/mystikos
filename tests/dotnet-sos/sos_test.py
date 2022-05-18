# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

import lldb
import os
import re
import subprocess
import sys

def copy_libmscordaccore(ci, res):
    ci.HandleCommand("finish", res)
    assert(res.Succeeded())

    ci.HandleCommand("p tmpdir", res)
    assert(res.Succeeded())
    tmpdir_match = re.search('"(.*)"', res.GetOutput())    
    assert(tmpdir_match)
    tmpdir_path = tmpdir_match.group(0)[1:-1]

    bashCommand = f"cp libmscordaccore.so {tmpdir_path}"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    assert(not error)

def run_test(debugger):
    debugger.SetAsync(False)
    res = lldb.SBCommandReturnObject()
    ci = debugger.GetCommandInterpreter()

    # The `personality` syscall is used by lldb to turn off ASLR.
    # This syscall may not be permitted within containers.
    # Therefore, turn off disable-aslr.
    lldb.debugger.HandleCommand("settings set target.disable-aslr false")

    # Set breakpoint to get /tmp path with symbol files 
    ci.HandleCommand("b init_symbol_file_tmpdir", res)
    assert(res.Succeeded())
    print(res)

    debugger.HandleCommand("run")

    process = debugger.GetSelectedTarget().GetProcess()

    # For sgx, we hit the cpuid SIGILL pretty early in OE crypto initialization
    # Note that the SIGILL will be suppressed when vDSO is used (Linux Kernel 5.11+)
    if os.getenv("TARGET") == "sgx":
        assert(process.GetState() == lldb.eStateStopped)
        # Continue the execution if SIGILL is not suppressed
        if process.GetSelectedThread().GetStopReason() == lldb.eStopReasonSignal:
            debugger.HandleCommand("pro hand -p true -s false -n false SIGILL")
            process.Continue()

    # Should've hit /tmp path init breakpoint
    assert(process.GetState() == lldb.eStateStopped)
    assert(process.GetSelectedThread().GetStopReason() == lldb.eStopReasonBreakpoint)
    copy_libmscordaccore(ci, res)

    # Set managed breakpoint
    ci.HandleCommand("bpmd hello.dll hello.Program.Main", res)
    assert(res.Succeeded())

    process.Continue()

    # Should've hit managed breakpoint
    assert(process.GetState() == lldb.eStateStopped)
    assert(process.GetSelectedThread().GetStopReason() == lldb.eStopReasonBreakpoint)

    # Run clrstack at breakpoint hit
    ci.HandleCommand("clrstack", res)
    assert(res.Succeeded())

    process.Continue()

    # Should've hit Debugger.Break SIGTRAP
    assert(process.GetState() == lldb.eStateStopped)
    assert(process.GetSelectedThread().GetStopReason() == lldb.eStopReasonSignal)

    # Run clrstack at Debugger.Break() hit
    ci.HandleCommand("clrstack", res)
    assert(res.Succeeded())

    # Print thread info
    ci.HandleCommand("clrthreads", res)
    assert(res.Succeeded())

    process.Continue()

def __lldb_init_module(debugger, dict):
    run_test(debugger)
