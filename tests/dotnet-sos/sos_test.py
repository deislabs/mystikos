# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

import lldb
import os
import sys

def run_test(debugger):
    debugger.SetAsync(False)
    res = lldb.SBCommandReturnObject()
    ci = debugger.GetCommandInterpreter()

    # Set managed breakpoint
    ci.HandleCommand("bpmd hello.dll hello.Program.Main", res)
    assert(res.Succeeded())

    # The `personality` syscall is used by lldb to turn off ASLR.
    # This syscall may not be permitted within containers.
    # Therefore, turn off disable-aslr.
    lldb.debugger.HandleCommand("settings set target.disable-aslr false")
    debugger.HandleCommand("run")

    process = debugger.GetSelectedTarget().GetProcess()

    # For sgx, we hit the cpuid SIGILL pretty early in dotnet initialization
    if os.getenv("TARGET") == "sgx":
        assert(process.GetState() == lldb.eStateStopped)
        assert(process.GetSelectedThread().GetStopReason() == lldb.eStopReasonSignal)
        debugger.HandleCommand("pro hand -p true -s false -n false SIGILL")
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
