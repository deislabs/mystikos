import io, re, sys
import lldb
from contextlib import redirect_stdout

def my_stop_hook(debugger, command, result, internal_dict):
    output = ""
    with io.StringIO() as buf, redirect_stdout(buf):
        old = debugger.GetOutputFile()
        debugger.SetOutputFile(buf)
        debugger.SetAsync(False)
        stop_reason = (debugger.GetSelectedTarget()
                        .GetProcess()
                        .GetSelectedThread()
                        .GetStopReason())
        if stop_reason == lldb.eStopReasonBreakpoint:
            debugger.HandleCommand("re r rip -f x")
            output = buf.getvalue()
            buf.truncate(0)
            m = re.search("rip\\s*=\\s*([0-9a-fA-Fx]+)\.*", output)
            if m:
                rip = m[1]
                debugger.HandleCommand(f"ip2md {rip}")
                output = buf.getvalue()
                buf.truncate(0)
                # TODO: check if this if IP lies in a JITTED frame
                #print(f"ip2md output: {output}", file=sys.stderr)
            else:
                return True  
            debugger.SetOutputFile(old)
        else:
            return True
    print(output)
    # TODO: SOS reads source file info from PDB files,
    # You can make SOS aware of the pdb file by: setsymbolserver -directory <path-to-dir-containing-pdb> 
    # The source file path is the one recorded at the build time of the pdb file.
    # If its a multi-stage docker build, the file directory structure will not be available.
    # One solution is to read dotnet source directories from an environment variable,
    # and search for the basename part of the file path in those specified directories.
    m = re.search("Source file:\\s*(.+)\\s+@\\s+(\d+)", output)
    if m:
        filename = m[1]
        line = int(m[2])
        code = open(filename, "r").read().split('\n')
        K=10
        for i in range(line-K, line+K):
            cursor = "->" if i == line else "  "
            if i >= 0 and i < len(code):
                print("%3d %s %s" % (i, cursor, code[i]))

    return True
    
def __lldb_init_module(debugger, dict):
    debugger.HandleCommand('command script add -f code_view.my_stop_hook my_stop_hook')
    debugger.HandleCommand('target stop-hook add -o "my_stop_hook"')

