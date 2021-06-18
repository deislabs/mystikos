import io, os, re, sys
import lldb

def lldb_handle_command(debugger, cmd):
    output = ""
    old = debugger.GetOutputFile()
    try:
        # TODO: Create unique tmp file path per oelldb instance
        fpath = "/tmp/oelldb.txt"
        f = open(fpath, "w")
        debugger.SetOutputFile(f)
        debugger.SetAsync(False)
        debugger.HandleCommand(cmd)
        f.flush()
        f.close()
        debugger.SetOutputFile(old)
        output = open(fpath, "r").read()
    except:
        pass
    debugger.SetOutputFile(old)
    return output

def lookup_file_in_source_dirs(source_file):
    source_dirs = os.getenv("DOTNET_SOURCE_DIRS")
    for s_dir in source_dirs.split(":"):
        if source_file in os.listdir(s_dir):
            return s_dir+"/"+source_file
    return None

def _print_source(debugger):
    output = lldb_handle_command(debugger, "re r rip -f x")
    m = re.search("\\s*rip\\s*=\\s*([0-9a-fA-Fx]+)\.*", output)
    if m:
        rip = m[1]
        #print("oelldb -> rip = %s" % rip)
        output = lldb_handle_command(debugger, "ip2md %s" % rip)
        #print("oelldb -> output = %s" % output)
        # TODO: check if this if IP lies in a JITTED frame
        #print(f"ip2md output: {output}", file=sys.stderr)
    else:
        return True

    # TODO: SOS reads source file info from PDB files,
    # You can make SOS aware of the pdb file by: setsymbolserver -directory <path-to-dir-containing-pdb>
    # The source file path is the one recorded at the build time of the pdb file.
    # If its a multi-stage docker build, the file directory structure will not be available.
    # One solution is to read dotnet source directories from an environment variable,
    # and search for the basename part of the file path in those specified directories.
    m = re.search("Source file:\\s*(.+)\\s+@\\s+(\d+)", output)
    if m:
        filename_at_build = m[1]
        basename = filename_at_build.split("/")[-1]
        line = int(m[2])
        filename = lookup_file_in_source_dirs(basename)
        if filename:
            code = open(filename, "r").read().split('\n')
            K=10
            for i in range(line-K, line+K):
                cursor = "->" if i == line else "  "
                if i >= 0 and i < len(code):
                    print("%3d %s %s" % (i, cursor, code[i]))
        else:
            print(f"Source file for ${basename} not found in paths specified by  DOTNET_SOURCE_DIRS env variable!")

    return True

def dotnet_source_printer_hook(debugger, command, result, internal_dict):
    output = ""
    stop_reason = (debugger.GetSelectedTarget()
                        .GetProcess()
                        .GetSelectedThread()
                        .GetStopReason())
    if stop_reason != lldb.eStopReasonBreakpoint:
        return True
    return _print_source(debugger)

def print_dotnet_source(debugger, command, result, internal_dict):
    return _print_source(debugger)

def __lldb_init_module(debugger, dict):
    debugger.HandleCommand('command script add -f code_view.dotnet_source_printer_hook dotnet_source_printer_hook')
    debugger.HandleCommand('target stop-hook add -o "dotnet_source_printer_hook"')
    debugger.HandleCommand('command script add -f code_view.print_dotnet_source print_dotnet_source')
