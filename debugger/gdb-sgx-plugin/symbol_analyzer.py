# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import gdb
import math
import tempfile

# Figure out missing symbols within enclaves.
import shutil
import subprocess

# For parsing the oe_debug_module_t
from gdb_sgx_plugin import oe_debug_module_t
# For loading symbols
from gdb_sgx_plugin import load_enclave_symbol
# For the mutable global variable
from gdb_sgx_plugin import g_loaded_modules

g_prev_debug_modules = None

# Ensure that debugging symbols are loaded for all loaded enclave libraries.
def myst_sync_symbols():
    names = ["_debug_modules", "myst_debug_modules"]
    debug_modules = None
    for n in names:
        try:
            debug_modules = gdb.parse_and_eval(n)
            break
        except:
            pass

    # If debug modules is not found, sync cannot be done.
    if not debug_modules:
        return

    # Compare against the previous value of _debug_modules. If same, symbols are
    # up to date.
    global g_prev_debug_modules
    if g_prev_debug_modules == int(debug_modules):
        # No change observed
        return
    g_prev_debug_modules = int(debug_modules)

    # Gather the list of debug modules.
    m = debug_modules
    modules = []
    while m:
        # Ignore modules that aren't marked loaded.
        if int(m['loaded']):
            modules.append(int(m))
        m = m['next']

    # Modules are maintained in reverse order of notification.
    # Reverse the list to obtain the original order of debugger notification.
    modules.reverse()

    # Copy loaded modules.
    global g_loaded_modules
    loaded_modules = g_loaded_modules[:]
    g_loaded_modules.clear()

    # Iterate through each module in the list (modules) gathered by iterating
    # though debug_modules. Simultaneously iterate though loaded_modules list,
    # comparing each module. Stop when there is a mismatch.
    idx = 0
    for m in modules:
        if idx >= len(loaded_modules):
            break

        debug_module = oe_debug_module_t(m)
        if debug_module.base_address != loaded_modules[idx][0]:
            break

        # Match. Retain module.
        g_loaded_modules.append(loaded_modules[idx])
        idx += 1

    # Remove modules for which symbols have been loaded, but are no longer in
    # debug_modules.
    while idx < len(loaded_modules):
        m = loaded_modules.pop()
        try:
            gdb.execute("remove-symbol-file -a %s" % m[2], False, True)
        except:
            pass

    # Load symbols for modules that are in debug_modules, but are not yet processed.
    while idx < len(modules):
        module_addr = int(modules[idx])
        debug_module = oe_debug_module_t(module_addr)
        print('loading symbols for module %s' % debug_module.path)
        load_enclave_symbol(debug_module.path, debug_module.base_address)
        idx += 1

class MystSyncSymbols (gdb.Command):
    """Ensure that symbols for all enclave modules are loaded."""

    def __init__ (self):
        super (MystSyncSymbols, self).__init__ ("myst-sync-symbols", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        myst_sync_symbols()

class MystAnalyzeSymbols (gdb.Command):
    """Analyze loaded libraries and find out missing symbols."""

    def __init__ (self):
        super (MystAnalyzeSymbols, self).__init__ ("myst-analyze-symbols", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        analyzer = MissingSymbolAnalyzer()
        if len(g_loaded_modules) == 0:
            myst_sync_symbols()

        for m in g_loaded_modules:
            analyzer.process(m[1])

class HookModuleLoadedBreakPoint(gdb.Breakpoint):
    def __init__(self):
        # Setup the same break as ModuleLoadedBreakpoint in gdb_sgx_plugin.py from OE so that
        # we can hook the same point. Adding this script after the OE's script so that this
        # hook is triggered after oe_debugger_init() in gdb_sgx_plugin.py.
        super(HookModuleLoadedBreakPoint, self).__init__('oe_debug_module_loaded_hook', internal=True)

    def stop(self):
        MystSyncSymbols()
        MystAnalyzeSymbols()

class MissingSymbolAnalyzer():
    def __init__(self):
        self.libs = {}

        # objdump is used to figure out imports and exports of
        # a module.
        self.enabled = shutil.which('objdump') is not None
        if not self.enabled:
            self.message('objdump not available. Missing symbols cannot be analyzed.')
        else:
            print('myst-gdb: objdump found. Mising symbols will be analyzed.')

        # Missing symbols in the following modules can be ignored
        self.ignored_libs = [
            # dotnet fails to load one of the dependencies of this module.
            # But that seems to be expected behavior.
            'libcoreclrtraceptprovider.so'
        ]

        # Symbols with the following name can be ignored
        self.ignored_symbols = [
            # Many shared libraries are compiled for gprof and take a weak dependency
            # on this symbol.
            '__gmon_start__'
        ]

    def ignore(self, symbol):
        # Ignore transactional memory functions
        if symbol.startswith('_ITM_'):
            return True
        # ITM new/delete
        if symbol in ['_ZGTtnam', '_ZGTtdlPv']:
            return True
        if symbol in self.ignored_symbols:
            return True

    def message(self, m):
        # unresolved_color = '\033[1;38;5;170m'
        unresolved_color = '\033[0;31m'
        colorize = lambda str, c: ('%s%s\033[0m' % (c, str))
        print(colorize('myst-gdb: ' + m, unresolved_color))

    def find_missing_symbols(self, libname, lib):
        for ig in self.ignored_libs:
            if libname.endswith(ig):
                self.message('skipping symbol analysis for module %s' % libname)
                return

        for sym in lib['imports']:
            if self.ignore(sym):
                continue

            found = False
            for l in self.libs.values():
                if sym in l['exports']:
                    found = True
                    break
            if not found:
                self.message('unresolved symbol: %s' % sym)

    def process(self, libname):
        if not self.enabled:
            return

        print('myst-gdb: analyzing symbols for module %s' % libname)
        output = subprocess.run(['objdump', '-T', libname], stdout=subprocess.PIPE)

        imports = set()
        exports = set()
        for l in output.stdout.decode('utf-8').split('\n'):
            und = "*UND*" in l
            words = l.split()
            if words:
                name = words[-1]
                if und:
                    imports.add(name)
                else:
                    exports.add(name)
        lib = {
             name:libname,
                'imports':imports,
                'exports':exports
             }
        self.libs[libname] = lib
        self.find_missing_symbols(libname, lib)

if __name__ == "__main__":
    HookModuleLoadedBreakPoint()
