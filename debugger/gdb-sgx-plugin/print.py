# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Monkey-patching the print to replace oegdb by myst-gdb from OE plugins
myst_print = print
def print(*args, **kw):
    args = (arg.replace('oegdb', 'myst-gdb') if isinstance(arg, str) else arg
            for arg in args)
    myst_print(*args, **kw)
