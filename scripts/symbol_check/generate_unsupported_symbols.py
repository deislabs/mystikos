#!/usr/bin/env python3
# Requires Python >= 3.7

import argparse
from functools import reduce
import sys
import subprocess
from typing import List, Set, AnyStr


def call_nm(path, flag_dynamic=True):
    """
    Call nm with the given path and return the output
    """
    # requires Python >= 3.7
    list_args = ["nm", "-D", path] if flag_dynamic else ["nm", path]

    result = subprocess.run(args=list_args, capture_output=True, text=True)
    if result.returncode != 0:
        print("nm command failed with output:\n",
              result.stdout, result.stderr, file=sys.stderr)
        exit(1)

    return result.stdout


def load_nm_output_from_text_file(filepath):
    '''
    This function expects filepath point to file that contains output of nm command
    Return list of tuple (address, type, symbol)
    '''
    symbols = []
    with open(filepath, 'r') as f:
        while True:
            line = f.readline()
            if not line:
                break
            symbols.append(tuple(line.strip().split()))

    return symbols


def load_nm_output_from_object_file(path_so, flag_dynamic=True):
    '''
    Converts the output to list of tuples (address, type, symbol)
    This function expects filepath point to object file
    Return list of tuple (address, type, symbol)
    '''
    symbols = []
    raw_stdout = call_nm(path_so, flag_dynamic)
    for line in raw_stdout.split('\n'):
        if line:
            symbols.append(tuple(line.strip().split()))

    return symbols


def extract_symbols(symbols):
    """
    Given list of tuples in the form of (address, type, symbol), return a set of symbols
    """
    output = set()
    for each in symbols:
        symbol = each[-1]
        # remove version info like mprotect@@GLIBC_x.y.z
        symbol = symbol[:symbol.index("@")] if '@' in symbol else symbol
        output.add(symbol)

    return output


def write_to(s: Set, file=None):
    if file is None:
        print(*sorted(s), sep='\n')
    else:
        with open(file, 'w') as f:
            f.writelines(each + "\n" for each in sorted(s))


def get_args():
    parser = argparse.ArgumentParser(
        description='Generate glibc symbols that are unsupported in Mystikos CRT, and save to output. See readme.md for more details')

    parser.add_argument('--iglibc', nargs='+', type=str,
                        help='Specify one or more glibc family object file')
    parser.add_argument('--imystikos', nargs='+', type=str,
                        help='Specify one or more Mystikos CRT object file')

    parser.add_argument('-o', '--output', nargs='?',
                        help='Specify output filename')

    args = parser.parse_args()

    if args.iglibc is None or args.imystikos is None:
        print("Error: Missing --glibc or --imystikos")
        parser.print_usage()
        exit(1)

    return args


if __name__ == '__main__':
    '''
    Expected usage:
    ./generate_unsupported_symbol.py --iglibc /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libm.so.6 /lib/x86_64-linux-gnu/libpthread.so.0 --imystikos ../../build/lib/libmystcrt.so -o symbols/unsupported
    '''

    # 0. Grab arguments
    args = get_args()

    # 1 get list of symbols and convert list to set, then get union of all sets
    set_symbols_glibc: Set[AnyStr] = reduce(lambda a, b: a | b,
                                            map(lambda each: extract_symbols(load_nm_output_from_object_file(each)), args.iglibc))

    set_symbols_mystikos: Set[AnyStr] = reduce(lambda a, b: a | b,
                                               map(lambda each: extract_symbols(load_nm_output_from_object_file(each, flag_dynamic=False)), args.imystikos))

    # 2 get diff
    set_symbols_not_in_mystikos = set_symbols_glibc - set_symbols_mystikos

    write_to(set_symbols_not_in_mystikos, args.output)
