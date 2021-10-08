# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

import os
import runpy
import socket
import sys

from pdb import Pdb

# Based on cpython/Lib/pdb.py
def main():
    port_var = 'MYSTIKOS_PDB_PORT'

    port = os.environ.get(port_var)
    if not port:
        print('MYSTIKOS_PDB_PORT environment variable not set. Defaulting to port 5678')
        port = 5678
    else:
        port = int(port)

    print('Mystikos pdb waiting for connections at port %d' % port)
    sys.stdout.flush()

    host = '127.0.0.1'
    client_socket = socket.create_server((host, port),
                                         family=socket.AF_INET,
                                         reuse_port=False)

    client_socket.listen(1)
    connection, address = client_socket.accept()
    fd = connection.makefile('rw')
    
    args = sys.argv[1:]
    mainpyfile = args[0]
    run_as_module = False

    if args[0] == '-m':
        run_as_module = True
        mainpyfile = args[1]
        args = args[1:]

    # Update args
    sys.argv[:] = args
        
    if not run_as_module:
        mainpyfile = os.path.realpath(mainpyfile)
        # Replace pdb's dir with script's dir in front of module search path.
        sys.path[0] = os.path.dirname(mainpyfile)
    else:
        runpy._get_module_details(mainpyfile)

    pdb = Pdb(completekey='tab', stdin=fd, stdout=fd)
    # Alias n, c, s commands to show source listing.
    pdb.rcLines.extend(['alias n n;; l .',
                        'alias c c;; l .',
                        'alias s s;; l .'])
    try:
        if run_as_module:
            pdb._runmodule(mainpyfile)
        else:
            pdb._runscript(mainpyfile)
    except:
        pass

    connection.close()
    client_socket.close()

if __name__ == '__main__':
    import mpdb
    mpdb.main()
