#!/usr/local/bin/python3
import remote_pdb

print ("Setting break")
remote_pdb.set_trace('127.0.0.1', 4444)

def fact(n):
    if n == 0:
        return 1
    return n * fact(n-1)

print ("Hello, World")
print ("fact(20) = %s" % fact(20))
print ("=== passed test (pdb)")
