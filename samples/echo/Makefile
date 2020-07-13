TOP=$(abspath ../..)
include $(TOP)/defs.mak

DIRECTORY = samples/echo

DIRS = enc host

include $(TOP)/rules.mak

tests:
	./host/host ./enc/enc
