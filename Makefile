.PHONY: tests
SUBDIR = third_party
TOP = $(abspath $(CURDIR))
include $(TOP)/defs.mak

DIRS = third_party kernel tools alpine tests

include $(TOP)/rules.mak
