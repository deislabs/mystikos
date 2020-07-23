.PHONY: tests
SUBDIR = third_party
TOP = $(abspath $(CURDIR))
include $(TOP)/defs.mak

DIRS = third_party enclave tests

include $(TOP)/rules.mak
