TOP = $(abspath ../..)
include $(TOP)/defs.mak

DIRS = enclave host

ifdef LIBOS_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

include $(TOP)/rules.mak
