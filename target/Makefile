TOP = $(abspath ..)
include $(TOP)/defs.mak

DIRS = common linux sgx

include $(TOP)/rules.mak

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif
