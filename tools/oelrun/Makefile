SUBDIR = tools/oelrun
TOP=$(abspath ../..)
include $(TOP)/defs.mak

DIRS = enc host

include $(TOP)/rules.mak

run: main
	$(BINDIR)/oelrun rootfs /bin/main one two three

ROOTFS=$(CURDIR)/rootfs

##==============================================================================
##
## main:
##
##==============================================================================

MUSL_GCC=$(TOP)/build/musl/bin/musl-gcc
MUSL_LIB=$(TOP)/build/musl/lib

main:
	mkdir -p $(ROOTFS)/bin
	$(MUSL_GCC) -fPIC -Wl,-rpath=$(MUSL_LIB) -o $(ROOTFS)/bin/main main.c
