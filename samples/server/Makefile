SUBDIR = tools/oelrun
TOP=$(abspath ../..)
include $(TOP)/defs.mak

MUSL_GCC=$(TOP)/build/musl/bin/musl-gcc
MUSL_LIB=$(TOP)/build/musl/lib

ROOTFS=$(CURDIR)/rootfs

all:
	mkdir -p $(ROOTFS)/bin
	$(MUSL_GCC) -fPIC -Wl,-rpath=$(MUSL_LIB) -o $(ROOTFS)/bin/main main.c

run:
	$(BINDIR)/oelrun --trace-syscalls $(ROOTFS) /bin/main

clean:
	rm -rf $(ROOTFS)
