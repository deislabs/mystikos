SUBDIR = samples/shlib
TOP=$(abspath ../..)
include $(TOP)/defs.mak

ROOTFS=$(CURDIR)/rootfs

export LD_LIBRARY_PATH=$(ROOTFS)/lib

all:
	@mkdir -p $(ROOTFS)/bin
	@mkdir -p $(ROOTFS)/lib
	@$(MUSL_GCC) -fPIC -shared -o $(ROOTFS)/lib/libfoo.so foo.c
	@$(MUSL_GCC) -fPIC -o $(ROOTFS)/bin/main main.c -Wl,-rpath=/lib -L$(ROOTFS)/lib -lfoo

#TRACE_SYSCALLS=--trace-syscalls

run: all
	libos $(TRACE_SYSCALLS) rootfs /bin/main

clean:
	rm -rf rootfs
