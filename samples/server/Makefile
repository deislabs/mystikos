SUBDIR = samples/server
TOP=$(abspath ../..)
include $(TOP)/defs.mak

ROOTFS=$(CURDIR)/rootfs

all:
	mkdir -p $(ROOTFS)/bin
	$(MUSL_GCC) -fPIC -Wl,-rpath=$(MUSL_LIB) -o $(ROOTFS)/bin/main main.c

#TRACE_SYSCALLS = --trace-syscalls

run:
	$(BINDIR)/libos $(TRACE_SYSCALLS) $(ROOTFS) /bin/main

clean:
	rm -rf $(ROOTFS)
