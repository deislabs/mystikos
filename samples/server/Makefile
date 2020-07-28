SUBDIR = samples/server
TOP=$(abspath ../..)
include $(TOP)/defs.mak

ROOTFS=$(CURDIR)/rootfs

all:
	mkdir -p $(ROOTFS)/bin
	$(MUSL_GCC) -fPIC -Wl,-rpath=$(MUSL_LIB) -o $(ROOTFS)/bin/main main.c

TRACE= --trace-syscalls

run:
	$(BINDIR)/oelrun $(TRACE) $(ROOTFS) /bin/main

clean:
	rm -rf $(ROOTFS)
