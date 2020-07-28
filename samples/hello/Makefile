SUBDIR = samples/hello
TOP=$(abspath ../..)
include $(TOP)/defs.mak

ROOTFS=$(CURDIR)/rootfs

all:
	mkdir -p $(ROOTFS)/bin
	$(MUSL_GCC) -fPIC -Wl,-rpath=$(MUSL_LIB) -o $(ROOTFS)/bin/hello hello.c

#TRACE_SYSCALLS = --trace-syscalls

run: all
	$(BINDIR)/oelrun $(TRACE_SYSCALLS) $(ROOTFS) /bin/hello red green blue yellow

clean:
	rm -rf $(ROOTFS)
