SUBDIR = tools/oelrun
TOP=$(abspath ../..)
include $(TOP)/defs.mak

MUSL_GCC=$(TOP)/build/musl/bin/musl-gcc
MUSL_LIB=$(TOP)/build/musl/lib

ROOTFS=$(CURDIR)/rootfs

all:
	mkdir -p $(ROOTFS)/bin
	$(MUSL_GCC) -fPIC -Wl,-rpath=$(MUSL_LIB) -o $(ROOTFS)/bin/hello hello.c

run:
	$(BINDIR)/oelrun --trace-syscalls $(ROOTFS) /bin/hello red green blue yellow

clean:
	rm -rf $(ROOTFS)
