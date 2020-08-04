SUBDIR = samples/shlib
TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir

export LD_LIBRARY_PATH=$(APPDIR)/lib

all: libos
	mkdir -p $(APPDIR)/bin
	mkdir -p $(APPDIR)/lib
	$(MUSL_GCC) -fPIC -shared -o $(APPDIR)/lib/libfoo.so foo.c
	$(MUSL_GCC) -fPIC -o $(APPDIR)/bin/main main.c -Wl,-rpath=/lib -L$(APPDIR)/lib -lfoo
	(cd appdir; find . | cpio --create --format='newc' > ../rootfs)

#OPTS = --trace-syscalls

run: all
	libos exec rootfs /bin/main $(OPTS)

clean:
	rm -rf $(APPDIR) rootfs

libos:
	$(MAKE) -C $(TOP)/tools/libos
