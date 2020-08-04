SUBDIR = samples/hello
TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir

all: libos
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) -fPIC -Wl,-rpath=$(MUSL_LIB) -o $(APPDIR)/bin/hello hello.c
	(cd appdir; find . | cpio --create --format='newc' > ../rootfs)

#OPTS = --trace-syscalls

run: all
	$(BINDIR)/libos exec rootfs /bin/hello red green blue yellow $(OPTS)

gdb: all
	$(OEGDB) --args $(BINDIR)/libos $(OPTS) $(APPDIR) /bin/hello red green blue yellow

clean:
	rm -rf $(APPDIR)

libos:
	$(MAKE) -C $(TOP)/tools/libos
