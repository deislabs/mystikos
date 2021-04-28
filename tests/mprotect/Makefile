TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: main.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/mprotect_test main.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

tests: rootfs
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/mprotect_test $(OPTS) | grep -v "OE_ENCLAVE_ABORTING" > result
	diff result expected
	@ echo "=== passed test (mprotect)"

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs result
