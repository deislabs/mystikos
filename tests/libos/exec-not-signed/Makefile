TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPDIR = appdir
APPNAME = hello
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

REDEFINE_TESTS=1

include $(TOP)/rules.mak

tests:
	$(RUNTEST) $(MAKE) test-a

test-a:
	rm -rf $(APPDIR) result rootfs
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/$(APPNAME) ../hello.c $(LDFLAGS)
	$(PREFIX) $(LIBOS) mkcpio $(APPDIR) rootfs
	$(LIBOS_EXEC) rootfs /bin/$(APPNAME) red green blue yellow > result
	grep -E "argv\[0]=/bin/hello" result
	grep -E "argv\[1]=red" result
	grep -E "argv\[2]=green" result
	grep -E "argv\[3]=blue" result
	grep -E "argv\[4]=yellow" result
	grep -E "TESTNAME=tests/libos/exec-not-signed" result
	@ echo "=== passed test (libos: exec-not-signed)"

clean-exec-not-signed:
	rm -rf $(APPDIR) result rootfs

build: clean-exec-not-signed
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/$(APPNAME) ../hello.c $(LDFLAGS)

mkcpio: build
	$(PREFIX) $(LIBOS) mkcpio $(APPDIR) rootfs

run: mkcpio
	$(LIBOS_EXEC) rootfs /bin/$(APPNAME) red green blue yellow