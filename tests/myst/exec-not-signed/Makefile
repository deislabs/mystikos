TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPDIR = appdir
APPNAME = hello
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
LDFLAGS += -L$(LIBDIR) -lopenenclave

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

REDEFINE_TESTS=1

CLEAN = appdir result rootfs

include $(TOP)/rules.mak

tests:
	$(RUNTEST) $(MAKE) test-a
	$(RUNTEST) $(MAKE) test-config
	$(RUNTEST) $(MAKE) test-mem-size

test-a:
	rm -rf $(APPDIR) result rootfs
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/$(APPNAME) ../hello.c $(LDFLAGS)
	$(PREFIX) $(MYST) mkcpio $(APPDIR) rootfs
	$(MYST_EXEC) rootfs /bin/$(APPNAME) red green blue yellow > result
	grep -E "argv\[0]=/bin/hello" result
	grep -E "argv\[1]=red" result
	grep -E "argv\[2]=green" result
	grep -E "argv\[3]=blue" result
	grep -E "argv\[4]=yellow" result
	grep -vE "TESTNAME=tests/myst/exec-not-signed" result
	@ echo "=== passed test (myst: exec-not-signed)"

test-mem-size:
	rm -rf $(APPDIR) result rootfs
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/$(APPNAME) ../hello.c $(LDFLAGS)
	$(PREFIX) $(MYST) mkcpio $(APPDIR) rootfs
	$(MYST_EXEC) rootfs --memory-size 1g /bin/$(APPNAME) red green blue yellow > result
	grep -E "argv\[0]=/bin/hello" result
	grep -E "argv\[1]=red" result
	grep -E "argv\[2]=green" result
	grep -E "argv\[3]=blue" result
	grep -E "argv\[4]=yellow" result
	grep -vE "TESTNAME=tests/myst/exec-not-signed" result
	@ echo "=== passed test (myst: exec-not-signed-config)"

test-config:
	rm -rf $(APPDIR) result rootfs
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/$(APPNAME) ../hello.c $(LDFLAGS)
	$(PREFIX) $(MYST) mkcpio $(APPDIR) rootfs
	$(MYST_EXEC) rootfs --app-config-path config.json /bin/$(APPNAME) red green blue yellow > result
	grep -E "argv\[0]=/bin/hello" result
	grep -E "argv\[1]=red" result
	grep -E "argv\[2]=green" result
	grep -E "argv\[3]=blue" result
	grep -E "argv\[4]=yellow" result
	grep -E "TESTNAME=tests/myst/exec-not-signed" result
	@ echo "=== passed test (myst: exec-not-signed-mem-size)"

clean-exec-not-signed:
	rm -rf $(APPDIR) result rootfs

build: clean-exec-not-signed
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/$(APPNAME) ../hello.c $(LDFLAGS)

mkcpio: build
	$(PREFIX) $(MYST) mkcpio $(APPDIR) rootfs

run: mkcpio
	$(MYST_EXEC) rootfs /bin/$(APPNAME) red green blue yellow
