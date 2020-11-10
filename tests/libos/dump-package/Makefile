TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPDIR = appdir
APPNAME = hello
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

REDEFINE_TESTS=1

include $(TOP)/rules.mak

tests:
	$(RUNTEST) $(MAKE) dump-package

dump-package:
	rm -rf $(APPDIR) result private.pem public.pem libos/bin
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/$(APPNAME) ../hello.c $(LDFLAGS)
	$(PREFIX) $(VALGRIND) $(LIBOS) package $(APPDIR) private.pem config.json
	$(PREFIX) $(VALGRIND) $(LIBOS) dump ./libos/bin/$(APPNAME)
#	./libos/bin/$(APPNAME) red green blue yellow | grep -v TESTNAME > result
#	diff result expected-args
	rm -rf $(APPDIR) result private.pem public.pem libos/bin
	@ echo "=== passed test (libos: exec-signed)"

