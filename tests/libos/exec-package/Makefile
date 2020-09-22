TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPDIR = appdir
APPNAME = hello
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

REDEFINE_TESTS=1

include $(TOP)/rules.mak

tests:
	$(RUNTEST) $(MAKE) run-package-with-args
	$(RUNTEST) $(MAKE) run-package-no-args

run-package-with-args:
	rm -rf $(APPDIR) result private.pem public.pem $(APPNAME).signed
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/$(APPNAME) ../hello.c $(LDFLAGS)
	$(PREFIX) $(VALGRIND) $(LIBOS) package $(APPDIR) private.pem config.json
	$(APPNAME).signed/bin/$(APPNAME) red green blue yellow | grep -v TESTNAME > result
	diff result expected-args
	rm -rf $(APPDIR) result private.pem public.pem $(APPNAME).signed
	@ echo "=== passed test (libos: exec-signed)"

run-package-no-args:
	rm -rf $(APPDIR) result private.pem public.pem $(APPNAME).signed
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/$(APPNAME) ../hello.c $(LDFLAGS)
	$(PREFIX) $(VALGRIND) $(LIBOS) package $(APPDIR) private.pem config.json
	$(APPNAME).signed/bin/$(APPNAME) | grep -v TESTNAME > result
	diff result expected-no-args
	rm -rf $(APPDIR) result private.pem public.pem $(APPNAME).signed
	@ echo "=== passed test (libos: exec-signed)"
