TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPDIR = appdir
APPNAME = hello
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

REDEFINE_TESTS=1

include $(TOP)/rules.mak

tests:
	$(RUNTEST) $(MAKE) exec-signed

exec-signed:
	rm -rf $(APPDIR) result rootfs private.pem public.pem $(APPNAME).signed
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/$(APPNAME) ../hello.c $(LDFLAGS)
	$(PREFIX) $(MYST) mkcpio $(APPDIR) rootfs
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
	$(PREFIX) $(MYST) sign rootfs private.pem config.json
	$(PREFIX) ./$(APPNAME).signed/bin/myst $(EXEC) $(APPNAME).signed/rootfs /bin/$(APPNAME) red green blue yellow | grep -v TESTNAME > result
	sudo chown -R $(USER).$(USER) hello.signed
	diff result expected
	rm -rf $(APPDIR) result rootfs private.pem public.pem $(APPNAME).signed
	@ echo "=== passed test (myst: exec-signed)"
