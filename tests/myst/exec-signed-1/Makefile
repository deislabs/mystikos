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

include $(TOP)/rules.mak

tests:
	$(RUNTEST) $(MAKE) exec-signed

exec-signed:
	rm -rf $(APPDIR) result rootfs private.pem public.pem $(APPNAME).signed
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/$(APPNAME) ../hello.c $(LDFLAGS)
	$(PREFIX) $(MYST) mkcpio $(APPDIR) rootfs
	$(PREFIX) $(MYST) sign rootfs private.pem config.json
	sudo chown -R $(USER).$(USER) hello.signed
	$(PREFIX) ./$(APPNAME).signed/bin/myst $(EXEC) $(APPNAME).signed/rootfs /bin/$(APPNAME) red green blue yellow | grep -v TESTNAME > result
	diff result expected
	rm -rf $(APPDIR) result rootfs private.pem public.pem $(APPNAME).signed
	@ echo "=== passed test (myst: exec-signed)"

clean-exec-signed-1:
	rm -rf $(APPDIR) result rootfs private.pem public.pem $(APPNAME).signed

pem:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem

build: clean-exec-signed-1
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/$(APPNAME) ../hello.c $(LDFLAGS)

mkcpio: build
	$(PREFIX) $(MYST) mkcpio $(APPDIR) rootfs

sign: mkcpio pem
	$(PREFIX) $(MYST) sign rootfs private.pem config.json

run: sign
	$(PREFIX) $(APPNAME).signed/bin/myst $(EXEC) $(APPNAME).signed/rootfs /bin/$(APPNAME) red green blue yellow
