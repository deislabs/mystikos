TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
APPNAME = hello
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all: libos
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/$(APPNAME) hello.c $(LDFLAGS)

ifdef STRACE
OPTS += --strace
endif

mkcpio: all
	$(PREFIX) $(LIBOS) mkcpio $(APPDIR) rootfs

sign: all mkcpio private-pem
	$(PREFIX) $(LIBOS) sign rootfs private.pem config.json

package: all private-pem
	$(PREFIX) $(VALGRIND) $(LIBOS) package $(APPDIR) private.pem config.json

run: mkcpio
	$(LIBOS_EXEC) rootfs /bin/$(APPNAME) red green blue yellow $(OPTS)

run-signed: sign
	$(PREFIX) $(APPNAME).signed/bin/libos $(EXEC) $(APPNAME).signed/rootfs /bin/$(APPNAME) red green blue yellow $(OPTS)

run-package-with-args: package
	$(APPNAME).signed/bin/$(APPNAME) red green blue yellow $(OPTS)

run-package-no-args: package
	$(APPNAME).signed/bin/$(APPNAME) $(OPTS)

run-all: run run-signed run-package-with-args run-package-no-args

gdb: all
	$(LIBOS_GDB) --args $(LIBOS) exec rootfs /bin/$(APPNAME) $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

private-pem:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem

clean:
	rm -rf $(APPDIR) rootfs private.pem public.pem $(APPNAME).signed
