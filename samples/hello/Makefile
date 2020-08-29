SUBDIR = samples/hello
TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
LIBOS = $(BINDIR)/libos
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all: libos private.pem
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/hello hello.c $(LDFLAGS)
	$(LIBOS) mkcpio $(APPDIR) rootfs
	$(LIBOS) sign --target /bin/hello --rootfs rootfs --platform OE --pem_file private.pem --config_file config.conf

ifdef STRACE
OPTS += --strace
endif

run: all
	app.signed/libos exec app.signed/rootfs /bin/hello red green blue yellow $(OPTS)

gdb: all
	$(OEGDB) --args $(LIBOS) exec rootfs /bin/hello $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

private.pem:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem

clean:
	rm -rf $(APPDIR) rootfs private.pem public.pem app.signed
