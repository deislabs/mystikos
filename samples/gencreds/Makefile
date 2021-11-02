APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all: 
	mkdir -p $(APPDIR)/bin
	gcc $(CFLAGS) -o $(APPDIR)/bin/gencreds gencreds.c
	@myst mkcpio $(APPDIR) rootfs

#OPTS += --strace

run: all
	@myst exec-sgx rootfs /bin/gencreds $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs
