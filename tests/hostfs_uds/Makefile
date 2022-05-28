TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
PROG = enclave_client

all:
	$(MAKE) rootfs
	$(MAKE) build-server

build-server:
	gcc -o host_uds_server host_uds_server.c

rootfs: $(PROG).c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/$(PROG) $(PROG).c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS = --strace
endif

HOSTDIR=/tmp/hostfs_uds_test/

mk-hostdir:
	mkdir -p $(HOSTDIR)

ls-hostdir:
	ls -l $(HOSTDIR)

rm-hostdir:
	rm -rf $(HOSTDIR) || true

tests: all
	$(MAKE) rm-hostdir
	$(MAKE) mk-hostdir
	$(MAKE) server
	$(MAKE) client

server:
	./host_uds_server $(HOSTDIR) &

client:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/$(PROG) $(HOSTDIR)

killsrv:
	killall host_uds_server || true

clean:
	$(MAKE) killsrv	
	rm -rf $(APPDIR) $(HOSTDIR) rootfs host_uds_server
