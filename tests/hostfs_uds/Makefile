TOP=$(abspath ../..)
include $(TOP)/defs.mak

C-APPDIR = c-appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
PROG = enclave_client
APPBUILDER=$(TOP)/scripts/appbuilder

all:
	$(MAKE) c-client-rootfs
	$(MAKE) build-server

build-server:
	gcc -o host_uds_server host_uds_server.c

c-client-rootfs: $(PROG).c
	mkdir -p $(C-APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(C-APPDIR)/bin/$(PROG) $(PROG).c $(LDFLAGS)
	$(MYST) mkcpio $(C-APPDIR) c-client-rootfs

net-client-rootfs:
	$(APPBUILDER) -o net-appdir -m Dockerfile
	$(MYST) mkext2 net-appdir net-client-rootfs

ifdef STRACE-FILTER
OPTS = --strace-filter SYS_epoll_pwait:SYS_socket:SYS_myst_clone:SYS_exit:SYS_setsockopt:SYS_connect:SYS_exit_group:SYS_exit
endif

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
	$(MAKE) client-c

server:
	./host_uds_server $(HOSTDIR) &

client-c:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) c-client-rootfs /bin/$(PROG) $(HOSTDIR)

tests-net:
	$(MAKE) rm-hostdir
	$(MAKE) mk-hostdir
	$(MAKE) server
	sleep 2
	$(MAKE) client-net

client-net:
	$(MYST_EXEC) net-client-rootfs $(OPTS) --app-config-path=config.json \
	--mount $(HOSTDIR)=/mnt/host \
	/app/hello $(HOSTDIR)

killsrv:
	killall host_uds_server || true

clean:
	$(MAKE) killsrv	
	rm -rf $(C-APPDIR) $(HOSTDIR) c-client-rootfs host_uds_server
