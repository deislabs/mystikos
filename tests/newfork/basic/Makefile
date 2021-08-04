TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -Wall -Werror
LDFLAGS = -Wl,-rpath=$(MUSL_LIB) -lpthread

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: newfork.c hello.c goodbye.c
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/newfork newfork.c $(LDFLAGS)
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/hello hello.c $(LDFLAGS)
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/goodbye goodbye.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS += --strace
endif

#OPTS += --memory-size=8m
#OPTS += --memory-size=512m

tests: all
	rm -f /tmp/myst*.socket
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/newfork $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs

t:
	$(MAKE) tests STRACE=1

nc:
	nc -U $(wildcard /tmp/myst*.socket)
