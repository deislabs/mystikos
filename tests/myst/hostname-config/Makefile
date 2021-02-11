TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPDIR = $(SUBOBJDIR)/appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

ifdef STRACE
OPTS = --strace
endif

all: myst rootfs

build:	main.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/test main.c $(LDFLAGS)

rootfs: build
	$(MYST) mkcpio $(APPDIR) rootfs

tests: test-default-hostname test-override-hostname

test-default-hostname: rootfs
	$(RUNTEST) $(MYST_EXEC) rootfs $(OPTS) /bin/test TEE

test-override-hostname: rootfs
	$(RUNTEST) $(MYST_EXEC) rootfs $(OPTS) --app-config-path config1.json /bin/test test1

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs
