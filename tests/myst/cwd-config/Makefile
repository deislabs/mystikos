TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPDIR = $(SUBOBJDIR)/appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

ifdef STRACE
OPTS = --strace
endif

all: myst rootfs

build:	main.c child-cwd.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/test main.c $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/child-cwd child-cwd.c $(LDFLAGS)

rootfs: build
	$(MYST) mkcpio $(APPDIR) rootfs

tests: test-default-path test-override

test-default-path: rootfs
	$(RUNTEST) $(MYST_EXEC) rootfs $(OPTS) /bin/test /

test-override: rootfs
	$(RUNTEST) $(MYST_EXEC) rootfs $(OPTS) --app-config-path config1.json /bin/test /test1

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs
