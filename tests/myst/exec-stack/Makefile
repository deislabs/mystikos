TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: main.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/main main.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

OPTS =

ifdef STRACE
OPTS += --strace
endif

ifdef ETRACE
OPTS += --etrace
endif

tests: all
	$(MAKE) test-cmd-enable
	$(MAKE) test-config-enable
	$(MAKE) test-config-disable
	$(MAKE) testdefault

test-cmd-enable:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --exec-stack rootfs /bin/main 

test-config-enable:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --app-config-path config-enable.json rootfs /bin/main

test-config-disable:
	$(RUNTEST) $(MYST_EXEC) $(OPTS)  --app-config-path config-disable.json  rootfs /bin/main && return 1 || echo "=== passed test (exec-stack config disable)" 

testdefault:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/main && return 1 || echo "=== passed test (exec-stack default disable)" 
	

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
