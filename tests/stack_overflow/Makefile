TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

ifdef STRACE
OPTS += --strace
endif

OPTS += --fork-mode pseudo_wait_for_exit_exec

all: rootfs

rootfs: main.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/stk_ovf_test main.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

tests:
	$(MAKE) overflow_in_main
	$(MAKE) overflow_in_child
	$(MAKE) overflow_in_pthread

overflow_in_main:
	$(RUNTEST) $(MYST_EXEC) rootfs $(OPTS) /bin/stk_ovf_test test_main

overflow_in_child:
	$(RUNTEST) $(MYST_EXEC) rootfs $(OPTS) /bin/stk_ovf_test test_child

overflow_in_pthread:
	$(RUNTEST) $(MYST_EXEC) rootfs $(OPTS) /bin/stk_ovf_test test_pthread

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) rootfs /bin/stk_ovf_test $(OPTS)

clean:
	rm -rf $(APPDIR) rootfs export ramfs
