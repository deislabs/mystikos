TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: fork.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/fork fork.c $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/fork_child child.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs


ifdef STRACE
OPTS = --strace
endif

tests: all
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --app-config-path config-kill-children.json rootfs /bin/fork fork
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --fork-mode pseudo_kill_children rootfs /bin/fork fork
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --app-config-path config-none.json rootfs /bin/fork nofork

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
