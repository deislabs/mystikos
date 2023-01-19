TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
INCLUDES = -I$(INCDIR)

all: rootfs

rootfs: fork.c child.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) $(INCLUDES) -o $(APPDIR)/bin/fork fork.c $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) $(INCLUDES) -o $(APPDIR)/bin/fork_child child.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs


ifdef STRACE
OPTS = --strace
endif

tests:
	$(MAKE) test-no-fork
	$(MAKE) test-wait-exec
	$(MAKE) test-fork-kill-children
	

# no fork
test-no-fork: rootfs
	TIMEOUT=360 $(RUNTEST) $(MYST_EXEC) $(OPTS) --app-config-path config-none.json rootfs /bin/fork nofork
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/fork nofork
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --fork-mode none rootfs /bin/fork nofork

# pseudo, wait for exec or exit to be called
test-wait-exec: rootfs
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --app-config-path config-wait-exec.json rootfs /bin/fork forkwait
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --fork-mode pseudo_wait_for_exit_exec rootfs /bin/fork forkwait

# pseudo, killing child forks before main thread exits
test-fork-kill-children: all
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --app-config-path config-pseudo.json rootfs /bin/fork fork
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --fork-mode pseudo rootfs /bin/fork fork

# pseudo, wait for exec or exit to be called
test-wait-exec-sighandler: rootfs
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --app-config-path config-wait-exec.json rootfs /bin/fork forkwait_sighandler

clean:
	rm -rf $(APPDIR) rootfs
