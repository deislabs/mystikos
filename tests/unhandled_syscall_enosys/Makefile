TOP=$(abspath ../..)
include $(TOP)/defs.mak

ifdef STRACE
OPTS = --strace
endif

APPDIR = appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
INCLUDES = -I$(INCDIR)

all: rootfs

rootfs: enosys_test.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) $(INCLUDES) -o $(APPDIR)/bin/enosys_test enosys_test.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

tests: rootfs
	$(MAKE) config
	$(MAKE) cmdline
	$(MAKE) both

config:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --app-config-path config-false.json rootfs /bin/enosys_test false
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --app-config-path config-true.json rootfs /bin/enosys_test true

cmdline:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --fork-mode pseudo --unhandled-syscall-enosys false rootfs /bin/enosys_test false
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --fork-mode pseudo --unhandled-syscall-enosys true rootfs /bin/enosys_test true

both: 
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --app-config-path config-false.json --unhandled-syscall-enosys false rootfs /bin/enosys_test false
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --app-config-path config-false.json --unhandled-syscall-enosys true rootfs /bin/enosys_test false
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --app-config-path config-true.json --unhandled-syscall-enosys false rootfs /bin/enosys_test true
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --app-config-path config-true.json --unhandled-syscall-enosys true rootfs /bin/enosys_test true

clean:
	rm -rf $(APPDIR) rootfs
