TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
INCLUDES = -I$(INCDIR)

ifdef STRACE
OPTS = --strace
endif

all: rootfs

rootfs: parent.c child.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) $(INCLUDES) -o $(APPDIR)/bin/parent parent.c $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) $(INCLUDES) -o $(APPDIR)/bin/child child.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

tests:
	$(MAKE) test1
	$(MAKE) test2
	
# main parent waits for spawned child to shutdown before exiting
# no sighup handler
test1: rootfs
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/parent parent-wait-child-spawn-exit-no-sighup-handler | tee test.output
	diff test.output test1.output

# main parent waits for spawned child to shutdown before exiting
# with sighup handler
test2: rootfs
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/parent parent-wait-child-spawn-exit-with-sighup-handler | tee test.output
	diff test.output test2.output

clean:
	rm -rf $(APPDIR) rootfs test.output
