TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = $(SUBOBJDIR)/appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) rootfs

rootfs: spawn.c child.c child-signal.c child-crash.c script-shell.c
	mkdir -p $(APPDIR)/bin
	cp ./script*.sh $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/spawn spawn.c $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/child child.c $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/child-signal child-signal.c $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/child-crash child-crash.c $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/shell script-shell.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS = --strace
endif

ifdef ETRACE
OPTS = --etrace
endif

ifdef TRACE
OPTS = --etrace --strace
endif

tests:
	$(MAKE) test-spawn-binary
	$(MAKE) test-spawn-script

test-spawn-binary: rootfs
	$(RUNTEST) $(MYST_EXEC)  $(OPTS) rootfs /bin/spawn

test-spawn-script: rootfs
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/script1.sh 
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/script2.sh 
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/script3.sh 
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/script4.sh 
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/script5.sh 
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/script6.sh extra options

t: rootfs
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/script3.sh 

clean:
	rm -rf $(APPDIR) rootfs
