TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
GDB_LOG_FILE = myst_gdb_out.log

GDB_CMDS=--batch \
	-ex "set breakpoint pending on" \
	-ex "handle SIGILL nostop noprint" \
	-ex "break print_hello" \
	-ex "run" \
	-ex "backtrace" \
	--args

GDB_MATCH=Breakpoint 4, .................. in print_hello ()

# runtest timeouts cause gdb to hang
export NOTIMEOUT=1

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: helloworld.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/helloworld helloworld.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

tests:
	$(RUNTEST) $(MAKE) __tests

__tests:
	${MYST_GDB} ${GDB_CMDS} ${MYST} ${EXEC} rootfs /bin/helloworld ${OPTS} 2>&1 > ${GDB_LOG_FILE} 2> /dev/null
	@cat ${GDB_LOG_FILE} | grep -E "$(GDB_MATCH)" > /dev/null
	@ echo "=== passed test (gdb)"

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs $(GDB_LOG_FILE)
