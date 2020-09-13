TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
LIBOS = $(BINDIR)/libos
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
GDB_LOG_FILE = libos_gdb_out.log

GDB_CMDS=--batch \
	-ex "set breakpoint pending on" \
	-ex "break print_hello" \
	-ex "run" \
	-ex "backtrace" \
	--args

GDB_MATCH=Breakpoint 1, .................. in print_hello ()

all: libos
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/helloworld helloworld.c $(LDFLAGS)
	$(LIBOS) mkcpio $(APPDIR) rootfs

tests:
	${LIBOS_GDB} ${GDB_CMDS} ${LIBOS} ${EXEC} rootfs /bin/helloworld ${OPTS} 2>&1 > ${GDB_LOG_FILE} 2> /dev/null
	@cat ${GDB_LOG_FILE} | grep -E "$(GDB_MATCH)" > /dev/null
	@ echo "=== passed test: gdb"

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf $(APPDIR) rootfs $(GDB_LOG_FILE)
