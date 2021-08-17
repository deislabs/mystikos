TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
LLDB_LOG_FILE = myst_lldb_out.log

LLDB_CMDS=-o "b print_hello" \
	-o "run" \
	-o "process handle SIGILL -s false -n false" \
	-o "bt" \
	-o "c" \
	-o "q"

LLDB_MATCH=helloworld\`print_hello\(count\=4\) at helloworld.c:10

# runtest timeouts causes gdb to hang. Do no use timeouts for lldb too.
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

__tests:rootfs
	${MYST_LLDB} ${LLDB_CMDS} -- ${MYST} ${EXEC} rootfs /bin/helloworld ${OPTS} 2>&1 > ${LLDB_LOG_FILE} 2> /dev/null \
           || echo "Failure running myst_lldb"
	@cat ${LLDB_LOG_FILE} | grep -E "$(LLDB_MATCH)" > /dev/null || (cat ${LLDB_LOG_FILE} && exit 1)
	@ echo "=== passed test (lldb)"

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs $(LLDB_LOG_FILE)
