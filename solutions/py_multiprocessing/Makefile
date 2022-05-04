TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER = $(TOP)/scripts/appbuilder
OPTS= --memory-size 512m --thread-stack-size 1m --nobrk
FS=rootfs

ifdef STRACE
	OPTS += --strace-filter SYS_unlink:SYS_exit:SYS_myst_clone:SYS_exit_group:SYS_read
endif

ifdef PERF
	OPTS += --perf
endif

all: rootfs

rootfs:
	$(APPBUILDER) -m Dockerfile
	$(MYST) mkcpio appdir rootfs

clean:
	rm -rf rootfs appdir
run:
	$(MYST_EXEC) $(OPTS) $(FS) /usr/local/bin/python3 /app/mp_test.py

one-mpdb:
	killall myst 2> /dev/null || echo ""
	$(MYST_EXEC) $(OPTS) $(FS) /usr/local/bin/python3 -m mpdb /app/mp_test.py &
	sleep 15 # Increase this value in Makefile if connection fails
	rlwrap telnet 127.0.0.1 5678
	# Once debugger prompt is available, do
	# (Pdb) b /cpython/Lib/test/<test file>.py:line