TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

all:
	$(MAKE) rootfs

rootfs: appdir
	$(MYST) mkext2 appdir rootfs

appdir: brk.cpp
	rm -rf appdir rootfs
	$(APPBUILDER) Dockerfile

ifdef STRACE
OPTS += --strace
endif

OPTS += --thread-stack-size=1048576

TEST1_OPTS = $(OPTS) --enable-brk-syscall
TEST2_OPTS = $(OPTS)

tests:
	$(MAKE) test1
	$(MAKE) test2

test1:
	time $(RUNTEST) $(MYST_EXEC) $(TEST1_OPTS) rootfs /app/brk brk

test2:
	time $(RUNTEST) $(MYST_EXEC) $(TEST2_OPTS) rootfs /app/brk nobrk

clean:
	rm -rf brk appdir rootfs ramfs
