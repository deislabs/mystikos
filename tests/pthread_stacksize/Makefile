TOP=$(abspath ../..)
include $(TOP)/defs.mak

CFLAGS = -fPIC

OPTS =

ifdef STRACE
OPTS += --strace
endif

OPTS = --memory-size=8m

APP = /bin/pthread_stacksize

all:
	$(MAKE) rootfs

rootfs: pthread_stacksize.c
	mkdir -p appdir/bin
	$(CC) $(CFLAGS) -o appdir/$(APP) pthread_stacksize.c -lpthread
	$(MYST) mkcpio appdir rootfs

test = $(RUNTEST) $(MYST_EXEC) rootfs $(APP) $(1) $(OPTS) --thread-stack-size=$(1)

TEST1 = $$((4096 * 32))
TEST2 = $$((4096 * 64))
TEST3 = $$((4096 * 128))
TEST4 = $$((4096 * 256))
TEST5 = $$((4096 * 300))
TEST6 = $$((4096 * 1024))

tests: all
	$(call test,$(TEST1))
	$(call test,$(TEST2))
	$(call test,$(TEST3))
	$(call test,$(TEST4))
	$(call test,$(TEST5))
	$(call test,$(TEST6))

clean:
	rm -rf appdir rootfs export ramfs
