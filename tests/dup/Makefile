TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: dup.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/dup dup.c $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/exec_prog exec_prog.c $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/dup_cloexec dup_cloexec.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs
	$(MYST) mkext2 --force $(APPDIR) ext2fs

ifdef STRACE
OPTS = --strace
endif

tests: all
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/dup $(OPTS)
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/dup_cloexec $(OPTS)
	$(RUNTEST) $(MYST_EXEC) ext2fs /bin/dup $(OPTS)
	$(RUNTEST) $(MYST_EXEC) ext2fs /bin/dup_cloexec $(OPTS)

tests2:
	gcc dup.c -o dup 
	gcc exec_prog.c -o exec_prog
	gcc dup_cloexec.c -o dup_cloexec
	./dup
	./dup_cloexec

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
