.NOTPARALLEL:

TOP = $(abspath ../..)
include $(TOP)/defs.mak

all:
	make -C appdir
	$(MYST) mkcpio appdir rootfs
	$(MYST) mkext2 --force appdir ext2fs

ifdef STRACE
OPTS = --strace
endif

tests_ext2fs: all
	$(MYST_EXEC) $(OPTS) ext2fs /opath
	$(MYST_EXEC) $(OPTS) ext2fs /atemptypath

tests_ramfs: all
	$(MYST_EXEC) $(OPTS) rootfs /opath
	$(MYST_EXEC) $(OPTS) rootfs /atemptypath

tests: tests_ext2fs tests_ramfs


clean:
	rm -rf rootfs ramfs
	make -C appdir clean
