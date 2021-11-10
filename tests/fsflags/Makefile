TOP = $(abspath ../..)
include $(TOP)/defs.mak

all:
	make -C appdir
	$(MYST) mkcpio appdir/appdir rootfs
	$(MYST) mkext2 --force appdir/appdir ext2fs

ifdef STRACE
OPTS = --strace
endif

# ifdef MYST_ENABLE_GCOV
# OPTS += --export-ramfs
# endif

tests_ext2fs:
	$(MYST_EXEC) $(OPTS) ext2fs /opath
	$(MYST_EXEC) $(OPTS) ext2fs /atemptypath

tests_ramfs:
	$(MYST_EXEC) $(OPTS) rootfs /opath
	$(MYST_EXEC) $(OPTS) rootfs /atemptypath

tests: all tests_ext2fs tests_ramfs


clean:
	rm -rf rootfs ramfs
	make -C appdir clean
