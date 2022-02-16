TOP=$(abspath ..)
include $(TOP)/defs.mak

TESTS=../tests

DIRS =
DIRS += $(TESTS)/getcwd
DIRS += $(TESTS)/mman
DIRS += $(TESTS)/fs
DIRS += $(TESTS)/mount
DIRS += $(TESTS)/cpio
DIRS += $(TESTS)/ext2
DIRS += $(TESTS)/sockets

.PHONY: $(DIRS)

dirs: $(DIRS)

$(DIRS):
	$(MAKE) -C $@

__check:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) tests $(NL) )

check:
	@ sudo rm -rf $(TESTDIR)
	@ $(MAKE) __check TARGET=sgx
	@ $(MAKE) __check TARGET=linux

clean:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

distclean: clean
