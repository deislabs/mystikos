.PHONY: all app cpio

TOP=$(abspath ../../..)
include $(TOP)/defs.mak


APPBUILDER    = $(TOP)/scripts/appbuilder
APPDIR        = appdir
TESTSDIR_HOST =$(CURDIR)/$(APPDIR)/tests
TESTSDIR_MYST=/tests

#OPTS = --strace

all: myst cpio

run:
	@echo -e "\n------starting cpp restbed test suite------\n"
	$(foreach test, $(shell ls $(TESTSDIR_HOST)), $(MYST) exec rootfs $(TESTSDIR_MYST)/$(test) $(OPTS) $(NL))

run-single-test: 
	@echo -e "\n------running single cpp restbed test suite------\n"
	$(MYST) exec rootfs $(TESTSDIR_MYST)/signal_handling_feature_test_suite $(OPTS) 

gdb: clean cpio
	$(MYST_GDB) --args $(MYST_EXEC) rootfs $(TESTSDIR_MYST)/signal_handling_feature_test_suite $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

$(APPDIR): clean
	$(APPBUILDER) -v Dockerfile

cpio: $(APPDIR)
	$(MYST) mkcpio $(APPDIR) rootfs

clean:
	rm -rf $(APPDIR) rootfs
