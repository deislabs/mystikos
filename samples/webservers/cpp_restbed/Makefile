.PHONY: all app cpio

TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPDIR = appdir
TESTSDIR_HOST=$(CURDIR)/$(APPDIR)/tests
TESTSDIR_MYST=/tests

#OPTS = --strace

all: myst cpio

run:
	@echo -e "\n------starting cpp restbed test suite------\n"
	$(foreach test, $(shell ls $(TESTSDIR_HOST)), $(MYST) exec rootfs $(TESTSDIR_MYST)/$(test) $(OPTS) $(NL))

myst:
	$(MAKE) -C $(TOP)/tools/myst

app: clean
	$(TOP)/scripts/appbuilder Dockerfile

cpio: app
	$(MYST) mkcpio $(APPDIR) rootfs

clean:
	rm -rf $(APPDIR) rootfs
