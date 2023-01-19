TOP=$(abspath ../..)
include $(TOP)/defs.mak

CONTAINER_NAME=omp.myst.apline.062021

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
OPTS = --strace
endif

OPTS += --memory-size=256m

APPDIR=$(CURDIR)/appdir

ROOTFS=$(CURDIR)/rootfs

TEST_FILE = passed.tests

all: $(APPDIR) $(ROOTFS)

$(ROOTFS):
	$(MYST) mkcpio $(APPDIR) $(ROOTFS)

$(APPDIR):
	$(APPBUILDER) -m Dockerfile

TESTS=$(shell cat $(TEST_FILE))

define NL


endef

tests: $(APPDIR) $(ROOTFS)
	$(foreach i, $(TESTS), $(MYST_EXEC) $(ROOTFS) $(i) $(OPTS) $(NL) )

clean:
	rm -rf appdir image.tar rootfs
