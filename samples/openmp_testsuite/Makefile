TOP=$(abspath ../..)
include $(TOP)/defs.mak

CONTAINER_NAME=omp.myst.apline.062021

ifdef STRACE
OPTS = --strace
endif

OPTS += --memory-size=256m

APPDIR=$(CURDIR)/appdir

ROOTFS=$(CURDIR)/rootfs

TEST_FILE = passed.tests

all: $(APPDIR) $(ROOTFS)

$(ROOTFS):
	sudo $(MYST) mkcpio $(APPDIR) $(ROOTFS)

$(APPDIR):
	myst-appbuilder Dockerfile

TESTS=$(shell cat $(TEST_FILE))

define NL


endef

tests:
	$(foreach i, $(TESTS), $(MYST_EXEC) rootfs $(i) $(OPTS) $(NL) )

clean:
	rm -rf appdir image.tar rootfs
