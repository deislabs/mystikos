TOP=$(abspath ../..)
include $(TOP)/defs.mak

CONTAINER_NAME=omp.myst.apline.062021

ifdef STRACE
OPTS = --strace
endif

OPTS += --memory-size=256m

APPDIR=$(CURDIR)/appdir

ROOTFS=$(CURDIR)/rootfs

EXT2FS_SIZE=2147483648

TEST_FILE = passed.tests

all: $(APPDIR) $(ROOTFS)

$(ROOTFS):
	sudo $(MYST) mkext2 --force --size $(EXT2FS_SIZE) $(APPDIR) $(ROOTFS)
	sudo chown $(USER).$(USER) $(ROOTFS)
	truncate --size=-4096 $(ROOTFS)

$(APPDIR):
	myst-appbuilder Dockerfile

TESTS=$(shell cat $(TEST_FILE))

define NL


endef

tests:
	$(foreach i, $(TESTS), $(MYST_EXEC) rootfs $(i) $(OPTS) $(NL) )

clean:
	rm -rf appdir image.tar rootfs
