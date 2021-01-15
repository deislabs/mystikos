TOP = $(abspath ../..)
include $(TOP)/defs.mak

IMG=myst-alpine

ifdef STRACE
OPTS = --strace
endif

ROOTHASH=$(SUBOBJDIR)/roothash

APPDIR=$(CURDIR)/appdir

ROOTFS=$(CURDIR)/rootfs

##==============================================================================
##
## all rule:
##
##==============================================================================

all: $(APPDIR) $(APPDIR)/target $(APPDIR)/bin/run $(ROOTFS) $(ROOTHASH)

$(APPDIR):
	rm -rf $(APPDIR)
	cp -r $(TOP)/third_party/libc-test/libc-test $(APPDIR)

$(APPDIR)/target:
	sudo docker run --rm -v $(APPDIR):/appdir $(IMG) bash -c "make -C appdir"
	touch $(APPDIR)/target

$(APPDIR)/bin/run: run.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) -Wall -o $(APPDIR)/bin/run run.c

$(ROOTFS): run.c
	$(MYST) mkext2 --force $(APPDIR) $(ROOTFS)

$(ROOTHASH): run.c
	mkdir -p $(SUBOBJDIR)
	$(MYST) fssig --roothash $(ROOTFS) > $(ROOTHASH)

##==============================================================================
##
## tests:
##
##==============================================================================

RUN = $(RUNTEST) $(MYST_EXEC) $(OPTS) --roothash=$(ROOTHASH) $(ROOTFS)

OPTS += --roothash=$(ROOTHASH)

tests: all
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /bin/run

clean:
	rm -rf $(APPDIR) $(ROOTFS) $(ROOTHASH)
