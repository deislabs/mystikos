.NOTPARALLEL:
TOP=$(abspath ../..)
include $(TOP)/defs.mak

ifdef STRACE
OPTS += --strace
endif

ifdef ETRACE
OPTS += --etrace
endif

APPDIR=$(CURDIR)/appdir
APPBUILDER=$(TOP)/scripts/appbuilder

ROOTFS=$(CURDIR)/rootfs

OPTS += --nobrk
OPTS += --memcheck

all:
	$(MAKE) myst
	$(MAKE) $(APPDIR)
	$(MAKE) $(ROOTFS)

$(APPDIR):
	$(APPBUILDER) -m Dockerfile

$(ROOTFS):
	$(MYST) mkext2 $(APPDIR) $(ROOTFS)

tests: $(ROOTFS)
	$(MYST_EXEC) $(OPTS) $(ROOTFS) /app/foo/printvars

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) $(ROOTFS)
