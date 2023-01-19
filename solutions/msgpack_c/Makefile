TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
TESTSDIR_HOST=$(CURDIR)/$(APPDIR)/tests
TESTSDIR_MYST=/tests
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all: myst rootfs

OPTS = --memory-size=16m

_run:
	@ echo -e "\n------starting msgpack-c cpp unit tests------\n"
	$(foreach test, $(shell ls $(TESTSDIR_HOST)), $(MYST) exec rootfs $(TESTSDIR_MYST)/$(test) $(OPTS) $(NL))
	
run:
	$(RUNTEST) make -C $(CURDIR) _run

myst:
	$(MAKE) -C $(TOP)/tools/myst

$(APPDIR):
	$(TOP)/scripts/appbuilder Dockerfile

rootfs: appdir
	$(MYST) mkext2 $(APPDIR) rootfs

clean:
	rm -rf rootfs $(APPDIR)
