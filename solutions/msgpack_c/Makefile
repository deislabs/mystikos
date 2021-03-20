TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
TESTSDIR_HOST=$(CURDIR)/$(APPDIR)/tests
TESTSDIR_MYST=/tests
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all: myst rootfs

OPTS = --memory-size=8m

run:
	@ echo -e "\n------starting msgpack-c cpp unit tests------\n"
	$(foreach test, $(shell ls $(TESTSDIR_HOST)), $(MYST) exec rootfs $(TESTSDIR_MYST)/$(test) $(OPTS) $(NL))

myst:
	$(MAKE) -C $(TOP)/tools/myst

$(APPDIR):
	$(TOP)/scripts/appbuilder Dockerfile

rootfs: appdir
	sudo $(MYST) mkext2 $(APPDIR) rootfs
	sudo chown $(USER).$(USER) rootfs
	truncate --size=-4096 rootfs

clean:
	rm -rf rootfs $(APPDIR)
