TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR=appdir
APPBUILDER=$(TOP)/scripts/appbuilder

TEST_FILE=ltp_enabled.txt
TESTS=$(shell cat $(TEST_FILE))

all:
	git submodule update --init --progress $(TOP)/third_party/ltp/ltp
	$(MAKE) myst
	$(MAKE) rootfs

$(APPDIR): buildltp.sh
	@ rm -fr ltp
	@ mkdir ltp
	@ cp -R ../../third_party/ltp/ltp/* ltp/
	$(APPBUILDER) Dockerfile

rootfs: $(APPDIR)
	sudo $(MYST) mkext2 $(APPDIR) "$@"
	truncate --size=-4096 "$@"

ifdef STRACE
OPTS = --strace
endif

tests:
	@ $(foreach i, $(TESTS), $(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs $(i) $(OPTS) $(NL) )

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs ltp export ramfs
