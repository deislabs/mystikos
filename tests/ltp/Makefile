TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR=appdir
APPBUILDER=$(TOP)/scripts/appbuilder

TEST_FILE=ltp_enabled.txt
TESTS=$(shell cat $(TEST_FILE))

all: libos rootfs

$(APPDIR): buildltp.sh
	@ rm -fr ltp
	@ mkdir ltp
	@ cp -R ../../third_party/ltp/ltp/* ltp/ 
	$(APPBUILDER) Dockerfile

rootfs: $(APPDIR)
	$(LIBOS) mkcpio $(APPDIR) "$@"

tests:
	@ $(foreach i, $(TESTS), $(RUNTEST) $(LIBOS_EXEC) rootfs $(i) $(OPTS) $(NL) )

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf $(APPDIR) rootfs ltp export ramfs
