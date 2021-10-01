TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
HEAP_SIZE="768M"
OPTS += --report-native-tids

ifdef STRACE
OPTS += --strace
endif

all: ext2fs

appdir:
	$(APPBUILDER) Dockerfile
	$(SQUASH-APPDIR) appdir

ext2fs: appdir
	$(MYST) mkext2 appdir ext2fs

clean:
	rm -fr appdir ext2fs

OPTS += --memory-size $(HEAP_SIZE)

tests:
	$(RUNTEST) $(MYST_EXEC) ext2fs /app/hello $(OPTS)

##############################
# dev targets
# ############################
run-ext2-lldb:
	/mnt/oelldb/oelldb -- $(MYST) exec ext2fs /app/hello $(OPTS)

run-ext2-gdb:
	$(MYST_GDB) --args $(MYST) exec ext2fs /app/hello $(OPTS)

ct:
	sudo rm -fr /tmp/myst*
