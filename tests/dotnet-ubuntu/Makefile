TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
HEAP_SIZE="768M"

ifdef STRACE
OPTS += --strace
endif

all: appdir ext2fs

appdir:
	$(APPBUILDER) Dockerfile

ext2fs: appdir
	sudo $(MYST) mkext2 appdir ext2fs
	$(MYST) fssig --roothash ext2fs > roothash

clean:
	sudo rm -fr appdir ext2fs roothash

tests:
	$(RUNTEST) $(MYST_EXEC) ext2fs --roothash=roothash \
	--memory-size $(HEAP_SIZE) \
	/app/hello $(OPTS)

##############################
# dev targets
# ############################
run-ext2-lldb:
	/mnt/oelldb/oelldb -- $(MYST) exec ext2fs \
	--roothash=roothash \
	--memory-size $(HEAP_SIZE) \
	/app/hello $(OPTS)

run-ext2-gdb:
	$(MYST_GDB) --args $(MYST) exec ext2fs \
	--roothash=roothash \
	--memory-size $(HEAP_SIZE) \
	/app/hello $(OPTS)

ct:
	sudo rm -fr /tmp/myst*
