TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
RETRY_W_BACKOFF=$(TOP)/scripts/retry_with_backoff
HEAP_SIZE="768M"
OPTS += --report-native-tids

ifdef STRACE
OPTS += --strace
endif

all: ext2fs

appdir:
	$(RETRY_W_BACKOFF) docker pull mcr.microsoft.com/dotnet/sdk:6.0
	$(RETRY_W_BACKOFF) docker pull mcr.microsoft.com/dotnet/runtime:6.0
	$(APPBUILDER) Dockerfile

ext2fs: appdir
	$(MYST) mkext2 appdir ext2fs

clean:
	rm -fr appdir ext2fs

OPTS += --memory-size $(HEAP_SIZE) --thread-stack-size "16M"

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
