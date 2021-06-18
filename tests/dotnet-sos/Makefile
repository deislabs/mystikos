TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
HEAP_SIZE="768M"

MYST_LLDB = ./oelldb/oelldb

OPTS = --report-native-tids

ifdef STRACE
OPTS += --strace
endif

all: ext2fs oelldb

appdir:
	$(APPBUILDER) Dockerfile

ext2fs: appdir
	rm -rf appdir/tmp/clr-debug-pipe*
	sudo $(MYST) mkext2 appdir ext2fs
	$(MYST) fssig --roothash ext2fs > roothash

oelldb:
	git clone --branch working https://github.com/vtikoo/oelldb

clean:
	sudo rm -fr appdir ext2fs rootfs roothash oelldb stdouterr.txt

tests:
	$(RUNTEST) docker run --rm \
	-e TARGET=$(TARGET) \
	-v $(abspath .):/app/ -v $(TOP)/build:/build \
	--device /dev/sgx:/dev/sgx \
	vtikoo/dotnet-sos-prereqs:0.1 \
	/app/exec.sh $(MYST_LLDB) /build/bin/myst $(EXEC) $(OPTS)
	@ echo "=== passed test (dotnet-sos)"

tests-without-docker:
	$(RUNTEST) ./exec.sh $(MYST_LLDB) $(MYST) $(EXEC) $(OPTS)

##################################
#			dev targets			 #
##################################
run-ext2:
	$(MYST) exec ext2fs --roothash=roothash \
	--memory-size $(HEAP_SIZE) \
	/app/hello

run-ext2-lldb:
	$(MYST_LLDB) -o "command script import ignore_sigill" \
	-- $(MYST) exec $(OPTS) ext2fs \
	--roothash=roothash \
	--memory-size $(HEAP_SIZE) \
	/app/hello

ct:
	sudo rm -fr /tmp/myst*
