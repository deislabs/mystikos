TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
HEAP_SIZE="768M"

MYST_LLDB = ./oelldb/oelldb

OPTS = --report-native-tids

ifdef STRACE
OPTS += --strace
endif

all: ext2fs oelldb dotnet-sos

appdir:
	$(APPBUILDER) Dockerfile

ext2fs: appdir
	rm -rf appdir/tmp/clr-debug-pipe*
	sudo $(MYST) mkext2 appdir ext2fs
	$(MYST) fssig --roothash ext2fs > roothash

oelldb:
	git clone --branch working https://github.com/vtikoo/oelldb

dotnet-sos:
	sudo apt install -y dotnet-sdk-5.0 && \
	dotnet tool install -g dotnet-sos \
	&& $(HOME)/.dotnet/tools/dotnet-sos install || true

clean:
	sudo rm -fr appdir ext2fs rootfs roothash oelldb stdouterr.txt /tmp/myst*
	$(HOME)/.dotnet/tools/dotnet-sos uninstall && \
	sudo rm -rf ~/.dotnet && \
	sudo apt remove -y dotnet-sdk-5.0 || true

tests:
	$(RUNTEST) ./exec.sh $(MYST_LLDB) $(MYST) $(OPTS) $(HEAP_SIZE)
	@ echo "=== passed test (dotnet-sos)"

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
