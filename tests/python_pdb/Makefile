TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
PDB_LOG_FILE=pdb.log

ifdef STRACE
OPTS += --strace
endif

all: rootfs

appdir:
	$(APPBUILDER) -m Dockerfile

rootfs: appdir
	$(MYST) mkext2 appdir rootfs

APP_NAME=/usr/local/bin/python3
APP_ARGS=/app/main.py

tests: rootfs
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs $(APP_NAME) $(APP_ARGS) &
	sleep 2 && nc 127.0.0.1 4444 < commands.pdb > ${PDB_LOG_FILE}
	@cat ${PDB_LOG_FILE}
	@cat ${PDB_LOG_FILE} | grep -E "\(Pdb) 16" > /dev/null
	@cat ${PDB_LOG_FILE} | grep -E "=== passed test \(pdb)" > /dev/null

gdb:
	$(MAKE) tests GDB=1

clean:
	rm -fr appdir rootfs
