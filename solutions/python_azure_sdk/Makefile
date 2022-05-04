TOP = $(abspath ../../)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

OPTS = --nobrk

ifdef STRACE
OPTS += --strace
endif

TIMEOUT=1500

ifdef RUN_AZURE_TESTS
RUNTEST=$(RUNTEST_COMMAND)
endif

all: rootfs

appdir-keyvault_identity:
	$(APPBUILDER) -m -i mystikos/azure-python-sdk-keyvault-identity:azure-mgmt-keyvault_9.1.0 -v -o keyvault_identity/appdir

appdir-storage:
	$(APPBUILDER) -m -i mystikos/azure-python-sdk-storage:azure-mgmt-storage_19.0.0 -v -o storage/appdir

appdir-storage-blob:
	$(APPBUILDER) -m -i mystikos/azure-python-sdk-storage-blob:azure-storage-blob_12.8.1 -v -o storage-blob/appdir

rootfs-keyvault_identity: appdir-keyvault_identity
	$(MYST) mkext2 keyvault_identity/appdir keyvault_identity/rootfs

rootfs-storage: appdir-storage
	$(MYST) mkext2 storage/appdir storage/rootfs

rootfs-storage-blob: appdir-storage-blob
	$(MYST) mkext2 storage-blob/appdir storage-blob/rootfs

rootfs: rootfs-keyvault_identity rootfs-storage rootfs-storage-blob

test-keyvault_identity: rootfs-keyvault_identity
	./test-all-packages.sh "$(MYST_EXEC)" keyvault_identity/rootfs "$(OPTS)" keyvault_identity/packages.txt

test-storage: rootfs-storage
	./test-all-packages.sh "$(MYST_EXEC)" storage/rootfs "$(OPTS)" storage/packages.txt

test-storage-blob: rootfs-storage-blob
	./test-all-packages.sh "$(MYST_EXEC)" storage-blob/rootfs "$(OPTS)" storage-blob/packages.txt

_tests: all test-keyvault_identity test-storage test-storage-blob

tests:
	TIMEOUT=$(TIMEOUT) $(RUNTEST) make -C $(CURDIR) _tests 

clean:
	rm -rf keyvault_identity/rootfs keyvault_identity/appdir storage/rootfs storage/appdir storage-blob/rootfs storage-blob/appdir
