TOP=$(abspath ../..)
include $(TOP)/defs.mak

ifdef STRACE
OPTS = --strace
endif

APPDIR=$(CURDIR)/appdir
APPBUILDER=$(TOP)/scripts/appbuilder

ROOTFS=$(CURDIR)/rootfs

export TIMEOUT=10000

all: myst $(ROOTFS)

$(APPDIR):
	$(APPBUILDER) Dockerfile

$(ROOTFS): $(APPDIR)
	$(MYST) mkext2 $(APPDIR) $(ROOTFS)
	truncate --size=-4096 $(ROOTFS)

OPTS += --memory-size=256m

tests: all
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /azure-sdk-for-cpp/build/sdk/template/azure-template/test/azure-template-test
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /azure-sdk-for-cpp/build/sdk/core/azure-core/test/ut/azure-core-global-context-test
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /azure-sdk-for-cpp/build/sdk/keyvault/azure-security-keyvault-keys/test/ut/azure-security-keyvault-keys-test
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /azure-sdk-for-cpp/build/sdk/keyvault/azure-security-keyvault-common/test/ut/azure-security-keyvault-common-test
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /azure-sdk-for-cpp/build/sdk/identity/azure-identity/test/live/azure-identity-livetest # need AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET

	# Run partial test; the ones in the filter are disabled
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /azure-sdk-for-cpp/build/sdk/identity/azure-identity/test/ut/azure-identity-test --gtest_filter=-*ClientSecret* # timing problem
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /azure-sdk-for-cpp/build/sdk/core/azure-core/test/ut/azure-core-test --gtest_filter=-BearerTokenAuthenticationPolicy.RefreshNearExpiry:*BodyStream.Rewind:*BodyStream.BadInput:*ExpectThrow*:*Pre*ondition*:CurlConnectionPool.resiliencyOnConnectionClosed
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /azure-sdk-for-cpp/build/sdk/storage/azure-storage-test --gtest_filter=-*ExpectThrow*:*BlobClient*:*ListBlobsOtherStuff*:*SasTest:*AccountInfo:*DirectoryAccessControlRecursive:*ScheduleForDeletion:*ConcurrentUploadDownload:*ListPaths:*PathAccessControls:*FileShare*ClientTest*:*PathSetPermissions:*ConstructorsWorks:*UserDelegationKey:*ClientSecretCredentialWorks # the ones in the filter are disabled; needs fork & STANDARD_STORAGE_CONNECTION_STRING

	# FAIL OUTSIDE MYSTIKOS currently
	# $(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /azure-sdk-for-cpp/build/sdk/keyvault/azure-security-keyvault-keys/test/ut/azure-security-keyvault-keys-test-live # need AZURE_KEYVAULT_URL; only works in ubuntu
	# $(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /azure-sdk-for-cpp/build/sdk/core/azure-core/test/ut/azure-core-libcurl-test # works only in ubuntu

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) $(ROOTFS)
