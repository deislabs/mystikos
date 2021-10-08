TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=corerun
TEST_CASE=Loader/binding/tracing/BinderTracingTest.Basic/BinderTracingTest.Basic.dll
PACKAGE_PATH  = myst/bin/corerun

ifdef STRACE
OPTS += --strace
endif
OPTS += --app-config-path=config_3g.json

all: ext2fs build-package

# docker build time ~1hr. Using prebuilt image.
# Other docker images:
# pr1(~10k tests) tests in debug
#$(APPBUILDER) vtikoo/coreclr-tests:release
# runtime with debug symbols -
#$(APPBUILDER) vtikoo/coreclr-tests:debug3
appdir:
	# pr0(~2.7k tests) tests in release
	$(APPBUILDER) -i vtikoo/coreclr-tests:release

rootfs: appdir
	$(MYST) mkcpio appdir rootfs

ext2fs: appdir
	$(MYST) mkext2 appdir ext2fs

build-package: package.pem
	$(MYST) fssig --roothash ext2fs > roothash
	$(MYST) package-sgx --roothash=roothash package.pem config_3g.json

run-with-args:
	./test-runner.sh $(MYST_EXEC) config_1g.json 30 ext2 pr1-1g-arg1 0
	./run-single-test.sh $(MYST_EXEC) config_1g.json 30 ext2 GC/Scenarios/Dynamo/dynamo/dynamo.dll \
	"20 11"
	./run-single-test.sh $(MYST_EXEC) config_1g.json 30 ext2 GC/API/WeakReference/multipleWRs/multipleWRs.dll \
	"10000 track"
	./run-single-test.sh $(MYST_EXEC) config_1g.json 30 ext2 GC/API/WeakReference/multipleWRs_1/multipleWRs_1.dll \
	"10000 track"
	./run-single-test.sh $(MYST_EXEC) config_1g.json 30 ext2 JIT/Stress/ABI/stubs_do/stubs_do.dll \
	"--instantiatingstubs --unboxingstubs --sharedgenericunboxingstubs --num-calls 100 --max-params 5 --no-ctrlc-summary"
	./run-single-test.sh $(MYST_EXEC) config_1g.json 30 ext2 JIT/Stress/ABI/tailcalls_d/tailcalls_d.dll \
	"--tailcalls --num-calls 1000 --no-ctrlc-summary"
	./run-single-test.sh $(MYST_EXEC) config_1g.json 30 ext2 JIT/Stress/ABI/tailcalls_d/tailcalls_d.dll \
	"--tailcalls --num-calls 1000 --no-ctrlc-summary"
	./run-single-test.sh $(MYST_EXEC) config_1g.json 30 ext2 JIT/Stress/ABI/pinvokes_do/pinvokes_do.dll \
	"--pinvokes --num-calls 1000 --no-ctrlc-summary"
	./run-single-test.sh $(MYST_EXEC) config_1g.json 30 ext2 JIT/Stress/ABI/pinvokes_do/pinvokes_d.dll \
	"--pinvokes --num-calls 1000 --no-ctrlc-summary"
	./run-single-test.sh $(MYST_EXEC) config_1g.json 30 ext2 baseservices/threading/interlocked/compareexchange/compareexchangedouble/compareexchangedouble.dll \
	"/loops:100 /addVal:1.79769313486232E+304"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/interlocked/compareexchange/CompareExchangeLong/CompareExchangeLong.dll \
	"/loops:100 /addVar:-922337203685477"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/interlocked/add/CheckAddInt/CheckAddInt.dll \
	"/start:2147483647 /add:100"
	./run-single-test.sh $(MYST_EXEC) config_1g.json 30 ext2 baseservices/threading/interlocked/add/InterlockedAddLong/InterlockedAddLong.dll \
	"/loops:100 /addVal:100"
	./run-single-test.sh $(MYST_EXEC) config_1g.json 30 ext2 baseservices/threading/interlocked/add/InterlockedAddLongWithSubtract/InterlockedAddLongWithSubtract.dll \
	"/loops:10000 /addVal:1"
	./run-single-test.sh $(MYST_EXEC) config_1g.json 30 ext2 baseservices/threading/interlocked/add/InterlockedAddInt/InterlockedAddInt.dll \
	"/loops:100 /addVal:-214748"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/interlocked/add/CheckAddLong/CheckAddLong.dll \
	"/start:922337203685477 /add:100"
	./run-single-test.sh $(MYST_EXEC) config_1g.json 30 ext2 baseservices/threading/interlocked/add/interlockedaddintwithsubtract/interlockedaddintwithsubtract.dll \
	"/loops:10000 /addVal:1"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/paramthreadstart/ThreadStartUShort/ThreadStartUShort.dll "max"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/paramthreadstart/ThreadStartFloat/ThreadStartFloat.dll "max"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/paramthreadstart/ThreadStartBool/ThreadStartBool.dll "false"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/paramthreadstart/ThreadStartGenerics/ThreadStartGenerics.dll "min"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/paramthreadstart/ThreadStartString/ThreadStartString.dll "MyStringHere"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/paramthreadstart/ThreadStartDouble/ThreadStartDouble.dll "min"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/paramthreadstart/ThreadStartChar/ThreadStartChar.dll "min"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/paramthreadstart/ThreadStartULong/ThreadStartULong.dll "max"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/paramthreadstart/ThreadStartObject/ThreadStartObject.dll "\"\""
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/paramthreadstart/ThreadStartLong/ThreadStartLong.dll "min"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/paramthreadstart/ThreadStartByte/ThreadStartByte.dll "max"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/paramthreadstart/ThreadStartSByte/ThreadStartSByte.dll "min"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/semaphore/ctoropen/semaphorectorneg1/semaphorectorneg1.dll \
	"/iCount:-2147483647 /mCount:2147483647"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/semaphore/ctoropen/semaphorectorneg3/semaphorectorneg3.dll \
	"/iCount:-2147483647 /mCount:-2147483647 /semName:null"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/semaphore/ctoropen/semaphorectorneg2/semaphorectorneg2.dll \
	"/iCount:-1 /mCount:3 /semName:\" \""
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 baseservices/threading/semaphore/ctoropen/semaphorector1/semaphorector1.dll \
	"/iCount:2147483647 /mCount:2147483647"
	./run-single-test.sh $(MYST_EXEC) config_256m.json 30 ext2 Loader/regressions/polyrec/Polyrec/Polyrec.dll "4 50"

run:
	#./test-runner.sh $(PACKAGE_PATH) null null 60 package pr1-256m	# Contains 1 test that runs for 55 seconds
	#$(MAKE) run-with-args
	#./test-runner.sh $(MYST_EXEC) config_3g.json 120 ext2 pr1-3g-passed
	#./stat.sh
	./test-runner.sh $(PACKAGE_PATH) null null 480 package pr1-FAILED-137

package.pem:
	openssl genrsa -out package.pem -3 3072

clean:
	sudo rm -fr appdir ext2fs rootfs roothash myst /tmp/myst* PASSED FAILED-*

tests:
	@ $(MAKE) -s clean
	@ $(MAKE) -s all
	@ $(MAKE) -s run

##################################
#			dev targets			 #
##################################

run-ext2:
	$(MYST_EXEC) ext2fs \
	$(OPTS) \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	/coreclr-tests-all/$(TEST_CASE)

run-ext2-gdb:
	$(MYST_GDB) --args $(MYST_EXEC) ext2fs $(OPTS) \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	/coreclr-tests-all/$(TEST_CASE)

ct:
	sudo rm -fr /tmp/myst* PASSED FAILED-*
