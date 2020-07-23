.PHONY: openenclave
.PHONY: tests
.PHONY: lthread

BUILD_DIR=${CURDIR}/build

all: submodules openenclave lthread tests enclave

submodules:
	@ git submodule update --recursive --init --progress

openenclave: $(BUILD_DIR)/include/openenclave

$(BUILD_DIR)/include/openenclave:
	$(MAKE) -C third_party/openenclave

lthread: $(BUILD_DIR)/include/lthread.h

$(BUILD_DIR)/include/lthread.h:
	$(MAKE) -C third_party/lthread
	$(MAKE) -C third_party/lthread install

tests:
	$(MAKE) -C tests

tests:
	$(MAKE) -C tests tests

DIRS = enclave

enclave:
	$(MAKE) -C enclave

clean:
	rm -rf $(BUILD_DIR)
	$(MAKE) -C third_party/openenclave clean
	$(MAKE) -C third_party/lthread clean
	$(MAKE) -C tests clean
	$(MAKE) -C enclave clean
