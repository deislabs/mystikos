.PHONY: openenclave
.PHONY: samples
.PHONY: lthread

BUILD_DIR=${CURDIR}/build

all: submodules openenclave lthread samples

submodules:
	@ git submodule update --recursive --init --progress

openenclave: $(BUILD_DIR)/include/openenclave

$(BUILD_DIR)/include/openenclave:
	$(MAKE) -C third_party/openenclave

lthread: $(BUILD_DIR)/include/lthread.h

$(BUILD_DIR)/include/lthread.h:
	$(MAKE) -C third_party/lthread
	$(MAKE) -C third_party/lthread install

samples:
	$(MAKE) -C samples

tests:
	$(MAKE) -C samples tests

clean:
	rm -rf $(BUILD_DIR)
	$(MAKE) -C third_party/openenclave clean
	$(MAKE) -C third_party/lthread clean
	$(MAKE) -C samples clean
