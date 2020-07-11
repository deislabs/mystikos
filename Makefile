.PHONY: openenclave
.PHONY: samples

BUILD_DIR=${CURDIR}/build

all: submodules openenclave samples

submodules:
	@ git submodule update --recursive --init --progress

openenclave: $(BUILD_DIR)/include/openenclave

$(BUILD_DIR)/include/openenclave:
	$(MAKE) -C third_party/openenclave

samples:
	$(MAKE) -C samples

tests:
	$(MAKE) -C samples tests

clean:
	rm -rf $(BUILD_DIR)
	$(MAKE) -C third_party/openenclave clean
	$(MAKE) -C samples clean
