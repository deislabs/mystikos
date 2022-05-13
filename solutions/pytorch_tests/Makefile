TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

DOCKER_REGISTRY           = docker.io
DOCKER_ORG                = mystikos
DOCKER_IMAGE              = pytorch-test
DOCKER_FULL_NAME          = $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(DOCKER_IMAGE)
DOCKER_FILE               = Dockerfile
DOCKER_TAG                = $(PYTORCH_VERSION)

BASE_IMAGE                = python:3.9-buster
PYTORCH_VERSION           = v1.10.0
BUILD_PROGRESS            = auto
BUILD_TARGET              = test
BUILD_ARGS                = --build-arg BASE_IMAGE=$(BASE_IMAGE) \
							--build-arg PYTORCH_VERSION=$(PYTORCH_VERSION)
EXTRA_OPTIONS             = --progress=$(BUILD_PROGRESS) \
							--target $(BUILD_TARGET) \
							-t $(DOCKER_FULL_NAME):$(DOCKER_TAG) \
							$(BUILD_ARGS)

DOCKER_BUILD              = DOCKER_BUILDKIT=1 \
							docker build \
							-f $(DOCKER_FILE) \
							$(EXTRA_ARGS) .
DOCKER_RUN                = docker run --rm -it $(DOCKER_FULL_NAME):$(DOCKER_TAG)

RUN_PYTEST                = $(MYST_EXEC) rootfs $(OPTS) --app-config-path config.json /usr/local/bin/python -m pytest -v

ifdef STRACE
OPTS += --strace
endif

.PHONY: all
all: rootfs

.PHONY: image
image:
	$(DOCKER_BUILD)

.PHONY: docker-run
docker-run:
	$(DOCKER_RUN) /usr/local/bin/pytest /workspace/pytorch/test/test_autograd.py -v

.PHONY: push
push:
	docker push $(DOCKER_FULL_NAME):$(DOCKER_TAG)

appdir:
	$(APPBUILDER) -m -i $(DOCKER_FULL_NAME):$(DOCKER_TAG) -v

rootfs: appdir
	$(MYST) mkext2 appdir rootfs

.PHONY: run-test-autograd
run-test-autograd: EXCLUDE_TESTS = "not test_deep_reentrant \
and not test_no_grad_copy_sparse \
and not test_profiler_seq_nr \
and not test_record_function \
and not test_thread_shutdown"
run-test-autograd: rootfs
	$(RUN_PYTEST) /workspace/pytorch/test/test_autograd.py -k $(EXCLUDE_TESTS) 2>&1 | tee $@.out
	grep -q -E '400 passed.*68 skipped.*7 deselected.*1 xfailed' $@.out

.PHONY: run-test-autograd-thread-shutdown
run-test-autograd-thread-shutdown: rootfs
	$(RUN_PYTEST) /workspace/pytorch/test/test_autograd.py -k "test_thread_shutdown"

.PHONY: run-test-modules
run-test-modules: rootfs
	$(RUN_PYTEST) /workspace/pytorch/test/test_modules.py 2>&1 | tee $@.out
	grep -q -E '76 passed.*28 skipped' $@.out

.PHONY: run-test-nn
run-test-nn: EXCLUDE_TESTS = "not test_EmbeddingBag_empty_per_sample_weights_and_offsets_cpu_int32_int32_float32 \
and not test_EmbeddingBag_empty_per_sample_weights_and_offsets_cpu_int32_int64_float32 \
and not test_EmbeddingBag_empty_per_sample_weights_and_offsets_cpu_int64_int32_float32 \
and not test_EmbeddingBag_empty_per_sample_weights_and_offsets_cpu_int64_int64_float32 \
and not test_EmbeddingBag_per_sample_weights_and_new_offsets_cpu_int32_int32_float32 \
and not test_EmbeddingBag_per_sample_weights_and_new_offsets_cpu_int32_int64_float32 \
and not test_EmbeddingBag_per_sample_weights_and_new_offsets_cpu_int64_int32_float32 \
and not test_EmbeddingBag_per_sample_weights_and_new_offsets_cpu_int64_int64_float32 \
and not test_EmbeddingBag_per_sample_weights_and_no_offsets_cpu_int64_float32 \
and not test_EmbeddingBag_per_sample_weights_and_no_offsets_cpu_int32_float32 \
and not test_EmbeddingBag_per_sample_weights_and_offsets_cpu_int32_int32_float32 \
and not test_EmbeddingBag_per_sample_weights_and_offsets_cpu_int32_int32_float32 \
and not test_EmbeddingBag_per_sample_weights_and_offsets_cpu_int32_int64_float32 \
and not test_embedding_bag_1D_padding_idx_cpu_float32 \
and not test_EmbeddingBag_per_sample_weights_and_offsets_cpu_int64_int32_float32 \
and not test_embedding_bag_device_cpu_int32_int32_float32 \
and not test_EmbeddingBag_per_sample_weights_and_offsets_cpu_int64_int64_float32 \
and not test_embedding_bag_device_cpu_int32_int64_float32 \
and not test_embedding_bag_device_cpu_int64_int32_float32 \
and not test_embedding_bag_device_cpu_int64_int64_float32 \
and not test_embedding_bag_non_contiguous_weight_cpu_int32_int32_float32 \
and not test_embedding_bag_non_contiguous_weight_cpu_int32_int64_float32 \
and not test_embedding_bag_non_contiguous_weight_cpu_int64_int32_float32 \
and not test_embedding_bag_non_contiguous_weight_cpu_int64_int64_float32 \
and not test_EmbeddingBag_discontiguous \
and not test_EmbeddingBag_mean \
and not test_EmbeddingBag_sparse \
and not test_EmbeddingBag_sum \
and not test_share_memory \
and not test_avg_pool2d_nhwc_cpu_float32 \
and not test_avg_pool2d_nhwc_cpu_float64 \
and not test_max_pool2d_nhwc_cpu_float32 \
and not test_max_pool2d_nhwc_cpu_float64 \
and not test_cross_entropy_loss_precision \
and not test_l1_loss_correct \
and not test_GroupNorm_numeric_cpu"
run-test-nn: rootfs
	$(RUN_PYTEST) /workspace/pytorch/test/test_nn.py -k $(EXCLUDE_TESTS) 2>&1 | tee $@.out
	grep -q -E '1322 passed.*1437 skipped.*43 deselected.*3 xfailed' $@.out

.PHONY: run-test-nn-8g
run-test-nn-8g: INCLUDE_TESTS = "test_avg_pool2d_nhwc_cpu_float32 \
or test_avg_pool2d_nhwc_cpu_float64 \
or test_max_pool2d_nhwc_cpu_float32 \
or test_max_pool2d_nhwc_cpu_float64 \
or test_cross_entropy_loss_precision \
or test_l1_loss_correct \
or test_GroupNorm_numeric_cpu"
run-test-nn-8g: rootfs
	$(MYST_EXEC) rootfs $(OPTS) --app-config-path config8g.json /usr/local/bin/python -m pytest -v /workspace/pytorch/test/test_nn.py -k $(INCLUDE_TESTS)

.PHONY: run-test-ops
run-test-ops: rootfs
	$(MYST_EXEC) rootfs $(OPTS) --app-config-path config4g.json /usr/local/bin/python -m pytest -v /workspace/pytorch/test/test_ops.py 2>&1 | tee $@.out
	grep -q -E '4200 passed.*10069 skipped' $@.out

.PHONY: run-test-torch
run-test-torch: EXCLUDE_TESTS = "not test_RNG_after_pickle \
and not test_from_file \
and not test_torch_from_file"
run-test-torch: rootfs
	$(RUN_PYTEST) /workspace/pytorch/test/test_torch.py -k $(EXCLUDE_TESTS) 2>&1 | tee $@.out
	grep -q -E '693 passed.*527 skipped.*3 deselected' $@.out

.PHONY: run-core-tests
run-core-tests: run-test-autograd run-test-autograd-thread-shutdown run-test-modules run-test-nn run-test-nn-8g run-test-ops run-test-torch

.PHONY: run
_run: run-core-tests

run:
	$(RUNTEST) make -C $(CURDIR) _run

.PHONY: one
one: rootfs
	$(RUN_PYTEST) /workspace/pytorch/test/test_nn.py -s -k "test_EmbeddingBag_per_sample_weights_and_no_offsets_cpu_int64_float32"

.PHONY: gdb
gdb: rootfs
	$(MYST_GDB) --args $(MYST_EXEC) --max-affinity-cpus=1 rootfs --app-config-path config.json /usr/local/bin/python -m pytest /workspace/pytorch/test/test_autograd.py -v -s -k "test_too_many_grads"

pdb-rootfs: appdir
	wget https://raw.githubusercontent.com/deislabs/mystikos/main/scripts/mpdb.py
	cp mpdb.py appdir
	$(MYST) mkext2 appdir pdb-rootfs

.PHONY: pdb
pdb: pdb-rootfs
	$(MYST_EXEC) --max-affinity-cpus=1 rootfs --app-config-path config.json /usr/local/bin/python -m mpdb /usr/local/bin/pytest /workspace/pytorch/test/test_autograd.py -v -s -k "test_too_many_grads"

##############################################################
# Build pytorch C++ lib from github source.
# Here is the difference between two Dockerfiles,
# - Dockerfile:       install official PyTorch package.
# - Dockerfile-build: build PyTorch C++ libraries from source,
#                     used for debugging failures.
##############################################################

build-appdir: DOCKER_FILE  := $(DOCKER_FILE)-build
build-appdir: DOCKER_TAG   := $(PYTORCH_VERSION)-build
build-appdir: BUILD_TARGET := build
build-appdir: export DOCKER_BUILDKIT=1
build-appdir:
	$(APPBUILDER) -m -e '$(EXTRA_OPTIONS)' -v -d $(DOCKER_FILE) -o build-appdir

build-rootfs: build-appdir
	$(MYST) mkext2 build-appdir build-rootfs

.PHONY: build-one
build-one: build-rootfs
	$(MYST_EXEC) build-rootfs --app-config-path config.json /opt/conda/bin/python -m pytest /opt/pytorch/test/test_nn.py -v -s -k "test_EmbeddingBag_per_sample_weights_and_no_offsets_cpu_int64_float32"

#########################################################
# Run the following cmds in gdb to set breakpoint and set
# correct source directory.
#
# handle SIGILL pass nostop noprint
# handle SIG35 pass nostop noprint
# dir <mystikos root dir>
# set pagination off
# set substitute-path /opt/pytorch <$pwd>/build-appdir/opt/pytorch
# set breakpoint pending on
# break EmbeddingBag.cpp:<line>
#########################################################
.PHONY: build-gdb
build-gdb: build-rootfs
	$(MYST_GDB) --args $(MYST_EXEC) --max-affinity-cpus=1 build-rootfs --app-config-path config.json /opt/conda/bin/python -m pytest /opt/pytorch/test/test_nn.py -v -s -k "test_EmbeddingBag_per_sample_weights_and_no_offsets_cpu_int64_float32"

.PHONY: clean
clean:
	-rm -rf rootfs appdir pdb-appdir build-rootfs build-appdir *.out
