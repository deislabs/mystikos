TOP = $(abspath $(CURDIR)/..)
include $(TOP)/defs.mak

all: 
	$(MAKE) dirs
	$(MAKE) fuzzing_targets
	$(MAKE) syscallfuzzer

DIRS = 3rdparty
.PHONY: $(DIRS)
dirs: $(DIRS)

$(DIRS):
	$(MAKE) -C $@

MYST_FUZZING_SRC = $(CURDIR)
MYST_FUZZING_BUILD = $(BUILDDIR)/myst_fuzzing
MYST_SYSCALL_FUZZER_SRC = $(CURDIR)/src/syscallfuzzer
MYST_SYSCALL_FUZZER_BUILD = $(BUILDDIR)/syscallfuzzer

fuzzing_targets: $(MYST_FUZZING_BUILD)/fuzzing_targets
syscallfuzzer: $(MYST_SYSCALL_FUZZER_BUILD)/syscallfuzzer

CLANG=${BUILDDIR}/oe-llvm-2.0/bin/clang
CLANG_CPP=${BUILDDIR}/oe-llvm-2.0/bin/clang++

FUZZ_TARGET_OPTS += \
	-DCMAKE_PREFIX_PATH="${BUILDDIR}/openenclave)" \
	-DCMAKE_BUILD_TYPE=Debug \
	-DCMAKE_C_FLAGS_DEBUG="-O0 -g" \
	-DCMAKE_CXX_FLAGS_DEBUG="-O0 -g" \
	-DCMAKE_C_COMPILER="$(CLANG)" \
	-DCMAKE_CXX_COMPILER="$(CLANG_CPP)"

$(MYST_FUZZING_BUILD)/fuzzing_targets:
	rm -rf $(MYST_FUZZING_BUILD)
	mkdir -p $(MYST_FUZZING_BUILD)
	( cd $(MYST_FUZZING_BUILD); \
		cmake $(FUZZ_TARGET_OPTS) $(MYST_FUZZING_SRC) )
	$(MAKE) -C $(MYST_FUZZING_BUILD)

SYSCALL_FUZZER_OPTS = \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_C_COMPILER="gcc" \
	-DCMAKE_CXX_COMPILER="g++"

$(MYST_SYSCALL_FUZZER_BUILD)/syscallfuzzer:
	rm -rf $(MYST_SYSCALL_FUZZER_BUILD)
	mkdir -p $(MYST_SYSCALL_FUZZER_BUILD)
	( cd $(MYST_SYSCALL_FUZZER_BUILD); \
		cmake $(SYSCALL_FUZZER_OPTS) $(MYST_SYSCALL_FUZZER_SRC) )
	$(MAKE) -C $(MYST_SYSCALL_FUZZER_BUILD)

clean:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )
	rm -rf $(MYST_FUZZING_BUILD)
	rm -rf $(MYST_SYSCALL_FUZZER_BUILD)

distclean: clean
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) distclean $(NL) )
