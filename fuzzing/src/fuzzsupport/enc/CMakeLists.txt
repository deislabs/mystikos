# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(EDL_FILE ../../include/fuzzsupport.edl)
set(MUSLSRC ${OPEN_ENCLAVE_SDK_SRC}/3rdparty/musl/musl/src)

add_custom_command(
  OUTPUT fuzzsupport_t.h fuzzsupport_t.c
  DEPENDS ${EDL_FILE}
  COMMAND
    openenclave::oeedger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

set(COMMON_SRC   
  ${CMAKE_CURRENT_BINARY_DIR}/fuzzsupport_t.c
  ${MUSLSRC}/misc/nftw.c
  ${MUSLSRC}/stat/lstat.c
  ${MUSLSRC}/network/gethostbyaddr.c
  ${MUSLSRC}/network/h_errno.c
  ${MUSLSRC}/unistd/ftruncate.c
  ${MUSLSRC}/unistd/readlink.c
  ${MUSLSRC}/unistd/isatty.c
  ${MUSLSRC}/misc/syslog.c
  ${MUSLSRC}/process/posix_spawn_file_actions_init.c
  ${MUSLSRC}/process/posix_spawn_file_actions_destroy.c
  ${MUSLSRC}/signal/sigaltstack.c
  ${MUSLSRC}/sched/sched_cpucount.c
  ${MUSLSRC}/process/system.c
  ${MUSLSRC}/process/posix_spawnattr_init.c
  ${MUSLSRC}/process/posix_spawnattr_destroy.c
  ${MUSLSRC}/process/posix_spawnattr_setflags.c
  ${MUSLSRC}/signal/sigaddset.c
  ${MUSLSRC}/process/posix_spawn_file_actions_adddup2.c
  ${MUSLSRC}/misc/getauxval.c
  ${MUSLSRC}/mman/madvise.c
  ${MUSLSRC}/signal/sigismember.c
  ${MUSLSRC}/process/posix_spawnattr_setsigmask.c
  ${MUSLSRC}/misc/getrlimit.c
  ${MUSLSRC}/ldso/dlsym.c
  ${MUSLSRC}/ldso/dlerror.c
  ${MUSLSRC}/thread/clone.c
  ${MUSLSRC}/signal/restore.c
  ${MUSLSRC}/thread/pthread_attr_init.c
  ${MUSLSRC}/thread/pthread_attr_destroy.c
  ${MUSLSRC}/thread/pthread_attr_setstacksize.c
  ${MUSLSRC}/thread/default_attr.c
  ${MUSLSRC}/thread/lock_ptc.c
  ${MUSLSRC}/mman/shm_open.c
  ${MUSLSRC}/thread/pthread_getattr_np.c
  ${MUSLSRC}/mman/mremap.c
  ${MUSLSRC}/string/memset.c
  ${MUSLSRC}/thread/pthread_setcancelstate.c
  ${MUSLSRC}/thread/pthread_sigmask.c
  ${MUSLSRC}/thread/sem_init.c
  ${MUSLSRC}/thread/sem_wait.c
  ${MUSLSRC}/thread/sem_post.c
  ${MUSLSRC}/thread/sem_timedwait.c
  ${MUSLSRC}/thread/sem_trywait.c
  ${MUSLSRC}/unistd/_exit.c)

set (WARNINGS
  -mrdrnd
  -fPIE
  -fno-builtin-memcpy 
  -fno-builtin-memset 
  -ffreestanding  
  -Wno-incompatible-pointer-types
  -Wno-missing-braces
  -Wno-parentheses
  -Wno-unknown-pragmas
  -Wno-conversion
  -Wno-unused-parameter
  -Wno-sign-compare
  -Wno-unused-label
  -Wno-implicit-function-declaration
  -Wno-unused-variable
  -Wno-implicit-int
  -Wno-dangling-else
  -Wno-ignored-attributes
  -Wno-logical-op-parentheses
  -Wno-string-plus-int
  -Wno-typedef-redefinition
  -Wno-unneeded-internal-declaration)

set(COMMON_INC
  ${MYSTIKOS_SRC}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include
  ${OPEN_ENCLAVE_SDK_SRC}/build/3rdparty/musl/musl/src/include
  ${OPEN_ENCLAVE_SDK_SRC}/build/3rdparty/musl/musl/src/internal
  ${OPEN_ENCLAVE_SDK_SRC}/include
  ${OPEN_ENCLAVE_SDK_SRC}/include/openenclave
  ${OPEN_ENCLAVE_SDK_SRC}/build/output/include
  ${OPEN_ENCLAVE_SDK_SRC}/build/output/include/openenclave/libc
  ${OPEN_ENCLAVE_SDK_SRC}/build/3rdparty/musl/musl/arch/x86_64)

add_library(
  fuzzsup_enc
  STATIC
  enc.c
  syscall.c
  ${COMMON_SRC})
set_property(TARGET fuzzsup_enc PROPERTY C_STANDARD 99)
include_directories(fuzzsup_enc PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_compile_options(fuzzsup_enc PRIVATE ${WARNINGS})
target_compile_definitions(fuzzsup_enc PRIVATE OE_USE_DEBUG_MALLOC)
target_link_libraries(fuzzsup_enc PRIVATE openenclave::oelibcxx)
target_include_directories(fuzzsup_enc PRIVATE ${COMMON_INC})
