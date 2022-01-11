# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(MUSLSRC ${MYSTIKOS_SRC}/third_party/musl/crt/musl/src)

set (WARNINGS
  -mrdrnd
  -fPIE
  -fno-builtin-memcpy)

add_library(
  fuzzsup_kernel
  STATIC
  kernel_args.c
  printfs.c
  auxlibc.cpp
  symbol.cpp
)

set_property(TARGET fuzzsup_kernel PROPERTY C_STANDARD 99)
include_directories(fuzzsup_kernel PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_compile_options(fuzzsup_kernel PRIVATE ${WARNINGS})
target_link_libraries(fuzzsup_kernel PRIVATE openenclave::oelibcxx)
target_include_directories(fuzzsup_kernel PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include
  ${OPEN_ENCLAVE_SDK_SRC}/3rdparty/libunwind/libunwind/include
  ${MYSTIKOS_SRC}/include
  ${MUSLSRC}
)
enclave_enable_fuzzing(fuzzsup_kernel)
