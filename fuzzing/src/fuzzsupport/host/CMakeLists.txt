# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(EDL_FILE ../../include/fuzzsupport.edl)

add_custom_command(
  OUTPUT fuzzsupport_u.h fuzzsupport_u.c
  DEPENDS ${EDL_FILE}
  COMMAND
    openenclave::oeedger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_library(fuzzsup_host 
              host.cpp
              ${OPEN_ENCLAVE_SDK_SRC}/host/sgx/elf.c
              fuzzsupport_u.c)

target_include_directories(fuzzsup_host 
  PUBLIC
  ${CMAKE_PREFIX_PATH}/include
  ${OPEN_ENCLAVE_SDK_SRC}/..
  ${OPEN_ENCLAVE_SDK_SRC}/include
  ${OPEN_ENCLAVE_SDK_SRC}/build/output/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include
  ${CMAKE_CURRENT_BINARY_DIR})

target_compile_options(fuzzsup_host PRIVATE -O0 -g -Wno-writable-strings)
  
target_link_libraries(fuzzsup_host PRIVATE openenclave::oehost)
host_enable_fuzzing(fuzzsup_host)
