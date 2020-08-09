# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../posix.edl)

add_custom_command(
    OUTPUT posix_u.h posix_u.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --untrusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(posix_host
    host.c posix.c posix_restore.S spinlock.c posix_u.c)

target_include_directories(posix_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(posix_host oehostapp)
