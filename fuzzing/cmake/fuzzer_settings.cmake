# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

macro (enclave_enable_fuzzing NAME)
  target_compile_options(${NAME}
    PRIVATE
    -O0 -g
    -fsanitize=enclavefuzzer,enclaveaddress
    -fsanitize-address-instrument-interceptors
    -fsanitize-coverage=trace-pc-guard
    )

  target_link_options(${NAME}
    PRIVATE
    -fsanitize=enclavefuzzer,enclaveaddress
    -fsanitize-address-instrument-interceptors
    -fsanitize-coverage=trace-pc-guard
    )
endmacro (enclave_enable_fuzzing)

macro (host_enable_fuzzing NAME)
  target_compile_options(${NAME}
    PRIVATE
    -O0 -g
    -fsanitize=fuzzer,address
    -fsanitize-coverage=trace-pc-guard
    )
  
  target_link_options(${NAME}
    PRIVATE
    -fsanitize=fuzzer,address
    -fsanitize-coverage=trace-pc-guard
    )
endmacro (host_enable_fuzzing)
