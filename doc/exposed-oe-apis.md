# Exposed APIs from Open Enclave SDK in Mystikos

Mystikos is linked with [Open Enclave SDK](https://openenclave.io/sdk/)
libraries. Through an extended system call interface, Mystikos is able
to expose the following set of OE APIs to user applications. Please consult
[OE API documents](https://openenclave.io/apidocs/v0.13/globals.html)
for descriptions of individual functions.

* oe_get_report_v2
* oe_free_report
* oe_get_target_info_v2
* oe_free_target_info
* oe_parse_report
* oe_verify_report
* oe_get_seal_key_by_policy_v2
* oe_get_public_key_by_policy
* oe_get_public_key
* oe_get_private_key_by_policy
* oe_get_private_key
* oe_free_key
* oe_get_seal_key_v2
* oe_free_seal_key
* oe_generate_attestation_certificate
* oe_free_attestation_certificate
* oe_verify_attestation_certificate
* oe_result_str

All the `getter` functions, such as `oe_get_report_v2` or `oe_get_seal_key_v2`
actually allocate a buffer, fill the buffer with the requested data, and return
the buffer pointer to the application. It's the application's responsibility
to free the buffer after the data are copied or no longer needed with API calls
such as `oe_free_report` or `oe_free_seal_key`.

Applications written in C/C++ can make extended syscalls to Mystikos in the
following fashion:

```c
#include <unistd.h>
#include <sys/syscall.h>

 // look up the syscall# in myst/syscallext.h
int SYS_myst_oe_get_seal_key_v2 = 1028;
int SYS_myst_oe_free_seal_key = 1029;

const uint8_t * key_info = NULL;
size_t 	key_info_size = 0;
uint8_t * 	key_buffer = NULL;
size_t 	key_buffer_size = 0;

// Fill in key_info and key_info_size if necessary

// Request the seal key through a syscall
assert(syscall(SYS_myst_oe_get_seal_key_v2, key_info, key_info_size, &key_buffer, &key_buffer_size) == 0);

// Do something with the seal key

// After we are done with the seal key, free it
syscall(SYS_myst_oe_free_seal_key, key_buffer, &key_buffer_size);
```

Applications written in higher level languages can use FFI to make such system calls.