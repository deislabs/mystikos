#ifndef _TLSCREDS_H
#define _TLSCREDS_H

#include <stdint.h>
#include <stddef.h>

int libos_gen_creds(
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out);

void libos_free_creds(
    uint8_t* cert,
    size_t cert_size,
    uint8_t* private_key,
    size_t private_key_size);

#endif /* _TLSCREDS_H */
