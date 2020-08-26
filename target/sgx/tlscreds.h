#ifndef _TLSCREDS_H
#define _TLSCREDS_H

#include <stdint.h>
#include <stddef.h>

int libos_generate_tls_creds(
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out);

#endif /* _TLSCREDS_H */
