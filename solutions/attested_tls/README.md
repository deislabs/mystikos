## Attested TLS sample with oe-myst

### The enclaves

This sample launches two enclaves, one based on OpenEnclave SDK, and the other
running in oe-myst, and establishes a trusted channel between the two with
attested TLS. The OE-based enclave functions as the TLS server.

Specifically, during the TLS handshaking, the enclaves send each other a
self signed x509 certificate with an embedded SGX report. The recipient makes
sure the certificate is signed properly and conforms to the standard, and
then extracts the SGX report, and validates it, therefore ensuing the
other party is running inside an enclave.

### Requirement

This sample requires OpenEnclave SDK to be installed. Assuming it's installed
at the default location `/opt/openenclave`, we need to inform the build
environment with:

```
. /opt/openenclave/share/openenclave/openenclaverc
```

### Running the sample

As usual, use `make run` to launch the TLS server in the background, and then
launch the TLS client in the foreground. Once the two established the connection,
they both exit automatically.

We can also use `make run-host` to launch the TLS server in enclave, while
running the TLS client on Linux directly without oe-myst. This is called the
"host mode". In this mode, the client uses a pre-generated certificate to
estatblish a trusted channel with the server. Needless to say, this is an unsafe
setup and should be used only in development.


