# Mystikos Support for .Net

### Supported .Net and ASP.Net version
We recommend using .net 3.1 and .net 5.

### Supported Distros:
- Alpine
- Ubuntu

We recommend using official images from [mcr.microsoft.com/dotnet](https://hub.docker.com/_/microsoft-dotnet/).

### Recommended configurations

#### dotnet configurations
- Run with dotnet diagnostics disabled. This can be controlled via the `COMPlus_EnableDiagnostics` environment variable set to 0.
- If running with low memory settings, you can control dotnet's managed heap size by [`COMPlus_GCHeapHardLimit` environment variable](https://docs.microsoft.com/en-us/dotnet/core/run-time-config/garbage-collector#heap-limit).

##### Mystikos specific configurations
- `ThreadStackSize` of 256k. The default pthread stack size in Mystikos is 128k. We found System.Linq.Expressions can cause application to hang with the default 128k thread stack. More details [here](https://github.com/dotnet/runtime/issues/61757).
- For multiprocess applications, using either `dotnet exec` or .Net Process API, turn off support for `SYS_brk` with setting `NoBrk`.

Further explanation of these configs can be found [here](
https://github.com/deislabs/mystikos/blob/main/doc/sign-package.md#application-configuration-for-sgx-enclave-packaging
).

### Debugging dotnet code with lldb and SOS
myst-lldb, a lldb extension is distributed with Mystikos. This can be used to debug high level C# code.
More details [here](
https://github.com/deislabs/mystikos/tree/main/tests/dotnet-sos#readme
).

### Known limitations
- GC suspension signals are not delivered in a real-time fashion. Actively being addressed.

### Library Support
TODO
