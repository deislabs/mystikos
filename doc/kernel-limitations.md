# Notable Kernel limitations of Mystikos

The first hardware TEE that Mystikos based on is Intel SGX. Therefore, Mystikos
carries most limitations imposed by Intel SGX. However, we expect those
limitations can be relaxed as better hardware TEE platforms emerge, or when
Mystikos overcomes a hardware limitation with software emulation. In fact,
[SGX2](https://caslab.csl.yale.edu/workshops/hasp2016/HASP16-16_slides.pdf)
has already relaxed a few limitations imposed by SGX1, as shown below.

By and large, Mystikos implements a Linux-compatible kernel so it could
run Linux applications with little or no modifications. There are still
incompatibilities/limitations worth noting as summarized below:

| Limitation                    | Description         | Impact on | Mitigated by software |
| ------------------------------|---------------------|---------| -----------------|
| [Multi-process limitation](#limitations-arisen-from-sgxs-single-process-model) | No forking of child processes. However `posix_spawn` is supported. | Compatibility with existing applications, e.g., bash | Possible |
| [Thread limitations](#limitations-arisen-from-sgxs-thread-model) | Thread creation is slow and limited to a user setting. Thread scheduling is subject to attacks by host. | Compatibility, performance, and security | Possible with SGX2 |
| [Memory limitations](#limitations-arisen-from-sgxs-memory-model) | User stack/heap memory is limited to a user setting. Page permissions can be manipulated by host. | Compatibility and Security | Possible with SGX2 |
| [Clock limitation](#limitations-arisen-from-lack-of-access-to-time-source) | Clock ticks and resolution are controlled by host | Security | Possible but can't be entirely eliminated |
| [Exception handling limitation](#limitations-arisen-from-handling-of-hardware-exceptions-by-os) | Exception handling has to pass through host  | Performance and security | Possible with SGX2
| [Network limitation](#network-limitations)  | Networking has to pass through host | Performance and security | Possible but can't be entirely eliminated |
| [File system limitations](#file-System-limitations) | Support ramfs, hostfs, and ext2 only. Mounting of a file system has to be explicit. Changes are not always persisted. | Compatibility | Possible |

## Limitations arisen from SGX's single process model

With SGX, an enclave application runs as a single process in a single
address space. Mystikos tries to emulate a process with a thread. When we
create a child process, we actually create a child thread with proper
process specific information, including `pid`, `ppid`, `fd table`, etc.

This approach would allow child processes created with `posix_spawn` to
run alongside the parent process. Sure, there is no memory address space
separation between the processes, but the child or the parent would have
no handle to reference the other side's memory.

On the other hand, a child process created with `fork` is supposed to
share variables with the parent. It's significantly more challenging to
emulating a forked child process as a thread without underlying support
of address space separation.


## Limitations arisen from SGX's thread model

With SGX1, the number of threads running inside an enclave, i.e.,
**ethread**, has to be statically declared. Once the application starts,
no more ethreads can be dynamically created. Meanwhile, the stack size
of each ethread is also statically declared and allocated while creating
the enclave. An application attempting to create more ethreads than what
is declared will crash.

A Mystikos application declares how many user threads are needed in
config.json. A potential mitigation of the limitation is to make the setting big
enough. The caveat is that we should ensure the stack size for each ethread
is reasonable so we don't waste too much stack memory on unused threads.

When an user application calls `pthread_create`, Mystikos makes an OCALL
to the host to create a host thread, and re-enters the enclave with an
ECALL, and once inside the enclave, jump to the thread routine. The long
chain of events leads to delays and performance problems occasionally.

The security implication of using host threads is that the untrusted host
controls the thread scheduling, and may decide to starve or switch execution
order of ethreads.

The security and performance impact of this limitation can be mitigated with
an enclave-resident thread scheduler, which uses M:N mapping to map ethreads
to user application pthreads, and performs context switching between pthreads.

This limitation is likely to be relaxed when EDMM of SGX2 is officially
supported in Mystikos.

## Limitations arisen from SGX's memory model

With SGX1, the heap size of the enclave application has to be statically
declared. Once the application starts, allocating more memory than what's
declared causes a crash due to out of memory.

A Mystikos application declares how big the heap size is needed in config.json.
A potential mitigation of the limitation is to make the setting big enough.
The downside of doing that is: 1) the SGX runtime will take more time to
add/extend heap pages one by one during the initialization, and 2) The heap
size is backed by physical EPC memory of the system. If the declared heap
size is much more than the available physical EPC memory size, the application
performance is likely to suffer due to severe `EPC paging`.

Also with SGX1, the untrusted host can manipulate the page permissions at
will because the page tables are solely controlled by the host. The implies
the host can trigger page fault whenever and/or at whichever address it likes.

These limitations are likely to be relaxed when EDMM of SGX2 is officially
supported in Mystikos.

## Limitations arisen from lack of access to time source

Typically hardware time stamp counters are not available in user space. With
SGX, the enclave application runs in ring 3, therefore it's generally
forbidden to call `RDTSC` or `RDTSCP`. (They are legal inside
an enclave for processors that support SGX2, but subject to the value of
`CR4.TSD`).

Without a direct time source, Mystikos relies on a dedicated host thread that
periodically updates a clock shared by the host and the enclave. The host
decides how often to update and what's the updated value. Obviously this
has security implications.

To protect against a malicious host, Mystikos ensures the reading of the
clock is at least one over the previous reading. The clock monotonicity
is maintained this way. The host can still advance the clock with a faster
or slower speed. An application depending on trusted time should query
a trusted time server to detect such attacks.

## Limitations arisen from handling of hardware exceptions by OS

When hardware exceptions happen, the execution context is saved, and the ISR
of the kernel is invoked. This is even true for exceptions triggered by code
running inside an SGX enclave. It has to perform an `enclave exit` (`AEX`)
before invoke the kernel handler, and re-enter enclave with `AEP` after it.
This basically means the untrusted host is trusted with the confidential
execution context, e.g., the register values, when a hardware exception
occurs. It also means that the untrusted host is in the middle of the handling
loop, thus is able to withhold, manipulate, or manufacture hardware
exceptions to the enclave.

Some mitigation are possible for some hardware exceptions. For example, we
can maintain an internal page permission list inside the enclave and cross
check `#PF` exceptions coming from the host.

The security impact is likely to be mitigated when SGX2 is officially
supported in Mystikos. With SGX2, the runtime saves detailed `EXIT_INFO`
inside the enclave before `AEX`. With the detailed
`EXIT_INFO`, the enclave exception handler can detect fake hardware
exceptions from the malicious host.

## Network limitations

Mystikos relies on host networking for establishing connections and
sending/receiving packages. For SGX, the current implementation uses OCALLs
to ask the host to perform network related tasks, which adds some overheads.

Relying on host networking also introduces security concerns as the
untrusted host can eavesdrop or manipulate the network connections or
packages as it wishes. For maximum protection, we recommend applications
running with Mystikos to use
[TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security)
exclusively when communicating with peers.

## File System limitations

Mystikos only supports three types of file system:

1. **ramfs**: The default file system. Physical storage of the files are
loaded from a CPIO archive into the protected memory of TEE at runtime.
1. **ext2**: Can be opted in or out by users from the Mystikos runtime.
Physical storage of the files are on the host. Mystikos offers signature
verification, encryption, and/or integrity protection on the file system.
Host performs block-level operations on behalf of Mystikos.
1. **hostfs**: Can be opted in or out by users from the Mystikos runtime.
Physical storage of the files are on the host. Host performs file-level
operations on behalf of Mystikos.

Mounting of a particular file system has to be explicitly specified from the
command line or in the config file.

The writes to **ramfs** and **ext2** file systems are ephemeral. That is,
the changes are lost as soon as the Mystikos runtime exits. Only changes to
**hostfs** are persisted. Obviously **hostfs** has the weakest
security guarantee among the three and thus must be used with caution.

### **Continued reading**

Typically, the above mentioned limitations are reflected in the kernel
implementation of system calls. Interested readers are welcome to continue on
[notable incompatible syscalls in Mystikos](kernel-incompatible-syscalls.md).

