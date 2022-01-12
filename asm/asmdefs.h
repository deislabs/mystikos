// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/* Align the definition of x86_64/bits/signal.h in musl */
#define MYST_MCONTEXT_R8 (0 * 8)
#define MYST_MCONTEXT_R9 (1 * 8)
#define MYST_MCONTEXT_R10 (2 * 8)
#define MYST_MCONTEXT_R11 (3 * 8)
#define MYST_MCONTEXT_R12 (4 * 8)
#define MYST_MCONTEXT_R13 (5 * 8)
#define MYST_MCONTEXT_R14 (6 * 8)
#define MYST_MCONTEXT_R15 (7 * 8)
#define MYST_MCONTEXT_RDI (8 * 8)
#define MYST_MCONTEXT_RSI (9 * 8)
#define MYST_MCONTEXT_RBP (10 * 8)
#define MYST_MCONTEXT_RBX (11 * 8)
#define MYST_MCONTEXT_RDX (12 * 8)
#define MYST_MCONTEXT_RAX (13 * 8)
#define MYST_MCONTEXT_RCX (14 * 8)
#define MYST_MCONTEXT_RSP (15 * 8)
#define MYST_MCONTEXT_RIP (16 * 8)
#define MYST_MCONTEXT_EFL (17 * 8)
#define MYST_MCONTEXT_FPREGS (23 * 8)

/* the size of red zone in bytes */
#define MYST_X86_64_ABI_REDZONE_SIZE 0x80
