// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_CONFIG_H
#define _MYST_CONFIG_H

#define MYST_INTERRUPT_WITH_SIGNAL 1

#if (MYST_INTERRUPT_WITH_SIGNAL == 1)
/* ATTN: disable nanosleep() interrupt for now */
#define MYST_INTERRUPT_NANOSLEEP_WITH_SIGNAL -1
#define MYST_INTERRUPT_POLL_WITH_SIGNAL 1
#define MYST_INTERRUPT_EPOLL_WITH_SIGNAL 1
#else
#define MYST_INTERRUPT_NANOSLEEP_WITH_SIGNAL -1
#define MYST_INTERRUPT_POLL_WITH_SIGNAL -1
#define MYST_INTERRUPT_EPOLL_WITH_SIGNAL -1
#endif

#endif /* _MYST_CONFIG_H */
