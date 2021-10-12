#ifndef _MYST_INTERRUPT_H
#define _MYST_INTERRUPT_H

#include <unistd.h>

int myst_register_interruptable_thread(void);

int myst_unregister_interruptable_thread(void);

#endif /* _MYST_INTERRUPT_H */
