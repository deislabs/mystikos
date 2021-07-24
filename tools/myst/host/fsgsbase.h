#ifndef _MYST_TOOLS_MYST_HOST_FSGSBASE_H
#define _MYST_TOOLS_MYST_HOST_FSGSBASE_H

// Return zero if user-space FSGSBASE instructions are supported, which
// includes RDFSBASE, WRGSBASE, WRFSBASE, and WRGSBASE.
int test_user_space_fsgsbase(void);

/* The "myst fsgsbase" command */
int fsgsbase_action(int argc, const char* argv[]);

#endif /* _MYST_TOOLS_MYST_HOST_FSGSBASE_H */
