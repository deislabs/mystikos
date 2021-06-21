#ifndef _MYST_TOOLS_MYST_HOST_H
#define _MYST_TOOLS_MYST_HOST_H

// Return 1 if the process is being traced by a debugger, 0 if not being
// traced, and -errno on failure. This function searches for the "TracerPid"
// field in the "/proc/<pid>/status" file. The process is being traced if
// the "TracerPid" field has non-zero process id value.
int process_is_being_traced(void);

#endif /* _MYST_TOOLS_MYST_HOST_H */
