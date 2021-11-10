# Pass certain signals to program
handle SIGILL nostop noprint
handle SIGUSR1 nostop noprint
handle SIGUSR2 nostop noprint
handle SIG35 nostop noprint
handle SIGABRT nostop noprint

# Demangle C++ identifiers
set print asm-demangle on

# Don't prompt for pagination
set pagination off

# Don't prompt for pending breakpoints
set breakpoint pending on

# In general, don't wait for confirmation
set confirm off

# Set exit code to default value
set $_exitcode = -1

# Run the program
run

# Return exit code to shell
printf "Exit code is %d\n", $_exitcode
quit $_exitcode
