
Basic flow of gcov through app, CRT, kernel, enclave, to host
=============================================================

    app links libgcov.a:
        close is renamed to myst_gcov_close with objcopy tool
    CRT:
        ../gcov/gcovclient.c:
            int myst_gcov_close(int fd)
            {
                long params[6] = {(long)fd};
                return (int)myst_gcov(__FUNCTION__, params);
            }
        ../crt/enter.c:
            long myst_gcov(const char* func, long gcov_params[6])
            {
                long params[6] = {(long)func, (long)gcov_params};
                return myst_syscall(SYS_myst_gcov, params);
            }

    Kernel:
        ../kernel/syscall.c:
            case SYS_myst_gcov:
            {
                const char* func = (const char*)x1;
                long* gcov_params = (long*)x2;

                _strace(n, "func=%s gcov_params=%p", func, gcov_params);

                long ret = myst_gcov(func, gcov_params);
                BREAK(_return(n, ret));
            }
            long myst_gcov(const char* func, long gcov_params[6])
            {
                long params[6] = {(long)func, (long)gcov_params};
                return myst_tcall(MYST_TCALL_GCOV, params);
            }
    Target (enclave):
        ../target/sgx/enclave/tcall.c
            case MYST_TCALL_GCOV:
            {
                extern long myst_gcov(const char* func, long gcov_params[6]);
                const char* func = (const char*)x1;
                long* gcov_params = (long*)x2;
                return myst_gcov(func, gcov_params);
            }
        ../tools/myst/enc/gcov.c:
            long myst_gcov(const char* func, long params[6])
            {
                if (strcmp(func, "myst_gcov_close") == 0)
                {
                    int fd = (int)params[0];
                    int r;

                    if ((r = _close(fd)) < 0)
                    {
                        errno = -r;
                        return -1;
                    }

                    return 0;
                }
                else if (...)
                {
                }
            }
            static int _close(int fd)
            {
                long params[6] = {(long)fd};
                return (int)myst_handle_tcall(SYS_close, params);
            }
        ../tools/myst/enc/syscall.c:
            long myst_handle_tcall(long n, long params[6])
            {
                /* calls _close() */
            }
            static long _close(int fd)
            {
                long ret;
                RETURN(myst_close_ocall(&ret, fd));
            }
    Target (host):
            long myst_close_ocall(int fd)
            {
                return close(fd);
            }
