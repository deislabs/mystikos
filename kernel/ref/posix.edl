// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

enclave
{
    struct posix_timespec
    {
        int64_t tv_sec;
        uint64_t tv_nsec;
    };

    struct posix_sigaction
    {
        uint64_t handler;
        unsigned long flags;
        uint64_t restorer;
        unsigned mask[2];
    };

    struct posix_siginfo
    {
        uint8_t data[128];
    };

    struct posix_ucontext
    {
        uint8_t data[936];
    };

    struct posix_sigset
    {
        uint64_t data[16];
    };

    struct posix_sig_args
    {
        int sig;
        int enclave_sig;
        struct posix_siginfo siginfo;
        struct posix_ucontext ucontext;
    };

    struct posix_shared_block
    {
        struct posix_sig_args sig_args;
        int32_t futex;
        uint32_t trace;
        uint32_t kill_lock;
        uint8_t padding[3012];
    };

    trusted
    {
        public void posix_test_ecall(
            [user_check] struct posix_shared_block* shared_block,
            int tid);

        public int posix_run_thread_ecall(
            uint64_t cookie,
            int tid,
            [user_check] struct posix_shared_block* shared_block);
    };

    untrusted
    {
        int posix_start_thread_ocall(uint64_t cookie);

        int posix_nanosleep_ocall(
            [in, count=1] const struct posix_timespec* req,
            [out, count=1] struct posix_timespec* rem);

        int posix_gettid_ocall();

        int posix_getpid_ocall();

        int posix_wait_ocall(
            [user_check] int* host_uaddr,
            [in, count=1] const struct posix_timespec* timeout);

        void posix_wake_ocall([user_check] int* host_uaddr);

        int posix_wake_wait_ocall(
            [user_check] int* waiter_host_uaddr,
            [user_check] int* self_host_uaddr,
            [in, count=1] const struct posix_timespec* timeout);

        int posix_clock_gettime_ocall(
            int clk_id,
            [out, count=1] struct posix_timespec* tp);

        int posix_tkill_ocall(int tid, int sig)
            //transition_using_threads
            ;

        int posix_rt_sigaction_ocall(
            int signum,
            [in, count=1] const struct posix_sigaction* act,
            size_t sigsetsize);

        int posix_rt_sigprocmask_ocall(
            int how,
            [in, count=1] const struct posix_sigset* set,
            [out, count=1] struct posix_sigset* oldset,
            size_t sigsetsize);

        void posix_noop_ocall();

        ssize_t posix_write_ocall(
            int fd,
            [in, size=size] const void* data,
            size_t size)
            //transition_using_threads
            ;
    };
};
