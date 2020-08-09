#include "test.h"

void test_regression(void)
{
    int argc = 1;
    const char* argv[] = { "main", NULL, NULL };
    const char** envp = argv + argc + 1;

#if 0
    extern int daemon_failure_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running daemon_failure_main\n");
    OE_TEST(daemon_failure_main(argc, argv, envp) == 0);
#endif

    extern int dn_expand_empty_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running dn_expand_empty_main\n");
    OE_TEST(dn_expand_empty_main(argc, argv, envp) == 0);

    extern int dn_expand_ptr_0_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running dn_expand_ptr_0_main\n");
    OE_TEST(dn_expand_ptr_0_main(argc, argv, envp) == 0);

#if 0 /* SYS_execve */
    extern int execle_env_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running execle_env_main\n");
    OE_TEST(execle_env_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int fflush_exit_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running fflush_exit_main\n");
    OE_TEST(fflush_exit_main(argc, argv, envp) == 0);
#endif

    extern int fgets_eof_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running fgets_eof_main\n");
    OE_TEST(fgets_eof_main(argc, argv, envp) == 0);

#if 0
    extern int fgetwc_buffering_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running fgetwc_buffering_main\n");
    OE_TEST(fgetwc_buffering_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int flockfile_list_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running flockfile_list_main\n");
    OE_TEST(flockfile_list_main(argc, argv, envp) == 0);
#endif

    extern int fpclassify_invalid_ld80_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running fpclassify_invalid_ld80_main\n");
    OE_TEST(fpclassify_invalid_ld80_main(argc, argv, envp) == 0);

#if 0
    extern int ftello_unflushed_append_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running ftello_unflushed_append_main\n");
    OE_TEST(ftello_unflushed_append_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int getpwnam_r_crash_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running getpwnam_r_crash_main\n");
    OE_TEST(getpwnam_r_crash_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int getpwnam_r_errno_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running getpwnam_r_errno_main\n");
    OE_TEST(getpwnam_r_errno_main(argc, argv, envp) == 0);
#endif

    extern int iconv_roundtrips_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running iconv_roundtrips_main\n");
    OE_TEST(iconv_roundtrips_main(argc, argv, envp) == 0);

    extern int inet_ntop_v4mapped_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running inet_ntop_v4mapped_main\n");
    OE_TEST(inet_ntop_v4mapped_main(argc, argv, envp) == 0);

    extern int inet_pton_empty_last_field_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running inet_pton_empty_last_field_main\n");
    OE_TEST(inet_pton_empty_last_field_main(argc, argv, envp) == 0);

    extern int iswspace_null_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running iswspace_null_main\n");
    OE_TEST(iswspace_null_main(argc, argv, envp) == 0);

    extern int lrand48_signextend_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running lrand48_signextend_main\n");
    OE_TEST(lrand48_signextend_main(argc, argv, envp) == 0);

#if 0
    extern int lseek_large_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running lseek_large_main\n");
    OE_TEST(lseek_large_main(argc, argv, envp) == 0);
#endif

    extern int malloc_0_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running malloc_0_main\n");
    OE_TEST(malloc_0_main(argc, argv, envp) == 0);

#if 0
    extern int malloc_brk_fail_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running malloc_brk_fail_main\n");
    OE_TEST(malloc_brk_fail_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int malloc_oom_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running malloc_oom_main\n");
    OE_TEST(malloc_oom_main(argc, argv, envp) == 0);
#endif

    extern int mbsrtowcs_overflow_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running mbsrtowcs_overflow_main\n");
    OE_TEST(mbsrtowcs_overflow_main(argc, argv, envp) == 0);

    extern int memmem_oob_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running memmem_oob_main\n");
    OE_TEST(memmem_oob_main(argc, argv, envp) == 0);

    extern int memmem_oob_read_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running memmem_oob_read_main\n");
    OE_TEST(memmem_oob_read_main(argc, argv, envp) == 0);

    extern int mkdtemp_failure_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running mkdtemp_failure_main\n");
    OE_TEST(mkdtemp_failure_main(argc, argv, envp) == 0);

    extern int mkstemp_failure_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running mkstemp_failure_main\n");
    OE_TEST(mkstemp_failure_main(argc, argv, envp) == 0);

    extern int printf_1e9_oob_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running printf_1e9_oob_main\n");
    OE_TEST(printf_1e9_oob_main(argc, argv, envp) == 0);

    extern int printf_fmt_g_round_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running printf_fmt_g_round_main\n");
    OE_TEST(printf_fmt_g_round_main(argc, argv, envp) == 0);

    extern int printf_fmt_g_zeros_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running printf_fmt_g_zeros_main\n");
    OE_TEST(printf_fmt_g_zeros_main(argc, argv, envp) == 0);

    extern int printf_fmt_n_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running printf_fmt_n_main\n");
    OE_TEST(printf_fmt_n_main(argc, argv, envp) == 0);

#if 0
    extern int pthread_atfork_errno_clobber_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running pthread_atfork_errno_clobber_main\n");
    OE_TEST(pthread_atfork_errno_clobber_main(argc, argv, envp) == 0);
#endif

    extern int pthread_cancel_sem_wait_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running pthread_cancel_sem_wait_main\n");
    OE_TEST(pthread_cancel_sem_wait_main(argc, argv, envp) == 0);

    extern int pthread_condattr_setclock_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running pthread_condattr_setclock_main\n");
    OE_TEST(pthread_condattr_setclock_main(argc, argv, envp) == 0);

    extern int pthread_cond_smasher_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running pthread_cond_smasher_main\n");
    OE_TEST(pthread_cond_smasher_main(argc, argv, envp) == 0);

#if 0 /* AAA */
    extern int pthread_cond_wait_cancel_ignored_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running pthread_cond_wait_cancel_ignored_main\n");
    OE_TEST(pthread_cond_wait_cancel_ignored_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int pthread_create_oom_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running pthread_create_oom_main\n");
    OE_TEST(pthread_create_oom_main(argc, argv, envp) == 0);
#endif

    extern int pthread_exit_cancel_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running pthread_exit_cancel_main\n");
    OE_TEST(pthread_exit_cancel_main(argc, argv, envp) == 0);

#if 0
    extern int pthread_exit_dtor_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running pthread_exit_dtor_main\n");
    OE_TEST(pthread_exit_dtor_main(argc, argv, envp) == 0);
#endif

    extern int pthread_once_deadlock_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running pthread_once_deadlock_main\n");
    OE_TEST(pthread_once_deadlock_main(argc, argv, envp) == 0);

#if 0 /* AAA */
    extern int pthread_robust_detach_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running pthread_robust_detach_main\n");
    OE_TEST(pthread_robust_detach_main(argc, argv, envp) == 0);
#endif

    extern int pthread_rwlock_ebusy_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running pthread_rwlock_ebusy_main\n");
    OE_TEST(pthread_rwlock_ebusy_main(argc, argv, envp) == 0);

    extern int putenv_doublefree_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running putenv_doublefree_main\n");
    OE_TEST(putenv_doublefree_main(argc, argv, envp) == 0);

#if 0 /* NEXT */
    extern int raise_race_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running raise_race_main\n");
    OE_TEST(raise_race_main(argc, argv, envp) == 0);
#endif

    extern int regex_backref_0_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running regex_backref_0_main\n");
    OE_TEST(regex_backref_0_main(argc, argv, envp) == 0);

    extern int regex_bracket_icase_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running regex_bracket_icase_main\n");
    OE_TEST(regex_bracket_icase_main(argc, argv, envp) == 0);

    extern int regexec_nosub_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running regexec_nosub_main\n");
    OE_TEST(regexec_nosub_main(argc, argv, envp) == 0);

    extern int regex_ere_backref_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running regex_ere_backref_main\n");
    OE_TEST(regex_ere_backref_main(argc, argv, envp) == 0);

    extern int regex_escaped_high_byte_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running regex_escaped_high_byte_main\n");
    OE_TEST(regex_escaped_high_byte_main(argc, argv, envp) == 0);

    extern int regex_negated_range_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running regex_negated_range_main\n");
    OE_TEST(regex_negated_range_main(argc, argv, envp) == 0);

#if 0
    extern int rewind_clear_error_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running rewind_clear_error_main\n");
    OE_TEST(rewind_clear_error_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int rlimit_open_files_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running rlimit_open_files_main\n");
    OE_TEST(rlimit_open_files_main(argc, argv, envp) == 0);
#endif

    extern int scanf_bytes_consumed_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running scanf_bytes_consumed_main\n");
    OE_TEST(scanf_bytes_consumed_main(argc, argv, envp) == 0);

    extern int scanf_match_literal_eof_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running scanf_match_literal_eof_main\n");
    OE_TEST(scanf_match_literal_eof_main(argc, argv, envp) == 0);

    extern int scanf_nullbyte_char_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running scanf_nullbyte_char_main\n");
    OE_TEST(scanf_nullbyte_char_main(argc, argv, envp) == 0);

#if 0
    extern int setenv_oom_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running setenv_oom_main\n");
    OE_TEST(setenv_oom_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int setvbuf_unget_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running setvbuf_unget_main\n");
    OE_TEST(setvbuf_unget_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int sigaltstack_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running sigaltstack_main\n");
    OE_TEST(sigaltstack_main(argc, argv, envp) == 0);
#endif

    extern int sigprocmask_internal_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running sigprocmask_internal_main\n");
    OE_TEST(sigprocmask_internal_main(argc, argv, envp) == 0);

#if 1 /* NEXT: signal recipient outside the enclave */
    extern int sigreturn_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running sigreturn_main\n");
    OE_TEST(sigreturn_main(argc, argv, envp) == 0);
#endif

    extern int sscanf_eof_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running sscanf_eof_main\n");
    OE_TEST(sscanf_eof_main(argc, argv, envp) == 0);

#if 0
    extern int statvfs_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running statvfs_main\n");
    OE_TEST(statvfs_main(argc, argv, envp) == 0);
#endif

    extern int strverscmp_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running strverscmp_main\n");
    OE_TEST(strverscmp_main(argc, argv, envp) == 0);

#if 0
    extern int syscall_sign_extend_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running syscall_sign_extend_main\n");
    OE_TEST(syscall_sign_extend_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int tls_get_new_dtv_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running tls_get_new_dtv_main\n");
    OE_TEST(tls_get_new_dtv_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int tls_get_new_dtv_dso_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running tls_get_new_dtv_dso_main\n");
    OE_TEST(tls_get_new_dtv_dso_main(argc, argv, envp) == 0);
#endif

    extern int uselocale_0_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running uselocale_0_main\n");
    OE_TEST(uselocale_0_main(argc, argv, envp) == 0);

    extern int wcsncpy_read_overflow_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running wcsncpy_read_overflow_main\n");
    OE_TEST(wcsncpy_read_overflow_main(argc, argv, envp) == 0);

    extern int wcsstr_false_negative_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running wcsstr_false_negative_main\n");
    OE_TEST(wcsstr_false_negative_main(argc, argv, envp) == 0);

}
