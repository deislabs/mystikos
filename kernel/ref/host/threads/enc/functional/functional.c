#include "test.h"

void test_functional(void)
{
    int argc = 1;
    const char* argv[] = { "main", NULL, NULL };
    const char** envp = argv + argc + 1;

    for (size_t i = 0; i < 10; i++)
    {
        extern int pthread_cancel_main(
            int argc, const char* argv[], const char* envp[]);
        t_status = 0;
        printf("=== running pthread_cancel_main\n");
        OE_TEST(pthread_cancel_main(argc, argv, envp) == 0);
    }

return;
    extern int argv_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running argv_main\n");
    OE_TEST(argv_main(argc, argv, envp) == 0);

    extern int basename_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running basename_main\n");
    OE_TEST(basename_main(argc, argv, envp) == 0);

    extern int clocale_mbfuncs_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running clocale_mbfuncs_main\n");
    OE_TEST(clocale_mbfuncs_main(argc, argv, envp) == 0);

    extern int clock_gettime_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running clock_gettime_main\n");
    OE_TEST(clock_gettime_main(argc, argv, envp) == 0);

    extern int crypt_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running crypt_main\n");
    OE_TEST(crypt_main(argc, argv, envp) == 0);

    extern int dirname_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running dirname_main\n");
    OE_TEST(dirname_main(argc, argv, envp) == 0);

#if 0
    extern int dlopen_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running dlopen_main\n");
    OE_TEST(dlopen_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int dlopen_dso_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running dlopen_dso_main\n");
    OE_TEST(dlopen_dso_main(argc, argv, envp) == 0);
#endif

    extern int env_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running env_main\n");
    OE_TEST(env_main(argc, argv, envp) == 0);

#if 0
    extern int fcntl_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running fcntl_main\n");
    OE_TEST(fcntl_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int fdopen_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running fdopen_main\n");
    OE_TEST(fdopen_main(argc, argv, envp) == 0);
#endif

    extern int fnmatch_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running fnmatch_main\n");
    OE_TEST(fnmatch_main(argc, argv, envp) == 0);

#if 0
    extern int fscanf_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running fscanf_main\n");
    OE_TEST(fscanf_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int fwscanf_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running fwscanf_main\n");
    OE_TEST(fwscanf_main(argc, argv, envp) == 0);
#endif

    extern int iconv_open_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running iconv_open_main\n");
    OE_TEST(iconv_open_main(argc, argv, envp) == 0);

    extern int inet_pton_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running inet_pton_main\n");
    OE_TEST(inet_pton_main(argc, argv, envp) == 0);

#if 0
    extern int ipc_msg_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running ipc_msg_main\n");
    OE_TEST(ipc_msg_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int ipc_sem_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running ipc_sem_main\n");
    OE_TEST(ipc_sem_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int ipc_shm_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running ipc_shm_main\n");
    OE_TEST(ipc_shm_main(argc, argv, envp) == 0);
#endif

    extern int mbc_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running mbc_main\n");
    OE_TEST(mbc_main(argc, argv, envp) == 0);

    extern int memstream_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running memstream_main\n");
    OE_TEST(memstream_main(argc, argv, envp) == 0);

#if 0
    extern int popen_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running popen_main\n");
    OE_TEST(popen_main(argc, argv, envp) == 0);
#endif

#if 0 /* SYS_open */
    extern int pthread_cancel_points_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running pthread_cancel_points_main\n");
    OE_TEST(pthread_cancel_points_main(argc, argv, envp) == 0);
#endif

    extern int pthread_cond_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running pthread_cond_main\n");
    OE_TEST(pthread_cond_main(argc, argv, envp) == 0);

    extern int pthread_mutex_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running pthread_mutex_main\n");
    OE_TEST(pthread_mutex_main(argc, argv, envp) == 0);

#if 0 /* FUTEX_LOCK_PI */
    extern int pthread_mutex_pi_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running pthread_mutex_pi_main\n");
    OE_TEST(pthread_mutex_pi_main(argc, argv, envp) == 0);
#endif

#if 0 /* FUTEX_LOCK_PI */
    extern int pthread_robust_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running pthread_robust_main\n");
    OE_TEST(pthread_robust_main(argc, argv, envp) == 0);
#endif

    extern int pthread_tsd_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running pthread_tsd_main\n");
    OE_TEST(pthread_tsd_main(argc, argv, envp) == 0);

    extern int qsort_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running qsort_main\n");
    OE_TEST(qsort_main(argc, argv, envp) == 0);

    extern int random_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running random_main\n");
    OE_TEST(random_main(argc, argv, envp) == 0);

    extern int search_hsearch_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running search_hsearch_main\n");
    OE_TEST(search_hsearch_main(argc, argv, envp) == 0);

    extern int search_insque_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running search_insque_main\n");
    OE_TEST(search_insque_main(argc, argv, envp) == 0);

    extern int search_lsearch_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running search_lsearch_main\n");
    OE_TEST(search_lsearch_main(argc, argv, envp) == 0);

    extern int search_tsearch_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running search_tsearch_main\n");
    OE_TEST(search_tsearch_main(argc, argv, envp) == 0);

    extern int sem_init_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running sem_init_main\n");
    OE_TEST(sem_init_main(argc, argv, envp) == 0);

#if 0 /* SYS_access */
    extern int sem_open_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running sem_open_main\n");
    OE_TEST(sem_open_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int setjmp_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running setjmp_main\n");
    OE_TEST(setjmp_main(argc, argv, envp) == 0);
#endif

    extern int snprintf_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running snprintf_main\n");
    OE_TEST(snprintf_main(argc, argv, envp) == 0);

#if 0 /* SYS_socket */
    extern int socket_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running socket_main\n");
    OE_TEST(socket_main(argc, argv, envp) == 0);
#endif

#if 0 /* SYS_pipe */
    extern int spawn_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running spawn_main\n");
    OE_TEST(spawn_main(argc, argv, envp) == 0);
#endif

    extern int sscanf_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running sscanf_main\n");
    OE_TEST(sscanf_main(argc, argv, envp) == 0);

    extern int sscanf_long_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running sscanf_long_main\n");
    OE_TEST(sscanf_long_main(argc, argv, envp) == 0);

#if 0
    extern int stat_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running stat_main\n");
    OE_TEST(stat_main(argc, argv, envp) == 0);
#endif

    extern int strftime_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running strftime_main\n");
    OE_TEST(strftime_main(argc, argv, envp) == 0);

    extern int string_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running string_main\n");
    OE_TEST(string_main(argc, argv, envp) == 0);

    extern int string_memcpy_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running string_memcpy_main\n");
    OE_TEST(string_memcpy_main(argc, argv, envp) == 0);

    extern int string_memmem_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running string_memmem_main\n");
    OE_TEST(string_memmem_main(argc, argv, envp) == 0);

    extern int string_memset_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running string_memset_main\n");
    OE_TEST(string_memset_main(argc, argv, envp) == 0);

    extern int string_strchr_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running string_strchr_main\n");
    OE_TEST(string_strchr_main(argc, argv, envp) == 0);

    extern int string_strcspn_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running string_strcspn_main\n");
    OE_TEST(string_strcspn_main(argc, argv, envp) == 0);

    extern int string_strstr_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running string_strstr_main\n");
    OE_TEST(string_strstr_main(argc, argv, envp) == 0);

#if 0 /* unknown */
    extern int strptime_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running strptime_main\n");
    OE_TEST(strptime_main(argc, argv, envp) == 0);
#endif

    extern int strtod_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running strtod_main\n");
    OE_TEST(strtod_main(argc, argv, envp) == 0);

    extern int strtod_long_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running strtod_long_main\n");
    OE_TEST(strtod_long_main(argc, argv, envp) == 0);

    extern int strtod_simple_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running strtod_simple_main\n");
    OE_TEST(strtod_simple_main(argc, argv, envp) == 0);

    extern int strtof_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running strtof_main\n");
    OE_TEST(strtof_main(argc, argv, envp) == 0);

    extern int strtol_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running strtol_main\n");
    OE_TEST(strtol_main(argc, argv, envp) == 0);

    extern int strtold_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running strtold_main\n");
    OE_TEST(strtold_main(argc, argv, envp) == 0);

    extern int swprintf_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running swprintf_main\n");
    OE_TEST(swprintf_main(argc, argv, envp) == 0);

#if 0
    extern int tgmath_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running tgmath_main\n");
    OE_TEST(tgmath_main(argc, argv, envp) == 0);
#endif

    extern int time_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running time_main\n");
    OE_TEST(time_main(argc, argv, envp) == 0);

    extern int tls_align_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running tls_align_main\n");
    OE_TEST(tls_align_main(argc, argv, envp) == 0);

#if 0
    extern int tls_align_dlopen_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running tls_align_dlopen_main\n");
    OE_TEST(tls_align_dlopen_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int tls_align_dso_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running tls_align_dso_main\n");
    OE_TEST(tls_align_dso_main(argc, argv, envp) == 0);
#endif

    extern int tls_init_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running tls_init_main\n");
    OE_TEST(tls_init_main(argc, argv, envp) == 0);

#if 0
    extern int tls_init_dlopen_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running tls_init_dlopen_main\n");
    OE_TEST(tls_init_dlopen_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int tls_init_dso_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running tls_init_dso_main\n");
    OE_TEST(tls_init_dso_main(argc, argv, envp) == 0);
#endif

#if 0 /* runs out of TLS */
    extern int tls_local_exec_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running tls_local_exec_main\n");
    OE_TEST(tls_local_exec_main(argc, argv, envp) == 0);
#endif

    extern int udiv_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running udiv_main\n");
    OE_TEST(udiv_main(argc, argv, envp) == 0);

#if 0 /* SYS_open */
    extern int ungetc_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running ungetc_main\n");
    OE_TEST(ungetc_main(argc, argv, envp) == 0);
#endif

#if 0 /* SYS_open */
    extern int utime_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running utime_main\n");
    OE_TEST(utime_main(argc, argv, envp) == 0);
#endif

#if 0
    extern int vfork_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running vfork_main\n");
    OE_TEST(vfork_main(argc, argv, envp) == 0);
#endif

    extern int wcsstr_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running wcsstr_main\n");
    OE_TEST(wcsstr_main(argc, argv, envp) == 0);

    extern int wcstol_main(int argc, const char* argv[], const char* envp[]);
    t_status = 0;
    printf("=== running wcstol_main\n");
    OE_TEST(wcstol_main(argc, argv, envp) == 0);
}
