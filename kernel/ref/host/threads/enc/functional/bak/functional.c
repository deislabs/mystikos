#include "test.h"

void test_functional(void)
{
    extern int argv_main(void);
    t_status = 0;
    printf("=== running argv_main\n");
    OE_TEST(argv_main() == 0);

    extern int basename_main(void);
    t_status = 0;
    printf("=== running basename_main\n");
    OE_TEST(basename_main() == 0);

    extern int clocale_mbfuncs_main(void);
    t_status = 0;
    printf("=== running clocale_mbfuncs_main\n");
    OE_TEST(clocale_mbfuncs_main() == 0);

    extern int clock_gettime_main(void);
    t_status = 0;
    printf("=== running clock_gettime_main\n");
    OE_TEST(clock_gettime_main() == 0);

    extern int crypt_main(void);
    t_status = 0;
    printf("=== running crypt_main\n");
    OE_TEST(crypt_main() == 0);

    extern int dirname_main(void);
    t_status = 0;
    printf("=== running dirname_main\n");
    OE_TEST(dirname_main() == 0);

#if 0
    extern int dlopen_main(void);
    t_status = 0;
    printf("=== running dlopen_main\n");
    OE_TEST(dlopen_main() == 0);
#endif

#if 0
    extern int dlopen_dso_main(void);
    t_status = 0;
    printf("=== running dlopen_dso_main\n");
    OE_TEST(dlopen_dso_main() == 0);
#endif

    extern int env_main(void);
    t_status = 0;
    printf("=== running env_main\n");
    OE_TEST(env_main() == 0);

    extern int fcntl_main(void);
    t_status = 0;
    printf("=== running fcntl_main\n");
    OE_TEST(fcntl_main() == 0);

    extern int fdopen_main(void);
    t_status = 0;
    printf("=== running fdopen_main\n");
    OE_TEST(fdopen_main() == 0);

    extern int fnmatch_main(void);
    t_status = 0;
    printf("=== running fnmatch_main\n");
    OE_TEST(fnmatch_main() == 0);

    extern int fscanf_main(void);
    t_status = 0;
    printf("=== running fscanf_main\n");
    OE_TEST(fscanf_main() == 0);

    extern int fwscanf_main(void);
    t_status = 0;
    printf("=== running fwscanf_main\n");
    OE_TEST(fwscanf_main() == 0);

    extern int iconv_open_main(void);
    t_status = 0;
    printf("=== running iconv_open_main\n");
    OE_TEST(iconv_open_main() == 0);

    extern int inet_pton_main(void);
    t_status = 0;
    printf("=== running inet_pton_main\n");
    OE_TEST(inet_pton_main() == 0);

    extern int ipc_msg_main(void);
    t_status = 0;
    printf("=== running ipc_msg_main\n");
    OE_TEST(ipc_msg_main() == 0);

    extern int ipc_sem_main(void);
    t_status = 0;
    printf("=== running ipc_sem_main\n");
    OE_TEST(ipc_sem_main() == 0);

    extern int ipc_shm_main(void);
    t_status = 0;
    printf("=== running ipc_shm_main\n");
    OE_TEST(ipc_shm_main() == 0);

    extern int mbc_main(void);
    t_status = 0;
    printf("=== running mbc_main\n");
    OE_TEST(mbc_main() == 0);

    extern int memstream_main(void);
    t_status = 0;
    printf("=== running memstream_main\n");
    OE_TEST(memstream_main() == 0);

    extern int popen_main(void);
    t_status = 0;
    printf("=== running popen_main\n");
    OE_TEST(popen_main() == 0);

    extern int pthread_cancel_main(void);
    t_status = 0;
    printf("=== running pthread_cancel_main\n");
    OE_TEST(pthread_cancel_main() == 0);

    extern int pthread_cancel_points_main(void);
    t_status = 0;
    printf("=== running pthread_cancel_points_main\n");
    OE_TEST(pthread_cancel_points_main() == 0);

    extern int pthread_cond_main(void);
    t_status = 0;
    printf("=== running pthread_cond_main\n");
    OE_TEST(pthread_cond_main() == 0);

    extern int pthread_mutex_main(void);
    t_status = 0;
    printf("=== running pthread_mutex_main\n");
    OE_TEST(pthread_mutex_main() == 0);

    extern int pthread_mutex_pi_main(void);
    t_status = 0;
    printf("=== running pthread_mutex_pi_main\n");
    OE_TEST(pthread_mutex_pi_main() == 0);

    extern int pthread_robust_main(void);
    t_status = 0;
    printf("=== running pthread_robust_main\n");
    OE_TEST(pthread_robust_main() == 0);

    extern int pthread_tsd_main(void);
    t_status = 0;
    printf("=== running pthread_tsd_main\n");
    OE_TEST(pthread_tsd_main() == 0);

    extern int qsort_main(void);
    t_status = 0;
    printf("=== running qsort_main\n");
    OE_TEST(qsort_main() == 0);

    extern int random_main(void);
    t_status = 0;
    printf("=== running random_main\n");
    OE_TEST(random_main() == 0);

    extern int search_hsearch_main(void);
    t_status = 0;
    printf("=== running search_hsearch_main\n");
    OE_TEST(search_hsearch_main() == 0);

    extern int search_insque_main(void);
    t_status = 0;
    printf("=== running search_insque_main\n");
    OE_TEST(search_insque_main() == 0);

    extern int search_lsearch_main(void);
    t_status = 0;
    printf("=== running search_lsearch_main\n");
    OE_TEST(search_lsearch_main() == 0);

    extern int search_tsearch_main(void);
    t_status = 0;
    printf("=== running search_tsearch_main\n");
    OE_TEST(search_tsearch_main() == 0);

    extern int sem_init_main(void);
    t_status = 0;
    printf("=== running sem_init_main\n");
    OE_TEST(sem_init_main() == 0);

    extern int sem_open_main(void);
    t_status = 0;
    printf("=== running sem_open_main\n");
    OE_TEST(sem_open_main() == 0);

    extern int setjmp_main(void);
    t_status = 0;
    printf("=== running setjmp_main\n");
    OE_TEST(setjmp_main() == 0);

    extern int snprintf_main(void);
    t_status = 0;
    printf("=== running snprintf_main\n");
    OE_TEST(snprintf_main() == 0);

    extern int socket_main(void);
    t_status = 0;
    printf("=== running socket_main\n");
    OE_TEST(socket_main() == 0);

    extern int spawn_main(void);
    t_status = 0;
    printf("=== running spawn_main\n");
    OE_TEST(spawn_main() == 0);

    extern int sscanf_main(void);
    t_status = 0;
    printf("=== running sscanf_main\n");
    OE_TEST(sscanf_main() == 0);

    extern int sscanf_long_main(void);
    t_status = 0;
    printf("=== running sscanf_long_main\n");
    OE_TEST(sscanf_long_main() == 0);

    extern int stat_main(void);
    t_status = 0;
    printf("=== running stat_main\n");
    OE_TEST(stat_main() == 0);

    extern int strftime_main(void);
    t_status = 0;
    printf("=== running strftime_main\n");
    OE_TEST(strftime_main() == 0);

    extern int string_main(void);
    t_status = 0;
    printf("=== running string_main\n");
    OE_TEST(string_main() == 0);

    extern int string_memcpy_main(void);
    t_status = 0;
    printf("=== running string_memcpy_main\n");
    OE_TEST(string_memcpy_main() == 0);

    extern int string_memmem_main(void);
    t_status = 0;
    printf("=== running string_memmem_main\n");
    OE_TEST(string_memmem_main() == 0);

    extern int string_memset_main(void);
    t_status = 0;
    printf("=== running string_memset_main\n");
    OE_TEST(string_memset_main() == 0);

    extern int string_strchr_main(void);
    t_status = 0;
    printf("=== running string_strchr_main\n");
    OE_TEST(string_strchr_main() == 0);

    extern int string_strcspn_main(void);
    t_status = 0;
    printf("=== running string_strcspn_main\n");
    OE_TEST(string_strcspn_main() == 0);

    extern int string_strstr_main(void);
    t_status = 0;
    printf("=== running string_strstr_main\n");
    OE_TEST(string_strstr_main() == 0);

    extern int strptime_main(void);
    t_status = 0;
    printf("=== running strptime_main\n");
    OE_TEST(strptime_main() == 0);

    extern int strtod_main(void);
    t_status = 0;
    printf("=== running strtod_main\n");
    OE_TEST(strtod_main() == 0);

    extern int strtod_long_main(void);
    t_status = 0;
    printf("=== running strtod_long_main\n");
    OE_TEST(strtod_long_main() == 0);

    extern int strtod_simple_main(void);
    t_status = 0;
    printf("=== running strtod_simple_main\n");
    OE_TEST(strtod_simple_main() == 0);

    extern int strtof_main(void);
    t_status = 0;
    printf("=== running strtof_main\n");
    OE_TEST(strtof_main() == 0);

    extern int strtol_main(void);
    t_status = 0;
    printf("=== running strtol_main\n");
    OE_TEST(strtol_main() == 0);

    extern int strtold_main(void);
    t_status = 0;
    printf("=== running strtold_main\n");
    OE_TEST(strtold_main() == 0);

    extern int swprintf_main(void);
    t_status = 0;
    printf("=== running swprintf_main\n");
    OE_TEST(swprintf_main() == 0);

#if 0
    extern int tgmath_main(void);
    t_status = 0;
    printf("=== running tgmath_main\n");
    OE_TEST(tgmath_main() == 0);
#endif

    extern int time_main(void);
    t_status = 0;
    printf("=== running time_main\n");
    OE_TEST(time_main() == 0);

    extern int tls_align_main(void);
    t_status = 0;
    printf("=== running tls_align_main\n");
    OE_TEST(tls_align_main() == 0);

    extern int tls_align_dlopen_main(void);
    t_status = 0;
    printf("=== running tls_align_dlopen_main\n");
    OE_TEST(tls_align_dlopen_main() == 0);

#if 1
    extern int tls_align_dso_main(void);
    t_status = 0;
    printf("=== running tls_align_dso_main\n");
    OE_TEST(tls_align_dso_main() == 0);
#endif

    extern int tls_init_main(void);
    t_status = 0;
    printf("=== running tls_init_main\n");
    OE_TEST(tls_init_main() == 0);

    extern int tls_init_dlopen_main(void);
    t_status = 0;
    printf("=== running tls_init_dlopen_main\n");
    OE_TEST(tls_init_dlopen_main() == 0);

#if 0
    extern int tls_init_dso_main(void);
    t_status = 0;
    printf("=== running tls_init_dso_main\n");
    OE_TEST(tls_init_dso_main() == 0);
#endif

    extern int tls_local_exec_main(void);
    t_status = 0;
    printf("=== running tls_local_exec_main\n");
    OE_TEST(tls_local_exec_main() == 0);

    extern int udiv_main(void);
    t_status = 0;
    printf("=== running udiv_main\n");
    OE_TEST(udiv_main() == 0);

    extern int ungetc_main(void);
    t_status = 0;
    printf("=== running ungetc_main\n");
    OE_TEST(ungetc_main() == 0);

    extern int utime_main(void);
    t_status = 0;
    printf("=== running utime_main\n");
    OE_TEST(utime_main() == 0);

    extern int vfork_main(void);
    t_status = 0;
    printf("=== running vfork_main\n");
    OE_TEST(vfork_main() == 0);

    extern int wcsstr_main(void);
    t_status = 0;
    printf("=== running wcsstr_main\n");
    OE_TEST(wcsstr_main() == 0);

    extern int wcstol_main(void);
    t_status = 0;
    printf("=== running wcstol_main\n");
    OE_TEST(wcstol_main() == 0);
}
