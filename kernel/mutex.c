#include <libos/mutex.h>
#include <openenclave/bits/result.h>

typedef struct oe_mutex oe_mutex_t;

int libos_mutex_init(libos_mutex_t* mutex)
{
    extern oe_result_t oe_mutex_init(oe_mutex_t* mutex);
    return oe_mutex_init((oe_mutex_t*)mutex) == OE_OK ? 0 : -1;
}

int libos_mutex_lock(libos_mutex_t* mutex)
{
    extern oe_result_t oe_mutex_lock(oe_mutex_t* mutex);
    return oe_mutex_lock((oe_mutex_t*)mutex) == OE_OK ? 0 : -1;
}

int libos_mutex_unlock(libos_mutex_t* mutex)
{
    extern oe_result_t oe_mutex_unlock(oe_mutex_t* mutex);
    return oe_mutex_unlock((oe_mutex_t*)mutex) == OE_OK ? 0 : -1;
}

int libos_mutex_destroy(libos_mutex_t* mutex)
{
    extern oe_result_t oe_mutex_destroy(oe_mutex_t* mutex);
    return oe_mutex_destroy((oe_mutex_t*)mutex) == OE_OK ? 0 : -1;
}
