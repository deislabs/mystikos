#include <oel/mutex.h>
#include <openenclave/bits/result.h>

typedef struct oe_mutex oe_mutex_t;

int oel_mutex_init(oel_mutex_t* mutex)
{
    extern oe_result_t oe_mutex_init(oe_mutex_t* mutex);
    return oe_mutex_init((oe_mutex_t*)mutex) == OE_OK ? 0 : -1;
}

int oel_mutex_lock(oel_mutex_t* mutex)
{
    extern oe_result_t oe_mutex_lock(oe_mutex_t* mutex);
    return oe_mutex_lock((oe_mutex_t*)mutex) == OE_OK ? 0 : -1;
}

int oel_mutex_unlock(oel_mutex_t* mutex)
{
    extern oe_result_t oe_mutex_unlock(oe_mutex_t* mutex);
    return oe_mutex_unlock((oe_mutex_t*)mutex) == OE_OK ? 0 : -1;
}

int oel_mutex_destroy(oel_mutex_t* mutex)
{
    extern oe_result_t oe_mutex_destroy(oe_mutex_t* mutex);
    return oe_mutex_destroy((oe_mutex_t*)mutex) == OE_OK ? 0 : -1;
}
