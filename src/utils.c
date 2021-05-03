#include "utils.h"

/*==============================================================================
 * CONVERT UTILS
 *
 * 1. From STRING to UINT16, UINT32
 * 1.1 uint8_t string_to_uint16 (const char*  string_val, uint16_t* uint16_val);
 * 1.2 uint8_t string_to_uint32 (const char*  string_val, uint32_t* uint32_val);
 */

uint8_t string_to_uint32 (const char*  string_val, uint32_t* uint32_val)
{
    for (int i=0; string_val[i]!= '\0'; i++)
    {
        if (isdigit(string_val[i]) == 0)
            return FALSE;
    }

    *uint32_val = atoi(string_val);
    return TRUE;
}
uint8_t string_to_uint16 (const char*  string_val, uint16_t* uint16_val)
{
    for (int i=0; string_val[i]!= '\0'; i++)
    {
        if (isdigit(string_val[i]) == 0)
            return FALSE;
    }

    uint32_t val = atoi(string_val);
    if (val > 65535)
        return FALSE;
    else
        *uint16_val = (uint16_t)val;
    return TRUE;
}


/*==============================================================================
 * NETWORK UTILS
 *
 * 1 IP STRING from/to UINT32
 * 1.1 uint8_t ip_string_to_uint32 (const char*  ip_string, uint32_t* ip_addr);
 */

uint8_t ip_string_to_uint32 (const char*  ip_string, uint32_t* ip_addr)
{
    unsigned int            byte3;
    unsigned int            byte2;
    unsigned int            byte1;
    unsigned int            byte0;
    char              dummy_string[2];

    /* The dummy string with specifier %1s searches for a non-whitespace char
       * after the last number. If it is found, the result of sscanf will be 5
       * instead of 4, indicating an erroneous format of the ip-address.
       */
    if (sscanf (ip_string, "%u.%u.%u.%u%1s",
                &byte3, &byte2, &byte1, &byte0, dummy_string) == 4)
    {
        if ((byte3 < 256) && (byte2 < 256) && (byte1 < 256) && (byte0 < 256))
        {
            *ip_addr = (byte3 << 24) + (byte2 << 16) + (byte1 << 8) + byte0;
            return TRUE;
        }
    }

    return FALSE;
}

/*==============================================================================
 * THREAD UTILS
 *
 * 1. Errors
 * 1.1 void error_pthread_mutex_unlock(const int unlock_rv);
 * 1.2 void error_pthread_mutex_lock(const int lock_rv);
 * 1.3 void error_pthread_cond_signal(const int signal_rv);
 * 1.4 void error_pthread_setcanceltype(const int setcanceltype_rv);
 * 1.5 void error_pthread_create(const int create_rv);
 * 1.6 void error_pthread_cond_timedwait(const int timed_wait_rv);
 * 1.7 void error_pthread_join(const int join_rv);
 * 1.8 void error_clock_gettime(const int gettime_rv);
 *
 * 2. Examples
 * 2.1 void *worker_thread_example(void *data);
 * 2.2 int main_thread_example();
 */

void error_pthread_mutex_unlock(const int unlock_rv)
{
    fprintf(stderr, "Failed to unlock mutex.\n");
    switch (unlock_rv)
    {
    case EINVAL:
        fprintf(stderr, "The value specified by mutex does not refer to an "
                        "initialized mutex object.\n");
        break;
    case EAGAIN:
        fprintf(stderr, "The mutex could not be acquired because the maximum "
                        "number of recursive locks for mutex has been exceeded.\n");
        break;
    case EPERM:
        fprintf(stderr, "The current thread does not own the mutex.\n");
        break;
    default:
        break;
    }
}
void error_pthread_mutex_lock(const int lock_rv)
{
    fprintf(stderr, "Failed to lock mutex.\n");
    switch (lock_rv)
    {
    case EINVAL:
        fprintf(stderr, "The value specified by mutex does not refer to an "
                        "initialized mutex object or the mutex was created with the protocol attribute having the value PTHREAD_PRIO_PROTECT and the calling thread's priority is higher than the mutex's current priority ceiling.\n");
        break;
    case EAGAIN:
        fprintf(stderr, "The mutex could not be acquired because the maximum "
                        "number of recursive locks for mutex has been exceeded.\n");
        break;
    case EDEADLK:
        fprintf(stderr, "A deadlock condition was detected or the current "
                        "thread already owns the mutex.\n");
        break;
    default:
        break;
    }
}
void error_pthread_cond_signal(const int signal_rv)
{
    fprintf(stderr, "Could not signal.\n");
    if (signal_rv == EINVAL)
    {
        fprintf(stderr, "The value cond does not refer to an initialised "
                        "condition variable.\n");
    }
}
void error_pthread_setcanceltype(const int setcanceltype_rv)
{
    fprintf(stderr, "Could not change cancelability type of thread.\n");
    if (setcanceltype_rv == EINVAL)
    {
        fprintf(stderr, "Invalid value for type.\n");
    }
}
void error_pthread_create(const int create_rv)
{
    fprintf(stderr, "Could not create thread.\n");
    switch (create_rv)
    {
    case EAGAIN:
        fprintf(stderr, "Insufficient resources to create another thread or a "
                        "system-imposed limit on the number of threads was encountered.\n");
        break;
    case EINVAL:
        fprintf(stderr, "Invalid settings in attr.\n");
        break;
    case EPERM:
        fprintf(stderr, "No permission to set the scheduling policy and "
                        "parameters specified in attr.\n");
        break;
    default:
        break;
    }
}
void error_pthread_cond_timedwait(const int timed_wait_rv)
{
    fprintf(stderr, "Conditional timed wait, failed.\n");
    switch (timed_wait_rv)
    {
    case ETIMEDOUT:
        fprintf(stderr, "The time specified by abstime to "
                        "pthread_cond_timedwait() has passed.\n");
        break;
    case EINVAL:
        fprintf(stderr, "The value specified by abstime, cond or "
                        "mutex is invalid.\n");
        break;
    case EPERM:
        fprintf(stderr, "The mutex was not owned by the current thread at "
                        "the time of the call.\n");
        break;
    default:
        break;
    }
}
void error_pthread_join(const int join_rv)
{

    fprintf(stderr, "Could not join thread.\n");
    switch (join_rv)
    {
    case EINVAL:
        fprintf(stderr, "The implementation has detected that the value "
                        "specified by thread does not refer to a "
                        "joinable thread.\n");
        break;
    case ESRCH:
        fprintf(stderr, "No thread could be found corresponding to that "
                        "specified by the given thread ID.\n");
        break;
    case EDEADLK:
        fprintf(stderr, "A deadlock was detected or the value of thread "
                        "specifies the calling thread.\n");
        break;
    default:
        break;
    }
}
void error_clock_gettime(const int gettime_rv)
{
    fprintf(stderr, "Could not get time from clock.\n");
    switch (gettime_rv)
    {
    case EFAULT:
        fprintf(stderr, "tp points outside the accessible address space.\n");
        break;
    case EINVAL:
        fprintf(stderr, "The clk_id specified is not supported on this system.\n");
        break;
    case EPERM:
        fprintf(stderr, "clock_settime() does not have permission to set "
                        "the clock indicated.\n");
        break;
    default:
        break;
    }
}

/* This is the thread that will be called by pthread_create() and it will be
 * executed by the new thread.
 */
void *worker_thread_example(void *data)
{
    /* We know that the input data pointer is pointing to a thread_info_t so we
     * are casting it to the right type.
     */
    struct thread_info_t *thread_info = (struct thread_info_t *) data;

    /* We block this thread trying to lock the mutex, this way we will make sure
     * that the parent thread had enough time to call pthread_cond_timedwait().
     *
     * When the parent thread calls pthread_cond_timedwait() it will unlock the
     * mutex and this thread will be able to proceed.
     */
    const int lock_rv = pthread_mutex_lock(&(thread_info->mutex));
    if (lock_rv)
    {
        error_pthread_mutex_lock(lock_rv);
    }

    int oldtype;
    /* The pthread_setcanceltype() sets the cancelability type of the calling
     * thread to the value given in type.
     *
     * The previous cancelability type of the thread is returned in the buffer
     * pointed to by oldtype.
     *
     * The argument PTHREAD_CANCEL_ASYNCHRONOUS means that the thread can be
     * canceled at any time.
     */
    const int setcanceltype_rv = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);
    if (setcanceltype_rv)
    {
        error_pthread_setcanceltype(setcanceltype_rv);
    }

    // TODO: This is the place you should implement the functionality that is needed for this thread

    /* The pthread_cond_signal() call unblocks at least one of the threads that
     * are blocked on the specified condition variable cond (if any threads are
     * blocked on cond).
     */
    const int signal_rv = pthread_cond_signal(&(thread_info->condition));
    if (signal_rv)
    {
        error_pthread_cond_signal(signal_rv);
    }

    // The pthread_mutex_unlock() function shall release the mutex object referenced by mutex.
    const int unlock_rv = pthread_mutex_unlock(&(thread_info->mutex));
    if (unlock_rv)
    {
        error_pthread_mutex_unlock(unlock_rv);
    }
    return NULL;
}

int main_thread_example()
{
    struct thread_info_t thread_info;
    pthread_cond_init(&thread_info.condition, NULL);
    pthread_mutex_init(&thread_info.mutex, NULL);

    const int lock_rv = pthread_mutex_lock(&thread_info.mutex);
    if (lock_rv)
    {
        error_pthread_mutex_lock(lock_rv);
    }

    const int create_rv = pthread_create(
                &(thread_info.thread_id), NULL,
                &worker_thread_example, (void *) &thread_info);
    if (create_rv)
    {
        error_pthread_create(create_rv);
        const int unlock_rv = pthread_mutex_unlock(&thread_info.mutex);
        if (unlock_rv)
        {
            error_pthread_mutex_unlock(unlock_rv);
        }
    }
    else
    {
        /* timespec is a structure holding an interval broken down into seconds
         * and nanoseconds.
         */
        struct timespec max_wait = {0, 0};

        /* The clock_gettime system call has higher precision than its successor
         * the gettimeofday().
         *
         * It has the ability to request specific clocks using the clock id.
         *
         * It fills in a timespec structure with the seconds and nanosecond
         * count of the time since the Epoch (00:00 1 January, 1970 UTC).
         *
         * CLOCK_REALTIME argument represents a system-wide real-time clock.
         *
         * This clock is supported by all implementations and returns the number
         * of seconds and nanoseconds since the Epoch.
         */
        const int gettime_rv = clock_gettime(CLOCK_REALTIME, &max_wait);
        if (gettime_rv)
        {
            error_clock_gettime(gettime_rv);
        }
        max_wait.tv_sec += 2; //2 sec

        /* The pthread_cond_timedwait() function blocks on a condition variable.
         *
         * It must be called with a mutex locked by the calling thread or
         * undefined behavior results will occur.
         *
         * This function atomically releases the mutex and causes the calling
         * thread to block on the condition variable cond;
         *
         * Atomically here means "atomically with respect to access by another
         * thread to the mutex and then the condition variable".
         *
         * That is, if another thread is able to acquire the mutex after
         * the about-to-block thread has released it, then a subsequent call
         * to pthread_cond_broadcast() or pthread_cond_signal() in that
         * thread shall behave as if it were issued after the about-to-block
         * thread has blocked.
         */
        const int timed_wait_rv = pthread_cond_timedwait(&thread_info.condition, &thread_info.mutex, &max_wait);
        if (timed_wait_rv)
        {
            error_pthread_cond_timedwait(timed_wait_rv);
        }

        /* The pthread_join() function suspends execution of the calling thread
         * until the target thread terminates, unless the target thread has
         * already terminated.
         */
        const int join_rv = pthread_join(thread_info.thread_id, NULL);
        if (join_rv)
        {
            error_pthread_join(join_rv);
        }
    }
    return 0;
}



/*==============================================================================
 * TIME UTILS
 *
 * 1. int get_time_of_day(struct timeval *tv, struct timezone *tz) - This function
 *    can get the time as well as a timezone.
 */

#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif

int get_time_of_day(struct timeval *tv, struct timezone *tz)
{
#ifdef _WIN32
    FILETIME ft;
    unsigned __int64 tmpres = 0;
    static int tzflag = 0;

    if (NULL != tv)
    {
        GetSystemTimeAsFileTime(&ft);

        tmpres |= ft.dwHighDateTime;
        tmpres <<= 32;
        tmpres |= ft.dwLowDateTime;

        tmpres /= 10;  /*convert into microseconds*/
        /*converting file time to unix epoch*/
        tmpres -= DELTA_EPOCH_IN_MICROSECS;
        tv->tv_sec = (long)(tmpres / 1000000UL);
        tv->tv_usec = (long)(tmpres % 1000000UL);
    }

    if (NULL != tz)
    {
        if (!tzflag)
        {
            _tzset();
            tzflag++;
        }
        tz->tz_minuteswest = _timezone / 60;
        tz->tz_dsttime = _daylight;
    }

    return 0;
#else

    return gettimeofday(tv, tz);

#endif
}
