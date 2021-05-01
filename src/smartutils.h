#ifndef SMARTUTILS_H
#define SMARTUTILS_H

/*==============================================================================
 * CONVERT UTILS
 *
 * 1. From STRING to UINT16, UINT32
 * 1.1 uint8_t string_to_uint16 (const char*  string_val, uint16_t* uint16_val);
 * 1.2 uint8_t string_to_uint32 (const char*  string_val, uint32_t* uint32_val);
 *
 * 2.
 */

#include <stddef.h>
#include <stdint.h>

/**
 * @brief string_to_uint16 - Convert char* to UINT16
 * @param string_val Input C string e.g. "1234"
 * @param uint16_val Output UINT32
 * @return TRUE on success, else FALSE
 */
uint8_t string_to_uint16 (const char*  string_val, uint16_t* uint16_val);

/**
 * @brief string_to_uint - Convert char* to UINT32
 * @param string_val Input C string e.g. "1234"
 * @param uint32_val Output UINT32
 * @return TRUE on success, else FALSE
 */
uint8_t string_to_uint32 (const char*  string_val, uint32_t* uint32_val);


/*==============================================================================
 * NETWORK UTILS
 *
 * 1 IP STRING from/to UINT32
 * 1.1 uint8_t ip_string_to_uint32 (const char*  ip_string, uint32_t* ip_addr);
 */


#ifdef _WIN32
#include <winsock.h>
#else
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#endif

/**
 * @brief ip_string_to_uint - Convert human readable IPv4 address to UINT32
 * @param ip_string Input C string e.g. "192.168.0.1"
 * @param ip_addr Output IP address as UINT32
 * @return TRUE on success, else FALSE
 */
uint8_t ip_string_to_uint32 (const char*  ip_string, uint32_t* ip_addr);



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

#include <stdio.h>

#ifdef _WIN32
#include <time.h>
#include <windows.h>
#include <pthread.h>
#else
#include <sys/types.h>
#include <pthread.h>
#include <asm/errno.h>
#endif

struct thread_info_t
{
    /* Used to identify a thread. */
    pthread_t thread_id;

    /* A condition is a synchronization device that allows threads to suspend
     * execution and relinquish the processors until some predicate on shared
     * data is satisfied.
     *
     * The basic operations on conditions are: signal the condition
     * (when the predicate becomes true), and wait for the condition,
     * suspending the thread execution until another thread signals the
     * condition.
     */
    pthread_cond_t condition;

    /* A mutex is a MUTual EXclusion device, and is useful for protecting shared
     * data structures from concurrent modifications, and implementing critical
     * sections and monitors.
     *
     * A mutex has two possible states: unlocked (not owned by any thread),
     * and locked (owned by one thread).
     *
     * A mutex can never be owned by two different threads simultaneously.
     *
     * A thread attempting to lock a mutex that is already locked by another
     * thread is suspended until the owning thread unlocks the mutex first.
     */
    pthread_mutex_t mutex;
};

void error_pthread_mutex_unlock(const int unlock_rv);
void error_pthread_mutex_lock(const int lock_rv);
void error_pthread_cond_signal(const int signal_rv);
void error_pthread_setcanceltype(const int setcanceltype_rv);
void error_pthread_create(const int create_rv);
void error_pthread_cond_timedwait(const int timed_wait_rv);
void error_pthread_join(const int join_rv);
void error_clock_gettime(const int gettime_rv);


/*==============================================================================
 * TIME UTILS
 *
 * 1) From STRING to UINT16, UINT32
 * 2)
 */

#if defined(_WIN32) && !defined(_TIMEZONE_DEFINED)
#define CLOCK_REALTIME 0
struct timezone {
    int tz_minuteswest;     /* minutes west of Greenwich */
    int tz_dsttime;         /* type of DST correction */
};
#endif
int get_time_of_day(struct timeval *tv, struct timezone *tz);

#endif // SMARTUTILS_H
