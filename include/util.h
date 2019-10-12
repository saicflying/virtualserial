#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <unistd.h>
#include <search.h>
#include <pthread.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/time.h>
#include <assert.h>
#include "list.h"

enum soe_status {
	SOE_STATUS_OK = 1,
	SOE_STATUS_WAIT,
	SOE_STATUS_SHUTDOWN,
	SOE_STATUS_KILLED,
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define container_of(ptr, type, member) ({                      \
		const typeof(((type *)0)->member) *__mptr = (ptr);      \
		(type *)((char *)__mptr - offsetof(type, member)); })
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#define __must_check            __attribute__((warn_unused_result))

#define __LOCAL(var, line) __ ## var ## line
#define _LOCAL(var, line) __LOCAL(var, line)
#define LOCAL(var) _LOCAL(var, __LINE__)

#define round_up(x, y) roundup(x, y)
#define round_down(x, y) (((x) / (y)) * (y))

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __cpu_to_be16(x) bswap_16(x)
#define __cpu_to_be32(x) bswap_32(x)
#define __cpu_to_be64(x) bswap_64(x)
#define __be16_to_cpu(x) bswap_16(x)
#define __be32_to_cpu(x) bswap_32(x)
#define __be64_to_cpu(x) bswap_64(x)
#define __cpu_to_le32(x) (x)
#else
#define __cpu_to_be16(x) (x)
#define __cpu_to_be32(x) (x)
#define __cpu_to_be64(x) (x)
#define __be16_to_cpu(x) (x)
#define __be32_to_cpu(x) (x)
#define __be64_to_cpu(x) (x)
#define __cpu_to_le32(x) bswap_32(x)
#endif

#define uninitialized_var(x) x = x

#ifndef NO_SOE_LOGGER

#include "logger.h"
#define panic(fmt, args...)                     \
	({                                              \
	 soe_emerg("PANIC: " fmt, ##args);        \
	 abort();                                \
	 })

#else

#define panic(fmt, args...)                     \
	({                                              \
	 fprintf(stderr, "PANIC: " fmt, ##args); \
	 abort();                                \
	 })

#endif

static inline int before(uint32_t seq1, uint32_t seq2)
{
	return (int32_t)(seq1 - seq2) < 0;
}

static inline int after(uint32_t seq1, uint32_t seq2)
{
	return (int32_t)(seq2 - seq1) < 0;
}

#define min(x, y) ({ \
		typeof(x) _x = (x);     \
		typeof(y) _y = (y);     \
		(void) (&_x == &_y);            \
		_x < _y ? _x : _y; })

#define max(x, y) ({ \
		typeof(x) _x = (x);     \
		typeof(y) _y = (y);     \
		(void) (&_x == &_y);            \
		_x > _y ? _x : _y; })

static inline void *zalloc(size_t size)
{
	return calloc(1, size);
}

/*
 *  * Compares two integer values
 *   *
 *    * If the first argument is larger than the second one, intcmp() returns 1.  If
 *     * two members are equal, returns 0.  Otherwise, returns -1.
 *      */
#define intcmp(x, y) \
	({                                      \
	 typeof(x) _x = (x);             \
	 typeof(y) _y = (y);             \
	 (void) (&_x == &_y);            \
	 _x < _y ? -1 : _x > _y ? 1 : 0; \
	 })


void *wmalloc(size_t size);
#define wzalloc(size) wcalloc(1, size)
void *wrealloc(void *ptr, size_t size);
void *wcalloc(size_t nmemb, size_t size);
void *wvalloc(size_t size);
char *wstrdup(const char *s);
void wfree(void * ptr);
ssize_t wread(int fd, void *buf, size_t len);
ssize_t wwrite(int fd, const void *buf, size_t len);
ssize_t wpread(int fd, void *buf, size_t count, off_t offset);
ssize_t wpwrite(int fd, const void *buf, size_t count, off_t offset);
int wmkdir(const char *pathname, mode_t mode);
int eventfd_create(void);
int eventfd_xread(int efd);
void eventfd_xwrite(int efd, int value);
void pstrcpy(char *buf, int buf_size, const char *str);
char *chomp(char *str);
bool is_numeric(const char *p);
const char *data_to_str(void *data, size_t data_length);
pid_t gettid(void);
int tkill(int tid, int sig);
bool is_xattr_enabled(const char *path);
const char *my_exe_path(void);

int split_path(const char *path, size_t nr_segs, char **segs);
void make_path(char *path, size_t size, size_t nr_segs, const char **segs);

/* a type safe version of qsort() */
#define xqsort(base, nmemb, compar)                                     \
	({                                                                      \
	 	if (nmemb > 1) {                                                \
			qsort(base, nmemb, sizeof(*(base)),                     \
	  		      (comparison_fn_t)compar);                         \
	 		assert(compar(base, base + 1) <= 0);                    \
	 	}                                                               \
	 })

/* a type safe version of bsearch() */
#define xbsearch(key, base, nmemb, compar)                              \
	({                                                                      \
	 	typeof(&(base)[0]) __ret = NULL;                                \
		if (nmemb > 0) {                                                \
		        assert(compar(key, key) == 0);                          \
	 		assert(compar(base, base) == 0);                        \
	 		__ret = bsearch(key, base, nmemb, sizeof(*(base)),      \
					(comparison_fn_t)compar);               \
	 	}                                                               \
	 	__ret;                                                          \
	 })


/*
 *  * Binary Search of the ascending sorted array. When the key is not found, this
 *   * returns the next greater position.
 *    */
#define nbsearch(key, base, nmemb, compar)                              \
	({                                                                      \
	 	typeof(key) __m,  __l = base, __r = base + nmemb - 1;           \
		int __ret;                                                      \
	 									\
	 	while(__l <= __r && likely(nmemb > 0)) {                        \
	 		__m = __l + (__r - __l) / 2;                            \
	 		__ret = compar(key, __m);                               \
			if (__ret < 0)                                          \
	 			__r = __m - 1;                                  \
	 		else if (__ret > 0)                                     \
	 			__l = __m + 1;                                  \
	 		else {                                                  \
	 			__l = __m;                                      \
	 			break;                                          \
	 		}                                                       \
	 	}                                                               \
	 	__l;                                                            \
	 })

/* a type safe version of lfind() */
#define xlfind(key, base, nmemb, compar)                                \
	({                                                                      \
	 	typeof(&(base)[0]) __ret = NULL;                                \
	 	if (nmemb > 0) {                                                \
	 		size_t __n = nmemb;                                     \
	 		assert(compar(key, key) == 0);                          \
	 		assert(compar(base, base) == 0);                        \
	 		__ret = lfind(key, base, &__n, sizeof(*(base)),         \
			 	      (comparison_fn_t)compar);                 \
	 	}                                                               \
	 	__ret;                                                          \
	 })

/*
 *  * Search 'key' in the array 'base' linearly and remove it if it found.
 *   *
 *    * If 'key' is found in 'base', this function increments *nmemb and returns
 *     * true.
 *      */
#define xlremove(key, base, nmemb, compar)                              \
	({                                                                      \
	 	bool __removed = false;                                         \
	 	typeof(&(base)[0]) __e;                                         \
					 					\
	 	__e = xlfind(key, base, *(nmemb), compar);                      \
	 	if (__e != NULL) {                                              \
	 		(*(nmemb))--;                                           \
	 		memmove(__e, __e + 1,                                   \
			 	sizeof(*(base)) * (*(nmemb) - (__e - (base)))); \
	 		__removed = true;                                       \
	 	}                                                               \
	 	__removed;                                                      \
	 })

#define SWAP(a, b) { typeof(a) tmp; tmp = a; a = b; b = tmp; }

/* urcu helpers */

/* Boolean data type which can be accessed by multiple threads */
typedef struct { volatile unsigned long val; } watomic_bool;

static inline unsigned long watomic_or(unsigned long * pval, unsigned long x)
{
	return __sync_fetch_and_or(pval, x);
}

static inline unsigned long watomic_and(unsigned long * pval, unsigned long x)
{
	return __sync_fetch_and_and(pval, x);
}

#define watomic_inc(addr) __sync_fetch_and_add((addr), 1) 
#define watomic_dec(addr) __sync_fetch_and_sub((addr), 1)
#define watomic_read(addr) (*(addr))

static inline bool watomic_is_true(watomic_bool *val)
{
	return val->val == 1;
}

/* success if the old value is false */
static inline bool watomic_set_true(watomic_bool *val)
{
	return __sync_val_compare_and_swap(&val->val, 0, 1) == 0;
}

static inline void watomic_set_false(watomic_bool *val)
{
	val->val = 0;
}

/*
 *  * refcnt_t: reference counter which can be manipulated by multiple threads
 *   * safely
 *    */

typedef struct {
	volatile int val;
} refcnt_t;

static inline void refcount_set(refcnt_t *rc, int val)
{
	rc->val = val;
}

static inline int refcount_read(refcnt_t *rc)
{
	return rc->val;
}

static inline int refcount_inc(refcnt_t *rc)
{
	return __sync_add_and_fetch(&rc->val, 1);
}

static inline int refcount_dec(refcnt_t *rc)
{
	assert(1 <= refcount_read(rc));
	return __sync_sub_and_fetch(&rc->val, 1);
}

/* wrapper for pthread_mutex */

#define SOE_MUTEX_INITIALIZER { .mutex = PTHREAD_MUTEX_INITIALIZER }

struct soe_mutex {
	pthread_mutex_t mutex;
};

static inline void soe_init_mutex(struct soe_mutex *mutex)
{
	int ret;

	do {
		ret = pthread_mutex_init(&mutex->mutex, NULL);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to initialize a lock, %s", strerror(ret));
}


static inline void soe_init_mutex_attr(struct soe_mutex *mutex,
		pthread_mutexattr_t *attr)
{
	int ret;

	do {
		ret = pthread_mutex_init(&mutex->mutex, attr);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to initialize a lock with attr, %s",
				strerror(ret));
}

static inline void soe_destroy_mutex(struct soe_mutex *mutex)
{
	int ret;

	do {
		ret = pthread_mutex_destroy(&mutex->mutex);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to destroy a lock, %s", strerror(ret));
}

static inline void soe_mutex_lock(struct soe_mutex *mutex)
{
	int ret;

	do {
		ret = pthread_mutex_lock(&mutex->mutex);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to lock for reading, %s", strerror(ret));
}

static inline int soe_mutex_trylock(struct soe_mutex *mutex)
{
	return pthread_mutex_trylock(&mutex->mutex);
}

static inline void soe_mutex_unlock(struct soe_mutex *mutex)
{
	int ret;

	do {
		ret = pthread_mutex_unlock(&mutex->mutex);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to unlock, %s", strerror(ret));
}



/* wrapper for pthread_cond */

#define SOE_COND_INITIALIZER { .cond = PTHREAD_COND_INITIALIZER }

struct soe_cond {
	pthread_cond_t cond;
};

static inline void soe_cond_init(struct soe_cond *cond)
{
	int ret;

	do {
		ret = pthread_cond_init(&cond->cond, NULL);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to initialize a lock, %s", strerror(ret));

}

static inline void soe_destroy_cond(struct soe_cond *cond)
{
	int ret;

	do {
		ret = pthread_cond_destroy(&cond->cond);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to destroy a lock, %s", strerror(ret));
}

static inline int soe_cond_signal(struct soe_cond *cond)
{
	return pthread_cond_signal(&cond->cond);
}

static inline int soe_cond_wait(struct soe_cond *cond, struct soe_mutex *mutex)
{
	return pthread_cond_wait(&cond->cond, &mutex->mutex);
}


static inline int soe_cond_wait_timeout(struct soe_cond *cond,
		struct soe_mutex *mutex, int msec)
{
	int ret;
	struct timeval now;
	struct timespec wait_time;

	gettimeofday(&now, NULL);
	wait_time.tv_sec = now.tv_sec + (msec / 1000);
	wait_time.tv_nsec = (now.tv_usec + (msec % 1000) * 1000) * 1000;
	if (wait_time.tv_nsec >= 1000000000) {
		wait_time.tv_sec += 1;
		wait_time.tv_nsec -= 1000000000;
	}
	return pthread_cond_timedwait(&cond->cond, &mutex->mutex, &wait_time);
}

static inline int soe_cond_broadcast(struct soe_cond *cond)
{
	return pthread_cond_broadcast(&cond->cond);
}




/* wrapper for pthread_rwlock */

#define SD_RW_LOCK_INITIALIZER { .rwlock = PTHREAD_RWLOCK_INITIALIZER }

struct soe_rw_lock {
	pthread_rwlock_t rwlock;
};

static inline void soe_init_rw_lock(struct soe_rw_lock *lock)
{
	int ret;

	do {
		ret = pthread_rwlock_init(&lock->rwlock, NULL);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to initialize a lock, %s", strerror(ret));
}

static inline void soe_destroy_rw_lock(struct soe_rw_lock *lock)
{
	int ret;

	do {
		ret = pthread_rwlock_destroy(&lock->rwlock);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to destroy a lock, %s", strerror(ret));
}

static inline void soe_read_lock(struct soe_rw_lock *lock)
{
	int ret;

	do {
		ret = pthread_rwlock_rdlock(&lock->rwlock);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to lock for reading, %s", strerror(ret));
}

/*
 *  * Even though POSIX manual it doesn't return EAGAIN, we indeed have met the
 *   * case that it returned EAGAIN
 *    */
static inline void soe_write_lock(struct soe_rw_lock *lock)
{
	int ret;

	do {
		ret = pthread_rwlock_wrlock(&lock->rwlock);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to lock for writing, %s", strerror(ret));
}

static inline void soe_rw_unlock(struct soe_rw_lock *lock)
{
	int ret;

	do {
		ret = pthread_rwlock_unlock(&lock->rwlock);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to unlock, %s", strerror(ret));
}

/* colors */
#define TEXT_NORMAL         "\033[0m"
#define TEXT_BOLD           "\033[1m"
#define TEXT_RED            "\033[0;31m"
#define TEXT_BOLD_RED       "\033[1;31m"
#define TEXT_GREEN          "\033[0;32m"
#define TEXT_BOLD_GREEN     "\033[1;32m"
#define TEXT_YELLOW         "\033[0;33m"
#define TEXT_BOLD_YELLOW    "\033[1;33m"
#define TEXT_BLUE           "\033[0;34m"
#define TEXT_BOLD_BLUE      "\033[1;34m"
#define TEXT_MAGENTA        "\033[0;35m"
#define TEXT_BOLD_MAGENTA   "\033[1;35m"
#define TEXT_CYAN           "\033[0;36m"
#define TEXT_BOLD_CYAN      "\033[1;36m"

#define CLEAR_SCREEN        "\033[2J"
#define RESET_CURSOR        "\033[1;1H"



static inline bool is_stdin_console(void)
{
	return isatty(STDIN_FILENO);
}

static inline bool is_stdout_console(void)
{
	return isatty(STDOUT_FILENO);
}

static inline void clear_screen(void)
{
	printf(CLEAR_SCREEN);
	printf(RESET_CURSOR);
}


#define MAX_ERRNO       4095

#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

/*
 *  * For SD, we should pass a '-SD_RES_SOME_ERROR' to ERR_PTR at first, then we
 *   * use PTR_ERR() to get the actual error code, because we use positive integer
 *    * for error code.
 *     */
static inline void * __must_check ERR_PTR(long error)
{
	assert(error < 0);
	return (void *)error;
}

static inline long __must_check PTR_ERR(const void *ptr)
{
	return -(long)ptr;
}

static inline long __must_check IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline long __must_check IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

static inline uint64_t clock_get_time(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000000000LL + (uint64_t)ts.tv_nsec;
}

uint32_t str_to_u32(const char *nptr);
uint16_t str_to_u16(const char *nptr);
int install_sighandler(int signum, void (*handler)(int, siginfo_t *, void *),bool once);
int install_crash_handler(void (*handler)(int, siginfo_t *, void *));
void reraise_crash_signal(int signo, int status);
void init_mem_leak_detection(void);
void collect_mem_leak(void);

struct soe_cache;
typedef struct soe_cache * soe_cache_t;

soe_cache_t soe_cache_init(char * name, size_t alloc_size, int maxitem);   
void soe_cache_deinit(soe_cache_t cache);
void * soe_cache_alloc(soe_cache_t cache); 
void soe_cache_dump(soe_cache_t cache);
void soe_cache_free(soe_cache_t cache, void * ptr); 
void soe_cache_cleanup(void);
#endif

