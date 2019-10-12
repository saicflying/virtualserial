
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/time.h>
#include <linux/types.h>
#include <signal.h>
#include <termios.h>
#include <ctype.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "list.h"
#include "util.h"
#include "bitops.h"
#include "work.h"
#include "event.h"

static struct soe_mutex soe_thread_lock = SOE_MUTEX_INITIALIZER;
static LIST_HEAD(soe_thread_list);

struct wq_info {
	char name[256];

	struct list_head finished_list;
	struct list_node list;

	struct soe_mutex finished_lock;

	/* workers sleep on this and signaled by work producer */
	struct soe_cond pending_cond;
	/* locked by work producer and workers */
	struct soe_mutex pending_lock;
	/* protected by pending_lock */
	struct work_queue q;

	/* protected by uatomic primitives */
	size_t nr_queued_work;

	int isclosing;	
	/* thread info */
	soe_thread_info_t thread; 
};

static int efd;
static struct soe_mutex wq_info_lock = SOE_MUTEX_INITIALIZER;
static LIST_HEAD(wq_info_list);

static void *worker_routine(void *arg);

uint64_t get_msec_time(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int create_worker_threads(struct wq_info *wi)
{
	int ret;

	ret = soe_thread_create(NULL, &wi->thread, worker_routine, wi);  
	if (ret != 0) {
		soe_err("failed to create worker thread: %m");
		return -1;
	}
	soe_info("create thread %s", wi->name);
	return 0;
}

int queue_work(struct work_queue *q, struct work *work)
{
	struct wq_info *wi = container_of(q, struct wq_info, q);
	
	if (wi->isclosing) return -EFAULT;

	watomic_inc(&wi->nr_queued_work);
	soe_mutex_lock(&wi->pending_lock);
	list_add_tail(&work->w_list, &wi->q.pending_list);
	soe_mutex_unlock(&wi->pending_lock);
	soe_cond_signal(&wi->pending_cond);
	return 0;
}

static void worker_thread_request_done(int fd, int events, void *data)
{
	struct wq_info *wi, *tmp;
	struct work *work;
	LIST_HEAD(list);

	eventfd_xread(fd);
	soe_mutex_lock(&wq_info_lock);
	list_for_each_entry(wi, tmp, &wq_info_list, list) {
		soe_mutex_lock(&wi->finished_lock);
		list_splice_init(&wi->finished_list, &list);
		soe_mutex_unlock(&wi->finished_lock);

		while (!list_empty(&list)) {
			work = list_first_entry(&list, struct work, w_list);
			list_del(&work->w_list);
			work->done(work);
			destroy_work(work);
			watomic_dec(&wi->nr_queued_work);
		}
	}
	soe_mutex_unlock(&wq_info_lock);
}

static void *worker_routine(void *arg)
{
	struct wq_info *wi = arg;
	struct work *work;
	int tid = gettid();

	set_thread_name(wi->name, 0);
	setpriority(PRIO_PROCESS, 0, -10);
	while (!soe_thread_should_stop()) {
		soe_mutex_lock(&wi->pending_lock);
		if (list_empty(&wi->q.pending_list)) {
			if (!wi->isclosing) {
				soe_cond_wait_timeout(&wi->pending_cond, &wi->pending_lock, 1000);
				soe_mutex_unlock(&wi->pending_lock);
				continue;
			} else {
				soe_mutex_unlock(&wi->pending_lock);
				break;
			}
		}

		work = list_first_entry(&wi->q.pending_list,
				       struct work, w_list);

		list_del(&work->w_list);
		soe_mutex_unlock(&wi->pending_lock);

		if (work->fn)
			work->fn(work);

		soe_mutex_lock(&wi->finished_lock);
		list_add_tail(&work->w_list, &wi->finished_list);
		soe_mutex_unlock(&wi->finished_lock);
		
		soe_cond_init(&wi->pending_cond);
		eventfd_xwrite(efd, 1);
	}
	soe_info("thread %s is exiting", wi->name);
}

void cleanup_queue(void)
{
	if (efd) {
		unregister_event(efd);
		close(efd);
	}
}

static soe_cache_t soe_cache_work_hi_prio = NULL;   
static soe_cache_t soe_cache_work_lo_prio = NULL;   

struct work *alloc_work(void *priv, int which)
{
	struct work * wk;
	if (which) {
		if (soe_cache_work_hi_prio == NULL) return NULL;
		wk = soe_cache_alloc(soe_cache_work_hi_prio);
	} else {
		if (soe_cache_work_lo_prio == NULL) return NULL;
		wk = soe_cache_alloc(soe_cache_work_lo_prio);
	}
	if (wk) {
		memset(wk, 0, sizeof(struct work));
		wk->prio = which;
		wk->priv = priv;
	}
	return wk;
}

void dump_works()
{
	soe_cache_dump(soe_cache_work_hi_prio);
	soe_cache_dump(soe_cache_work_lo_prio);
}

void destroy_work(struct work *work)
{
	if (work) {
		if (work->prio) 
			soe_cache_free(soe_cache_work_hi_prio, work);
		else
			soe_cache_free(soe_cache_work_lo_prio, work);
	}
}

int init_work_queue(void)
{
	int ret;
	
	soe_cache_work_hi_prio = soe_cache_init("workitem cache hi", sizeof(struct work), 64);
	if (soe_cache_work_hi_prio == NULL) {
		soe_err("failed to create work cache");
		return -1;
	}

	soe_cache_work_lo_prio = soe_cache_init("workitem cache lo", sizeof(struct work), 1024);
	if (soe_cache_work_lo_prio == NULL) {
		soe_err("failed to create work cache");
		return -1;
	}

	//efd = eventfd(0, EFD_NONBLOCK);
	efd = eventfd_create();
	if (efd < 0) {
		soe_err("failed to create event fd: %m");
		efd = 0;
		return -1;
	}

	ret = register_event(efd, worker_thread_request_done, NULL);
	if (ret) {
		soe_err("failed to register event fd %m");
		close(efd);
		efd = 0;
		return -1;
	}

	return 0;
}

void destroy_queue(struct work_queue * q)
{
	struct wq_info *wi = container_of(q, struct wq_info, q);
	soe_mutex_lock(&wq_info_lock);
	list_del(&wi->list);
	soe_mutex_unlock(&wq_info_lock);
	/* destroy the thread */		
	wi->isclosing = 1;
	soe_cond_signal(&wi->pending_cond);
	soe_thread_join(wi->thread);
	wfree(wi);
}

struct work_queue *create_work_queue(const char *name)
{
	int ret;
	struct wq_info *wi;

	wi = wzalloc(sizeof(*wi));
	snprintf(wi->name, sizeof(wi->name), "%s", name);

	INIT_LIST_HEAD(&wi->q.pending_list);
	INIT_LIST_HEAD(&wi->finished_list);

	soe_cond_init(&wi->pending_cond);

	soe_init_mutex(&wi->finished_lock);
	soe_init_mutex(&wi->pending_lock);

	ret = create_worker_threads(wi);
	if (ret < 0)
		goto destroy_threads;

	soe_mutex_lock(&wq_info_lock);
	list_add(&wi->list, &wq_info_list);
	soe_mutex_unlock(&wq_info_lock);

	return &wi->q;
destroy_threads:
	soe_destroy_cond(&wi->pending_cond);
	soe_destroy_mutex(&wi->pending_lock);
	soe_destroy_mutex(&wi->finished_lock);
	wfree(wi);

	return NULL;
}

bool work_queue_empty(struct work_queue *q)
{
	struct wq_info *wi = container_of(q, struct wq_info, q);

	return watomic_read(&wi->nr_queued_work) == 0;
}

struct thread_args {
	const char *name;
	void *(*start_routine)(void *);
	void *arg;
	bool show_idx;
};

static void *thread_starter(void *arg)
{
	struct thread_args *args = (struct thread_args *)arg;
	void *ret;

	set_thread_name(args->name, args->show_idx);
	ret = args->start_routine(args->arg);
	wfree(arg);

	return ret;
}

static int __soe_thread_create(const char *name, soe_thread_info_t * pthread, void *(*start_routine)(void *), void *arg,
			      bool show_idx)
{
	int ret;
	struct soe_thread_info * tinfo;
	struct thread_args *args;

	tinfo = wzalloc(sizeof(*tinfo));
	if (tinfo == NULL) {
		return -ENOMEM;	
	}

	args = wzalloc(sizeof(*args));
	if (args == NULL) {
		wfree(tinfo);
		return -ENOMEM;
	}

	args->name = name;
	args->start_routine = start_routine;
	args->arg = arg;
	args->show_idx = show_idx;

	ret = pthread_create(&tinfo->thread, NULL, thread_starter, args);
	if (ret) {
		wfree(tinfo);
		wfree(args);
	} else {
		soe_mutex_lock(&soe_thread_lock);
		list_add_tail(&tinfo->list, &soe_thread_list);
		soe_mutex_unlock(&soe_thread_lock);
		*pthread = tinfo;
	}
	return ret;
}

int soe_thread_create(const char *name, soe_thread_info_t * pthread,
		     void *(*start_routine)(void *), void *arg)
{
	return __soe_thread_create(name, pthread, start_routine, arg, false);
}

int soe_thread_create_with_idx(const char *name, soe_thread_info_t * pthread, void *(*start_routine)(void *), void *arg)
{
	return __soe_thread_create(name, pthread, start_routine, arg, true);
}

void soe_thread_join(soe_thread_info_t pthread)
{
	soe_mutex_lock(&soe_thread_lock);
	list_del(&pthread->list);
	pthread_join(pthread->thread, NULL);
	wfree(pthread);
	soe_mutex_unlock(&soe_thread_lock);
}

void soe_threads_join()
{
	soe_thread_info_t pinfo, tmp;	

	soe_mutex_lock(&soe_thread_lock);
	list_for_each_entry(pinfo, tmp, &soe_thread_list, list) {
		list_del(&pinfo->list);	
		pthread_join(pinfo->thread, NULL);
		wfree(pinfo);
	}
	soe_mutex_unlock(&soe_thread_lock);
}

static int threads_should_stop = 0; 
int soe_thread_should_stop()
{
	return threads_should_stop;
}

void soe_stop_thread()
{
	threads_should_stop = 1;
}


