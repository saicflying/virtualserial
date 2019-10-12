#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "rbtree.h"
#include "logger.h"
#include "util.h"
#include "event.h"

static int efd;
struct soe_mutex evt_tree_lock;			
static struct rb_root events_tree = RB_ROOT;
static void unregister_events(void);

struct event_info {
	event_handler_t handler;
	int fd;
	void *data;
	struct rb_node rb;
	int prio;
};

static struct epoll_event *events;
static int nr_events;

static int event_cmp(const struct event_info *e1, const struct event_info *e2)
{
	return intcmp(e1->fd, e2->fd);
}

int init_event(int nr)
{
	nr_events = nr;
	events = wcalloc(nr_events, sizeof(struct epoll_event));

	soe_init_mutex(&evt_tree_lock);
	efd = epoll_create(nr);
	if (efd < 0) {
		soe_err("failed to create epoll fd");
		return -1;
	}
	return 0;
}

void events_close()
{
	unregister_events();
	if (efd > 0) {
		close(efd);
		efd = 0;
	}	
	if (events) {
		wfree(events);
	}
}

static struct event_info *lookup_event(int fd)
{
	struct event_info key = { .fd = fd };

	return rb_search(&events_tree, &key, rb, event_cmp);
}

int register_event_prio(int fd, event_handler_t h, void *data, int prio)
{
	int ret;
	struct epoll_event ev;
	struct event_info *ei;

	ei = wzalloc(sizeof(*ei));
	ei->fd = fd;
	ei->handler = h;
	ei->data = data;
	ei->prio = prio;

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.ptr = ei;

	soe_mutex_lock(&evt_tree_lock);
	ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
	if (ret) {
		soe_err("failed to add epoll event for fd %d: %m", fd);
		wfree(ei);
	} else
		rb_insert(&events_tree, ei, rb, event_cmp);

	soe_mutex_unlock(&evt_tree_lock);
	soe_info("register_event:%d", fd);
	return ret;
}

void unregister_event(int fd)
{
	int ret;
	struct event_info *ei;

	soe_mutex_lock(&evt_tree_lock);
	ei = lookup_event(fd);
	if (!ei) {
		soe_mutex_unlock(&evt_tree_lock);
		return;
	}

	soe_info("unregister_event:%d", fd);
	ret = epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
	if (ret)
		soe_err("failed to delete epoll event for fd %d: %m", fd);

	rb_erase(&ei->rb, &events_tree);
	wfree(ei);

	soe_mutex_unlock(&evt_tree_lock);
	/*
	 * Although ei is no longer valid pointer, ei->handler() might be about
	 * to be called in do_event_loop().  Refreshing the event loop is safe.
	 */
	event_force_refresh();

}

static  void unregister_events(void)
{
	int ret;
	struct event_info *ei;
	struct rb_node * tmpp, *tmpn;
	soe_mutex_lock(&evt_tree_lock);
	rb_for_each_entry(ei, tmpp, tmpn, &events_tree, rb) {
		ret = epoll_ctl(efd, EPOLL_CTL_DEL, ei->fd, NULL);
		if (ret) {
			soe_err("failed to delete epoll event for fd %d: %m", ei->fd);
		}
		rb_erase(&ei->rb, &events_tree);
		wfree(ei);
	}
	soe_mutex_unlock(&evt_tree_lock);
}

int modify_event(int fd, unsigned int new_events)
{
	int ret;
	struct epoll_event ev;
	struct event_info *ei;

	soe_mutex_lock(&evt_tree_lock);
	ei = lookup_event(fd);
	if (!ei) {
		soe_mutex_unlock(&evt_tree_lock);
		soe_err("event info for fd %d not found", fd);
		return 1;
	}
	soe_mutex_unlock(&evt_tree_lock);

	memset(&ev, 0, sizeof(ev));
	ev.events = new_events;
	ev.data.ptr = ei;

	ret = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &ev);
	if (ret) {
		soe_err("failed to modify epoll event for fd %d: %m", fd);
		return 1;
	}
	return 0;
}

static bool event_loop_refresh;

void event_force_refresh(void)
{
	event_loop_refresh = true;
}

static int epoll_event_cmp(const struct epoll_event *_a, struct epoll_event *_b)
{
	struct event_info *a, *b;

	a = (struct event_info *)_a->data.ptr;
	b = (struct event_info *)_b->data.ptr;

	/* we need sort event_info array in reverse order */
	return intcmp(b->prio, a->prio);
}

static void do_event_loop(int timeout, bool sort_with_prio)
{
	int i, nr;

refresh:
	event_loop_refresh = false;
	nr = epoll_wait(efd, events, nr_events, timeout);
	if (sort_with_prio)
		xqsort(events, nr, epoll_event_cmp);

	if (nr < 0) {
		if (errno == EINTR)
			return;
		soe_err("epoll_wait failed: %m");
		exit(1);
	} else if (nr) {
		for (i = 0; i < nr; i++) {
			struct event_info *ei;

			ei = (struct event_info *)events[i].data.ptr;
			ei->handler(ei->fd, events[i].events, ei->data);

			if (event_loop_refresh)
				goto refresh;
		}
	}
}

void event_loop(int timeout)
{
	do_event_loop(timeout, false);
}

void event_loop_prio(int timeout)
{
	do_event_loop(timeout, true);
}
