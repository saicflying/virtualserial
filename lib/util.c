

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/xattr.h>

#if __GLIBC__ == 2 && __GLIBC_MINOR__ >= 20
#if !defined PACKAGE && !defined PACKAGE_VERSION
#define PACKAGE "SOE"
#endif
#if CONFIG_BFD == 1
#include <bfd.h>
#endif
#endif
#include <fcntl.h>
#include <dlfcn.h>
#include <malloc.h>
#if __GLIBC__ == 2 && __GLIBC_MINOR__ >= 8
#include <sys/eventfd.h>
#endif
#include <sys/syscall.h>
#include "util.h"
#include "list.h"
#include "rbtree.h"
#include "logger.h"

static struct rb_root mem_tree = RB_ROOT;
static int mem_leak_dection = 0;
struct mem_info {
	void * ptr;	
	size_t size;
	void * caller;
	struct rb_node rb;
};

const char *my_exe_path(void)
{
        static __thread char path[PATH_MAX];
        ssize_t ret;

        if (path[0] == '\0') {
                ret = readlink("/proc/self/exe", path, sizeof(path));
                if (ret == -1)
                        panic("%m");
        }

        return path;
}

struct caller {
        void * addr;
        char *name;
};

static struct caller *callers = NULL;
static int nr_callers = 0;

static LIST_HEAD(soe_cache_list);

struct soe_cache_priv {
	clock_t alloc_time;
};

struct soe_cache {
	char name[256];
	struct soe_mutex lock;	
	struct list_head free_list; 	
	struct list_head inuse_list;
	uint32_t alloc_size;	
	uint32_t nr_free;
	uint32_t nr_total;
	uint32_t nr_max_use;

	struct list_node node;
};


soe_cache_t soe_cache_init(char * name, size_t alloc_size, int maxitem)
{
	int i;
	struct list_node *mem_node;
	soe_cache_t cache = wzalloc(sizeof(struct soe_cache));
	if (cache == NULL) {
		return NULL;
	}
	strncpy(cache->name, name, 256);
	soe_init_mutex(&cache->lock);	
	INIT_LIST_HEAD(&cache->free_list);
	INIT_LIST_HEAD(&cache->inuse_list);
	cache->nr_total = cache->nr_free = maxitem;
	cache->nr_max_use = 0;
	cache->alloc_size = alloc_size;
	for (i = 0; i < maxitem; i++) {
		mem_node = wmalloc(alloc_size + sizeof(struct list_node) + sizeof(struct soe_cache_priv));	
		if (mem_node == NULL) {
			soe_cache_deinit(cache);
			return NULL;
		}
		list_add_tail(mem_node, &cache->free_list);	
	}
	list_add_tail(&cache->node, &soe_cache_list);
	return cache;	
}

void soe_cache_deinit(soe_cache_t cache)
{
	struct list_node * pnode, *tmp;
	soe_mutex_lock(&cache->lock);
	list_for_each(pnode, tmp, &cache->free_list) {
		list_del(pnode);
		wfree(pnode);
	}
	list_for_each(pnode, tmp, &cache->inuse_list) {
		list_del(pnode);
		wfree(pnode);
	}
	soe_mutex_unlock(&cache->lock);
	list_del(&cache->node);
	wfree(cache);
}

void soe_cache_cleanup(void)
{
	soe_cache_t cache, tmp;	
	list_for_each_entry(cache, tmp, &soe_cache_list, node) {
		soe_cache_deinit(cache);
	}
}

void * soe_cache_alloc(soe_cache_t cache)
{
	void * ret_ptr;
	struct list_node *last;
	struct soe_cache_priv * priv = NULL;
	soe_mutex_lock(&cache->lock);
	if (cache->nr_free == 0) {
		soe_mutex_unlock(&cache->lock);
		return NULL;
	}
		
	last = cache->free_list.n.prev;
	list_del(last);
	list_add_tail(last, &cache->inuse_list);
	cache->nr_free--;
	soe_mutex_unlock(&cache->lock);
	
	if (cache->nr_total - cache->nr_free > cache->nr_max_use) {
		cache->nr_max_use = cache->nr_total - cache->nr_free;
		soe_info("cache %s max use %d(free:%d)", cache->name, cache->nr_max_use, cache->nr_free);
	}
	ret_ptr = (void *)(last + 1);
	priv = (struct soe_cache_priv *)((char *)ret_ptr +  cache->alloc_size);
	priv->alloc_time = times(NULL);
	return ret_ptr;
}

void soe_cache_dump(soe_cache_t cache)
{
	int count;
	struct soe_cache_priv * priv;
	struct list_node * pnode, *tmp;
	soe_mutex_lock(&cache->lock);
	soe_info("cache %s total:%d, free:%d, max:%d", cache->name, cache->nr_total, cache->nr_free, cache->nr_max_use);	
	count = 0;
	list_for_each(pnode, tmp, &cache->free_list) {
		count++;	
	}
	soe_info("cache %s free list %d", cache->name, count);
	count = 0;
	list_for_each(pnode, tmp, &cache->inuse_list) {
		priv = (struct soe_cache_priv *)((char *)pnode + sizeof(struct list_node) + cache->alloc_size);
		soe_info("cache %s inuse list alloc time %lu", cache->name, priv->alloc_time);
		count++;
	}
	soe_info("cache %s inuse list %d, cur time %lu", cache->name, count, times(NULL));
	soe_mutex_unlock(&cache->lock);
}

void soe_cache_free(soe_cache_t cache, void * ptr)
{
	struct list_node * pnode, *tmp;	
	soe_mutex_lock(&cache->lock);
	list_for_each(pnode, tmp, &cache->inuse_list) {
		if (ptr == (pnode + 1)) {
			list_del(pnode);
			cache->nr_free++;
			list_add_tail(pnode, &cache->free_list);
			break;
		}
	}
	soe_mutex_unlock(&cache->lock);
}


static int caller_cmp(const struct caller *a, const struct caller *b)
{
        return intcmp(a->addr, b->addr);
}

static struct caller * find_caller_in_table(void * addr) 
{
	int i;	
	if (nr_callers == 0) return NULL;
	for (i = 0; i < nr_callers - 1; i++) {
		if (addr >= callers[i].addr && addr < callers[i + 1].addr) {
			return callers + i;
		}
	}
	if (addr >= callers[nr_callers - 1].addr) return callers + nr_callers - 1;
	return NULL;
} 

static int init_callers(void)
{
        const char *fname = my_exe_path();
#ifdef __BFD_H_SEEN__
        int max_symtab_size;
        asymbol **symtab;
        int symcount, i;
        bfd *abfd;

	bfd_init();
        abfd = bfd_openr(fname, NULL);
        if (abfd == 0) {
                soe_err("cannot open %s", fname);
                return -1;
        }

        if (!bfd_check_format(abfd, bfd_object)) {
                soe_err("invalid format");
		goto end;
        }

        if (!(bfd_get_file_flags(abfd) & HAS_SYMS)) {
                soe_err("no symbols found");
		goto end;
        }

        max_symtab_size = bfd_get_symtab_upper_bound(abfd);
        if (max_symtab_size < 0) {
                soe_err("failed to get symtab size");
                return -1;
        }

        symtab = malloc(max_symtab_size);
        symcount = bfd_canonicalize_symtab(abfd, symtab);

	callers = calloc(symcount, sizeof(*callers));
	for (i = 0; i < symcount; i++) {
		asymbol *sym = symtab[i];
		void * addr = (void *)bfd_asymbol_value(sym);
		const char *name = bfd_asymbol_name(sym);
		if (addr == 0 || !(sym->flags & BSF_FUNCTION))
			/* sym is not a function */
			continue;

		callers[nr_callers].addr = addr;
		callers[nr_callers].name = strdup(name);
		nr_callers++;
	}
        free(symtab);

	xqsort(callers, nr_callers, caller_cmp);	
end:
	bfd_close(abfd);
#endif
	return 0;
}

static int mem_cmp(const struct mem_info *m1, const struct mem_info *m2)
{
	return intcmp(m1->ptr, m2->ptr);
}

void *wmalloc(size_t size)
{
	void *ret = malloc(size);
	if (unlikely(!ret))
		panic("Out of memory");
	
	if (mem_leak_dection) {
		struct mem_info * new_mem = calloc(1, sizeof(struct mem_info)); 
		if (new_mem) {
			new_mem->ptr = ret;
			new_mem->size = size;
			new_mem->caller = __builtin_return_address(0);
			rb_insert(&mem_tree, new_mem, rb, mem_cmp);
		} else {
			soe_warn("losing trace of the mem %p(%lu)", ret, size); 
		}
	}

	return ret;
}

char *wstrdup(const char *s)
{
        char *ret;
        ret = strdup(s);
        if (!ret)
                panic("Out of memory");

	if (mem_leak_dection) {
		struct mem_info * new_mem = calloc(1, sizeof(struct mem_info)); 
		if (new_mem) {
			new_mem->ptr = ret;
			new_mem->size = strlen(s) + 1;
			new_mem->caller = __builtin_return_address(0);
			rb_insert(&mem_tree, new_mem, rb, mem_cmp);
		} else {
			soe_warn("losing trace of the mem %p(%lu)", ret, strlen(s) + 1); 
		}
	}

        return ret;
}

void *wrealloc(void *ptr, size_t size)
{
	errno = 0;
	struct mem_info mi, *old_mi;
	void *ret = realloc(ptr, size);
	if (unlikely(errno == ENOMEM))
		panic("Out of memory");

	if (mem_leak_dection) {		
		mi.ptr = ptr;
		old_mi = rb_search(&mem_tree, &mi, rb, mem_cmp);	
		if (old_mi) {
			rb_erase(&old_mi->rb, &mem_tree);
		} else {
			soe_warn("found unknown pointer:%p", ptr);
			old_mi = calloc(1, sizeof(struct mem_info));			
		}
		if (old_mi) {
			old_mi->ptr = ret;
			old_mi->size = size;	
			old_mi->caller = __builtin_return_address(0);
			rb_insert(&mem_tree, old_mi, rb, mem_cmp);
		} else {
			soe_warn("losing trace of the mem %p(%lu)", ret, size); 
		}
	}

	return ret;
}

void init_mem_leak_detection(void)
{
	void * my_init_mem = init_mem_leak_detection;
	char * start;
	int i;
	struct caller * fixcl;
	init_callers();
	/* fixed up */
	for (i = 0; i < nr_callers; i++) {
		if (strcmp(callers[i].name, "init_mem_leak_detection") == 0) {
			start = (char *)my_init_mem - (unsigned long)callers[i].addr;
			break;
		}
	}
	for (i = 0; i < nr_callers; i++) {
		callers[i].addr = start + (unsigned long)(callers[i].addr);	
	}
	mem_leak_dection = 1;
}

static void print_caller_table()
{
	int i;	
	for (i = 0; i < nr_callers; i++) {
		soe_info("caller: %s, %p", callers[i].name, callers[i].addr);
	}
}

void collect_mem_leak()
{
	struct mem_info * mi;	
	struct rb_node * tmpp, *tmpn;
	struct caller * cler;	
	int i;
	soe_info("collect the memory leak");
	rb_for_each_entry(mi, tmpp, tmpn, &mem_tree, rb) {
		rb_erase(&mi->rb, &mem_tree);
		cler = find_caller_in_table(mi->caller);
		soe_warn("rb:%p", &mi->rb);
		if (cler) {
			soe_warn("memory leak detection:%p(%lu) caller:%p %s + (%u)", mi->ptr, mi->size, 
						mi->caller, cler->name, (int)((char *)mi->caller - (char *)cler->addr));
		} else {
			soe_warn("memory leak detection:%p(%lu) caller:%p", mi->ptr, mi->size, mi->caller);
		}
		free(mi);	
	}
	if (callers) {
		// print_caller_table();	
		for (i = 0; i < nr_callers; i++) {
			free(callers[i].name);
		}
		free(callers);
	}
}

void *wcalloc(size_t nmemb, size_t size)
{
	void *ret = calloc(nmemb, size);
	if (unlikely(!ret))
		panic("Out of memory");

	if (mem_leak_dection) {
		struct mem_info * new_mem = calloc(1, sizeof(struct mem_info)); 
		if (new_mem) {
			new_mem->ptr = ret;
			new_mem->size = size;
			new_mem->caller = __builtin_return_address(0);
			rb_insert(&mem_tree, new_mem, rb, mem_cmp);
		} else {
			soe_warn("losing trace of the mem %p(%lu)", ret, size); 
		}
	}

	return ret;
}

/* zeroed memory version of valloc() */
void *wvalloc(size_t size)
{
	void *ret = memalign(sysconf(_SC_PAGESIZE),size);
	if (unlikely(!ret))
		panic("Out of memory");

	if (mem_leak_dection) {
		struct mem_info * new_mem = calloc(1, sizeof(struct mem_info)); 
		if (new_mem) {
			new_mem->ptr = ret;
			new_mem->size = size;
			new_mem->caller = __builtin_return_address(0);
			rb_insert(&mem_tree, new_mem, rb, mem_cmp);
		} else {
			soe_warn("losing trace of the mem %p(%lu)", ret, size); 
		}
	}

	memset(ret, 0, size);
	return ret;
}

void wfree(void * ptr)
{
	struct mem_info mi, *old_mi;
	if (mem_leak_dection) {
		mi.ptr = ptr;	
		old_mi = rb_search(&mem_tree, &mi, rb, mem_cmp);	
		if (old_mi) {
			rb_erase(&old_mi->rb, &mem_tree);	
			free(old_mi);
		}
	}
	free(ptr);
} 

static ssize_t _read(int fd, void *buf, size_t len)
{
	ssize_t nr;
	while (true) {
		nr = read(fd, buf, len);
		if (unlikely(nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

static ssize_t _write(int fd, const void *buf, size_t len)
{
	ssize_t nr;
	while (true) {
		nr = write(fd, buf, len);
		if (unlikely(nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

ssize_t wread(int fd, void *buf, size_t count)
{
	char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t loaded = _read(fd, p, count);
		if (unlikely(loaded < 0))
			return -1;
		if (unlikely(loaded == 0))
			return total;
		count -= loaded;
		p += loaded;
		total += loaded;
	}

	return total;
}

ssize_t wwrite(int fd, const void *buf, size_t count)
{
	const char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t written = _write(fd, p, count);
		if (unlikely(written < 0))
			return -1;
		if (unlikely(!written)) {
			errno = ENOSPC;
			return -1;
		}
		count -= written;
		p += written;
		total += written;
	}

	return total;
}

static ssize_t _pread(int fd, void *buf, size_t len, off_t offset)
{
	ssize_t nr;
	while (true) {
		nr = pread(fd, buf, len, offset);
		if (unlikely(nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

static ssize_t _pwrite(int fd, const void *buf, size_t len, off_t offset)
{
	ssize_t nr;
	while (true) {
		nr = pwrite(fd, buf, len, offset);
		if (unlikely(nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

ssize_t wpread(int fd, void *buf, size_t count, off_t offset)
{
	char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t loaded = _pread(fd, p, count, offset);
		if (unlikely(loaded < 0))
			return -1;
		if (unlikely(loaded == 0))
			return total;
		count -= loaded;
		p += loaded;
		total += loaded;
		offset += loaded;
	}

	return total;
}

ssize_t wpwrite(int fd, const void *buf, size_t count, off_t offset)
{
	const char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t written = _pwrite(fd, p, count, offset);
		if (unlikely(written < 0))
			return -1;
		if (unlikely(!written)) {
			errno = ENOSPC;
			return -1;
		}
		count -= written;
		p += written;
		total += written;
		offset += written;
	}

	return total;
}

/* Return EEXIST when path exists but not a directory */
int wmkdir(const char *pathname, mode_t mode)
{
	if (mkdir(pathname, mode) < 0) {
		struct stat st;

		if (errno != EEXIST)
			return -1;

		if (stat(pathname, &st) < 0)
			return -1;

		if (!S_ISDIR(st.st_mode)) {
			errno = EEXIST;
			return -1;
		}
	}
	return 0;
}


int eventfd_create()
{
#ifdef _SYS_EVENTFD_H
	return eventfd(0, EFD_NONBLOCK);
#else
	int efd, flag;
	efd = syscall(__NR_eventfd, 0);
	if (efd < 0) {
		return efd;
	}
	flag = fcntl(efd, F_GETFL, 0);
	flag |= O_NONBLOCK;
	if (fcntl(efd, F_SETFL, flag) < 0) {
		close(efd);
		return -1; 
	}
	return efd;
#endif
}

#ifndef _SYS_EVENTFD_H
typedef uint64_t eventfd_t;
#endif
/*
 * Return the read value on success, or -1 if efd has been made nonblocking and
 * errno is EAGAIN.  If efd has been marked blocking or the eventfd counter is
 * not zero, this function doesn't return error.
 */
int eventfd_xread(int efd)
{
	int ret;
	eventfd_t value = 0;

	do {
#ifdef _SYS_EVENTFD_H
		ret = eventfd_read(efd, &value);
#else
		ret = (read(efd, value, sizeof (eventfd_t)) != sizeof (eventfd_t))?-1:0;
#endif
	} while (unlikely(ret < 0) && errno == EINTR);

	if (ret == 0)
		ret = value;
	else if (unlikely(errno != EAGAIN))
		panic("eventfd_read() failed, %m");

	return ret;
}

void eventfd_xwrite(int efd, int value)
{
	int ret;

	do {
#ifdef _SYS_EVENTFD_H
		ret = eventfd_write(efd, (eventfd_t)value);
#else
		ret = (write(efd, &value, sizeof (eventfd_t)) != sizeof (eventfd_t)?-1:0);
#endif
	} while (unlikely(ret < 0) && (errno == EINTR || errno == EAGAIN));

	if (unlikely(ret < 0))
		panic("eventfd_write() failed, %m");
}

/*
 * Copy the string str to buf. If str length is bigger than buf_size -
 * 1 then it is clamped to buf_size - 1.
 * NOTE: this function does what strncpy should have done to be
 * useful. NEVER use strncpy.
 *
 * @param buf destination buffer
 * @param buf_size size of destination buffer
 * @param str source string
 */
void pstrcpy(char *buf, int buf_size, const char *str)
{
	int c;
	char *q = buf;

	if (buf_size <= 0)
		return;

	while (true) {
		c = *str++;
		if (c == 0 || q >= buf + buf_size - 1)
			break;
		*q++ = c;
	}
	*q = '\0';
}

/* remove a newline character from the end of a string */
char *chomp(char *str)
{
	char *p = strchr(str, '\n');
	if (p != NULL)
		*p = '\0';

	return str;
}

bool is_numeric(const char *s)
{
	const char *p = s;

	if (*p) {
		char c;

		while ((c = *p++))
			if (!isdigit(c))
				return false;
		return true;
	}
	return false;
}

/*
 * We regard 'data' as string when it contains '\0' in the first 256 characters.
 */
const char *data_to_str(void *data, size_t data_length)
{
	data_length = MIN(data_length, 256);

	if (data == NULL)
		return "(null)";

	if (memchr(data, '\0', data_length) != NULL)
		return data;

	return "(not string)";
}

pid_t gettid(void)
{
	return syscall(SYS_gettid);
}

int tkill(int tid, int sig)
{
	return syscall(SYS_tgkill, getpid(), tid, sig);
}

bool is_xattr_enabled(const char *path)
{
	int ret, dummy;

	ret = getxattr(path, "user.dummy", &dummy, sizeof(dummy));

	return !(ret == -1 && errno == ENOTSUP);
}

/*
 * Split the given path and sets the split parts to 'segs'.
 *
 * This returns the number of split segments.
 *
 * For example:
 *   split_path("/a/b/c", 3, segs);
 *     -> Returns 3 and segs will be { "a", "b", "c" }.
 *   split_path("/a//b//c", 3, segs);
 *     -> Returns 3 and segs will be { "a", "b", "c" }.
 *   split_path("/a/b/c", 2, segs);
 *     -> Returns 2 and segs will be { "a", "b/c" }.
 *   split_path("/a/b/c", 4, segs);
 *     -> Returns 3 and segs will be { "a", "b", "c", undefined }.
 */
int split_path(const char *path, size_t nr_segs, char **segs)
{
	int i;
	for (i = 0; i < nr_segs; i++) {
		while (*path == '/')
			path++;

		if (*path == '\0')
			return i;

		if (i == nr_segs - 1) {
			segs[i] = strdup(path);
			if (segs[i] == NULL)
				panic("OOM");
		} else {
			char *p = strchrnul(path, '/');
			int len = p - path;

			segs[i] = wmalloc(len + 1);
			memcpy(segs[i], path, len);
			segs[i][len] = '\0';

			path = p;
		}
	}

	return nr_segs;
}

/* Concatenate 'segs' with '/' separators. */
void make_path(char *path, size_t size, size_t nr_segs, const char **segs)
{
	int i;
	for (i = 0; i < nr_segs; i++) {
		int len = snprintf(path, size, "/%s", segs[i]);
		path += len;
		size -= len;
	}
}

/*
 * Returns a list organized in an intermediate format suited
 * to chaining of merge() calls: null-terminated, no reserved or
 * sentinel head node, "prev" links not maintained.
 */
static struct list_node *merge(void *priv,
			       int (*cmp)(void *priv, struct list_node *a,
					  struct list_node *b),
			       struct list_node *a, struct list_node *b)
{
	struct list_node head, *tail = &head;

	while (a && b) {
		/* if equal, take 'a' -- important for sort stability */
		if ((*cmp)(priv, a, b) <= 0) {
			tail->next = a;
			a = a->next;
		} else {
			tail->next = b;
			b = b->next;
		}
		tail = tail->next;
	}
	tail->next = a?:b;
	return head.next;
}

/*
 * Combine final list merge with restoration of standard doubly-linked
 * list structure.  This approach duplicates code from merge(), but
 * runs faster than the tidier alternatives of either a separate final
 * prev-link restoration pass, or maintaining the prev links
 * throughout.
 */
static void
merge_and_restore_back_links(void *priv,
			     int (*cmp)(void *priv, struct list_node *a,
					struct list_node *b),
			     struct list_head *head,
			     struct list_node *a, struct list_node *b)
{
	struct list_node *tail = &head->n;

	while (a && b) {
		/* if equal, take 'a' -- important for sort stability */
		if ((*cmp)(priv, a, b) <= 0) {
			tail->next = a;
			a->prev = tail;
			a = a->next;
		} else {
			tail->next = b;
			b->prev = tail;
			b = b->next;
		}
		tail = tail->next;
	}
	tail->next = a ? : b;

	do {
		/*
		 * In worst cases this loop may run many iterations.
		 * Continue callbacks to the client even though no
		 * element comparison is needed, so the client's cmp()
		 * routine can invoke cond_resched() periodically.
		 */
		(*cmp)(priv, tail->next, tail->next);

		tail->next->prev = tail;
		tail = tail->next;
	} while (tail->next);

	tail->next = &head->n;
	head->n.prev = tail;
}

/*
 * list_sort - sort a list
 * @priv: private data, opaque to list_sort(), passed to @cmp
 * @head: the list to sort
 * @cmp: the elements comparison function
 *
 * This function implements "merge sort", which has O(nlog(n))
 * complexity.
 *
 * The comparison function @cmp must return a negative value if @a
 * should sort before @b, and a positive value if @a should sort after
 * @b. If @a and @b are equivalent, and their original relative
 * ordering is to be preserved, @cmp must return 0.
 */
void list_sort(void *priv, struct list_head *head,
	       int (*cmp)(void *priv, struct list_node *a,
			  struct list_node *b))
{
	/* sorted partial lists -- last slot is a sentinel */
#define MAX_LIST_LENGTH_BITS 20
	struct list_node *part[MAX_LIST_LENGTH_BITS+1];
	int lev;  /* index into part[] */
	int max_lev = 0;
	struct list_node *list;

	if (list_empty(head))
		return;

	memset(part, 0, sizeof(part));

	head->n.prev->next = NULL;
	list = head->n.next;

	while (list) {
		struct list_node *cur = list;
		list = list->next;
		cur->next = NULL;

		for (lev = 0; part[lev]; lev++) {
			cur = merge(priv, cmp, part[lev], cur);
			part[lev] = NULL;
		}
		if (lev > max_lev) {
			if (unlikely(lev >= ARRAY_SIZE(part)-1)) {
				/*
				 * list passed to list_sort() too long for
				 * efficiency
				 */
				lev--;
			}
			max_lev = lev;
		}
		part[lev] = cur;
	}

	for (lev = 0; lev < max_lev; lev++)
		if (part[lev])
			list = merge(priv, cmp, part[lev], list);

	merge_and_restore_back_links(priv, cmp, head, part[max_lev], list);
}



/*
 * Convert a decimal string like as strtoll to uint32_t/uint16_t
 *
 * returns:
 *   - a converted value if success i.e. neither negative value nor overflow
 *   - undefined if something went wrong and set errno accordingly
 *
 * errno:
 *   - 0 if success
 *   - EINVAL if one of the following:
 *       - nptr was an empty string
 *       - there was an unconvertible character in nptr
 *   - ERANGE if negative/positive overflow occurred
 */
uint32_t str_to_u32(const char *nptr)
{
	char *endptr;
	errno = 0;
	const long long conv = strtoll(nptr, &endptr, 10);
	/* empty string or unconvertible character */
	if (nptr == endptr || *endptr != '\0') {
		errno = EINVAL;
		return (uint32_t)conv;
	}
	/* negative value or overflow */
	if (conv < 0LL || UINT32_MAX < conv) {
		errno = ERANGE;
		return UINT32_MAX;
	}
	return (uint32_t)conv;
}

uint16_t str_to_u16(const char *nptr)
{
	const uint32_t conv = str_to_u32(nptr);
	/* overflow */
	if (UINT16_MAX < conv) {
		errno = ERANGE;
		return UINT16_MAX;
	}
	return (uint16_t)conv;
}
