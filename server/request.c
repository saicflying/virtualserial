#include <netinet/tcp.h>
#include <sys/epoll.h>
#include "soe_proto.h"
#include "soe_priv.h"
#include "serial.h"

static struct soe_mutex client_fd_lock = SOE_MUTEX_INITIALIZER;
static LIST_HEAD(client_fd_list);
soe_notifier_t ci_shutdown_notifier = NULL;
static int mon_client_is_closing = 0;
static soe_thread_info_t mon_client_thread = NULL;

static soe_cache_t soe_cache_client_info = NULL;   
static soe_cache_t soe_cache_request = NULL; 
static soe_cache_t soe_cache_request_data = NULL; 

static void io_op_done(struct work *work)
{
	struct request *req = container_of(work, struct request, work);

	switch (req->rp.result) {
	case SOE_RES_EIO:
		req->rp.result = SOE_RES_NETWORK_ERROR;
		soe_err("leaving sheepdog cluster");
		break;
	case SOE_RES_SUCCESS:
	case SOE_RES_NETWORK_ERROR:
		break;
	default:
		soe_err("unhandled error %s", soe_strerror(req->rp.result));
		break;
	}

	put_request(req);
	return;
}

static inline void sleep_on_wait_queue(struct request *req)
{
	list_add_tail(&req->request_list, &sys->req_wait_queue);
}

void set_client_dead(struct client_info *ci)
{
	soe_mutex_lock(&ci->ref_lock);		
	ci->conn.dead = true;
	soe_mutex_unlock(&ci->ref_lock);		
}

int get_client(struct client_info *ci, int care) 
{
	soe_mutex_lock(&ci->ref_lock);		
	if (care && ci->conn.dead) {
		soe_mutex_unlock(&ci->ref_lock);		
		return 0;
	}
	refcount_inc(&ci->refcnt);
	soe_mutex_unlock(&ci->ref_lock);		
	return 1;
}

void put_client(struct client_info *ci)
{
	soe_mutex_lock(&ci->ref_lock);
	refcount_dec(&ci->refcnt);
	soe_mutex_unlock(&ci->ref_lock);		
}

void queue_request(struct request *req)
{
	struct soe_req *hdr = &req->rq;
	struct soe_rsp *rsp = &req->rp;

	req->op = get_soe_op(hdr->opcode);
	memcpy(rsp, hdr, sizeof(*hdr));
	rsp->len = rsp->readlen = 0;

	if (hdr->opcode != SOE_OP_PING && !req->op) {
		soe_err("invalid opcode %d", hdr->opcode);
		rsp->result = SOE_RES_INVALID_PARMS;
		goto done;
	}

	//soe_debug("%s, %d", op_name(req->op), sys->status);

	switch (sys->status) {
	case SOE_STATUS_KILLED:
		rsp->result = SOE_RES_KILLED;
		goto done;
	case SOE_STATUS_SHUTDOWN:
		rsp->result = SOE_RES_SHUTDOWN;
		goto done;
	default:
		break;
	}
	
	if (hdr->opcode == SOE_OP_PING) {
		req->ci->conn.timestamp_ping = times(NULL);
		rsp->result = SOE_RES_SUCCESS; 
		goto done;
	} else {
		switch (queue_serial_request(req)) {
			case -1:
				rsp->result = SOE_RES_NO_OBJ;
				soe_err("No ttySOE%d is detected", hdr->line);
				goto done;
			case -2:
				rsp->result = SOE_RES_NO_MEM;
				goto done;
			default:
				break;
		}
	}
	return;
done:
	put_request(req);
}

static void clear_client_info(struct client_info *ci);

/*
 * Exec the request locally and synchronously.
 *
 */

struct request *alloc_request(struct client_info *ci, uint32_t data_length)
{
	struct request *req;

	req = soe_cache_alloc(soe_cache_request);
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct request));

	if (data_length) {
		req->data_length = data_length;
		req->data = soe_cache_alloc(soe_cache_request_data);
		if (!req->data) {
			soe_cache_free(soe_cache_request, req);
			return NULL;
		}
	}

	req->ci = ci;
	get_client(ci, 0);
	refcount_set(&req->refcnt, 1);
	return req;
}

void free_request(struct request *req)
{
	put_client(req->ci);
	if (req->data) {
		soe_cache_free(soe_cache_request_data, req->data);
	}
	soe_cache_free(soe_cache_request, req);
}

main_fn void put_request(struct request *req)
{
	struct client_info *ci = req->ci;

	if (req->rp.opcode != SOE_OP_PING) {
		soe_debug("put request: op=%d, seq=%d", req->rp.opcode, req->rp.seq);
	}
	if (refcount_dec(&req->refcnt) > 0)
		return;

	if (ci->conn.dead) {
		/*
		 * free_request should be called prior to
		 * clear_client_info because refcnt of ci will
		 * be decreased in free_request. Otherwise, ci
		 * cannot be freed in clear_client_info.
		 */
		free_request(req);
	} else {
		
		soe_mutex_lock(&ci->conn_lock);
		list_add_tail(&req->request_list, &ci->done_reqs);
		if (req->rp.opcode != SOE_OP_PING) {
			soe_debug("add req to list: op=%d, seq=%d", req->rp.opcode, req->rp.seq);
		}
		if (ci->tx_req == NULL) {
			/* There is no request being sent. */
			if (conn_tx_on(&ci->conn)) {
				soe_err("switch on sending flag"
						" failure, connection"
						" maybe closed");
				/*
				 * should not free_request(req)
				 * here because it is already
				 * in done list
				 * clear_client_info will free
				 * it
				 */
				set_client_dead(ci);
			}
		}
		soe_mutex_unlock(&ci->conn_lock);
	}
}

main_fn void get_request(struct request *req)
{
	refcount_inc(&req->refcnt);
}

#define REQ_DEF_DATA_SIZE 4096
static void rx_work(struct work *work)
{
//	struct client_info *ci = container_of(work, struct client_info,
//					      rx_work);
	struct client_info *ci = (struct client_info *)work->priv;
	int ret;
	struct connection *conn = &ci->conn;
	struct soe_req hdr;
	struct request *req;

	ret = do_read(conn->fd, &hdr, sizeof(hdr), UINT32_MAX);
	if (ret) {
		soe_err("failed to read a header");
		conn->dead = true;
		return;
	}
	
	if (hdr.magic != SOE_MSG_MAGIC) {
		soe_err("corrupted request header");
		conn->dead = true;
		return;
	}
		
	req = alloc_request(ci, max(hdr.len, hdr.readlen));
	if (!req) {
		soe_err("failed to allocate request");
		conn->dead = true;
		return;
	}
	ci->rx_req = req;

	/* use le_to_cpu */
	memcpy(&req->rq, &hdr, sizeof(req->rq));
	if (hdr.len) {
		ret = do_read(conn->fd, req->data, hdr.len, UINT32_MAX);
		if (ret) {
			soe_err("failed to read data");
			conn->dead = true;
		}
	}
}

static void rx_main(struct work *work)
{
//	struct client_info *ci = container_of(work, struct client_info,
//					      rx_work);
	struct client_info *ci = (struct client_info *)work->priv;
	struct request *req = ci->rx_req;

	ci->rx_req = NULL;


	if (ci->conn.dead) {
		if (req)
			free_request(req);
		
		put_client(ci);
		return;
	}

	
	refcount_dec(&ci->rx_refcnt);	
	if (conn_rx_on(&ci->conn))
		soe_err("switch on receiving flag failure, "
				"connection maybe closed");
#if 0
	soe_debug("%d, %s:%d",
			ci->conn.fd,
			ci->conn.ipstr,
			ci->conn.port);
#endif
	if (req) 
		queue_request(req);
	
	put_client(ci);
}

static void tx_work(struct work *work)
{
//	struct client_info *ci = container_of(work, struct client_info,
//					      tx_work);
	struct client_info *ci = (struct client_info *)work->priv;
	int ret;
	struct connection *conn = &ci->conn;
	struct soe_rsp rsp;
	struct request *req = ci->tx_req;
	void *data = NULL;

	/* use cpu_to_le */
	memcpy(&rsp, &req->rp, sizeof(rsp));
	if (rsp.len)
		data = req->data;

	if (rsp.opcode != SOE_OP_PING) {
		soe_debug("send cmd=%d, seq = %d, len = %d", rsp.opcode, rsp.seq, rsp.len);
	}
	ret = send_req(conn->fd, (struct soe_req *)&rsp, sizeof(struct soe_rsp), data, rsp.len, UINT32_MAX);
	if (ret != 0) {
		soe_err("failed to send a request");
		conn->dead = true;
	}
}

static void tx_main(struct work *work)
{
	//struct client_info *ci = container_of(work, struct client_info,
	//				      tx_work);
	struct client_info *ci = (struct client_info *)work->priv;
#if 0
	soe_debug("%d, %s:%d",
			ci->conn.fd,
			ci->conn.ipstr,
			ci->conn.port);
#endif
	free_request(ci->tx_req);
	if (ci->conn.dead) {
		put_client(ci);
		return;
	}

	refcount_dec(&ci->tx_refcnt);	
	soe_mutex_lock(&ci->conn_lock);
	ci->tx_req = NULL;
	if (!list_empty(&ci->done_reqs)) {
		if (conn_tx_on(&ci->conn))
			soe_err("switch on sending flag failure, "
					"connection maybe closed");
	}	
	soe_mutex_unlock(&ci->conn_lock);

	put_client(ci);
}

static void destroy_client(struct client_info *ci)
{
	
	if (ci->q)
		destroy_queue(ci->q);

	soe_info("destroy connection from: %s:%d", ci->conn.ipstr, ci->conn.port);
	close(ci->conn.fd);
	soe_cache_free(soe_cache_client_info, ci);
}

static void clear_client_info(struct client_info *ci)
{
	struct request *req, *tmp;

	if (ci_shutdown_notifier) {
		ci_shutdown_notifier(ci);
	}

	soe_mutex_lock(&ci->conn_lock);
	list_for_each_entry(req, tmp, &ci->done_reqs, request_list) {
		list_del(&req->request_list);
		free_request(req);
	}
	soe_mutex_unlock(&ci->conn_lock);

	if (refcount_read(&ci->refcnt)) {
		return;
	}

	list_del(&ci->list);
	unregister_event(ci->conn.fd);
	destroy_client(ci);
}

static struct client_info *create_client(int fd)
{
	struct client_info *ci;
	char qname[256];
	struct sockaddr_storage from;
	socklen_t namesize = sizeof(from);

	ci = soe_cache_alloc(soe_cache_client_info);
	if (!ci)
		return NULL;

	memset(ci, 0, sizeof(*ci));

	if (getpeername(fd, (struct sockaddr *)&from, &namesize)) {
		soe_cache_free(soe_cache_client_info, ci);
		return NULL;
	}
	
	switch (from.ss_family) {
	case AF_INET:
		ci->conn.port = ntohs(((struct sockaddr_in *)&from)->sin_port);
		inet_ntop(AF_INET, &((struct sockaddr_in *)&from)->sin_addr,
				ci->conn.ipstr, sizeof(ci->conn.ipstr));
		break;
	case AF_INET6:
		ci->conn.port = ntohs(((struct sockaddr_in6 *)&from)->sin6_port);
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&from)->sin6_addr,
				ci->conn.ipstr, sizeof(ci->conn.ipstr));
		break;
	}

	snprintf(qname, sizeof(qname), "%s:%d net queue", ci->conn.ipstr, ci->conn.port); 
	ci->q = create_work_queue(qname);
	if (!ci->q) {
		soe_cache_free(soe_cache_client_info, ci);
		return NULL;
	}
	ci->conn.fd = fd;
	ci->conn.events = EPOLLIN;

	soe_init_mutex(&ci->conn_lock);
	soe_init_mutex(&ci->ref_lock);
	refcount_set(&ci->refcnt, 0);
	refcount_set(&ci->rx_refcnt, 0);
	refcount_set(&ci->tx_refcnt, 0);
	ci->conn.timestamp_ping = times(NULL);
	INIT_LIST_HEAD(&ci->done_reqs);
	
	return ci;
}

static void client_handler(int fd, int events, void *data)
{
	struct client_info *ci = (struct client_info *)data;
	struct work * wk = NULL;
	int ref;

	if (events & (EPOLLERR | EPOLLHUP)) {
		soe_err("event find EPOLLERR|EPOLLHUP:%x", events);
		set_client_dead(ci);
		unregister_event(ci->conn.fd);
	}
	/*
	 * Although dead is true, ci might not be freed immediately
	 * because of refcnt. Never mind, we will complete it later
	 * as long as dead is true.
	 */
	if (ci->conn.dead) {
		return;
	}

	if (events & EPOLLIN) {
		if (conn_rx_off(&ci->conn) != 0) {
			soe_err("switch off receiving flag failure, "
					"connection maybe closed");
			set_client_dead(ci);	
			unregister_event(ci->conn.fd);
			return;
		}
		ref = refcount_read(&ci->rx_refcnt);
		if (ref) {
			soe_warn("get a EPOLLIN with ref %d", ref);
		}
		/*
		 * Increment refcnt so that the client_info isn't freed while
		 * rx_work uses it.
		 */
		if (get_client(ci, 1) == 0) {
			return;
		}

		wk = alloc_work(ci, 1);
		soe_assert(wk != NULL);

		wk->fn = rx_work;
		wk->done = rx_main;
		refcount_inc(&ci->rx_refcnt);
		queue_work(ci->q, wk);
	}

	if (events & EPOLLOUT) {
		if (get_client(ci, 1) == 0) {
			return;
		}

		soe_mutex_lock(&ci->conn_lock);
		if (conn_tx_off(&ci->conn) != 0) {
			soe_mutex_unlock(&ci->conn_lock);
			put_client(ci);	
			soe_err("switch off sending flag failure, "
					"connection maybe closed");
			set_client_dead(ci);
			unregister_event(ci->conn.fd);
			return;
		}

		soe_assert(ci->tx_req == NULL);
		ci->tx_req = list_first_entry(&ci->done_reqs, struct request,
					      request_list);

		list_del(&ci->tx_req->request_list);
		soe_mutex_unlock(&ci->conn_lock);

		ref = refcount_read(&ci->tx_refcnt);
		if (ref) {
			soe_warn("get a EPOLLOUT with ref %d", ref);
		}
		/*
		 * Increment refcnt so that the client_info isn't freed while
		 * tx_work uses it.
		 */
		if (ci->tx_req->rp.opcode != SOE_OP_PING) {
			soe_debug("queue to work: op=%d, seq=%d", ci->tx_req->rp.opcode, ci->tx_req->rp.seq);
		}

		wk = alloc_work(ci, 1);
		soe_assert(wk != NULL);
		
		wk->fn = tx_work;
		wk->done = tx_main;
		refcount_inc(&ci->tx_refcnt);
		queue_work(ci->q, wk);
	}
}

static void listen_handler(int listen_fd, int events, void *data)
{
	struct sockaddr_storage from;
	socklen_t namesize;
	int fd, ret;
	struct client_info *ci;
	bool is_inet_socket = *(bool *)data;

	if (sys->status == SOE_STATUS_SHUTDOWN) {
		soe_warn("unregistering connection %d", listen_fd);
		unregister_event(listen_fd);
		return;
	}

	namesize = sizeof(from);
	fd = accept(listen_fd, (struct sockaddr *)&from, &namesize);
	if (fd < 0) {
		soe_err("failed to accept a new connection: %m");
		return;
	}

	if (is_inet_socket) {
		ret = set_nodelay(fd);
		if (ret) {
			close(fd);
			return;
		}
		ret = set_keepalive(fd);
		if (ret) {
			close(fd);
			return;
		}
	}

	ci = create_client(fd);
	if (!ci) {
		close(fd);
		return;
	}

	ret = register_event(fd, client_handler, ci);
	if (ret) {
		destroy_client(ci);
		return;
	}

	soe_mutex_lock(&client_fd_lock);
	list_add_tail(&ci->list, &client_fd_list);
	soe_mutex_unlock(&client_fd_lock);
	soe_info("accepted a new connection: %d", fd);
}


/* listening list */
static LIST_HEAD(listening_fd_list);

struct listening_fd {
	int fd;
	struct list_node list;
};

static int create_listen_port_fn(int fd, void *data)
{
	struct listening_fd *new_fd;

	new_fd = wzalloc(sizeof(*new_fd));
	new_fd->fd = fd;
	list_add_tail(&new_fd->list, &listening_fd_list);

	return register_event(fd, listen_handler, data);
}

void * mon_client_routine(void * arg)
{
	struct client_info *ci, *tmp;
	int freq = sysconf(_SC_CLK_TCK);	
	while(!soe_thread_should_stop() && !mon_client_is_closing) {
		soe_mutex_lock(&client_fd_lock);
		list_for_each_entry(ci, tmp, &client_fd_list, list) {
			if (ci->conn.dead == true) {
				clear_client_info(ci);
			} else {
				clock_t curr = times(NULL);
				if (ci->priv_data) {
					if ((curr - ci->conn.timestamp_ping) > freq * 4) {
						soe_err("ping failed at least 4 times");
						set_client_dead(ci);
					}
				}
			}
		}
		soe_mutex_unlock(&client_fd_lock);
		sleep(1);
	}
	soe_info("client monitor thread exit");
	return NULL;
}

int create_listen_port(const char *bindaddr, int port)
{
	static bool is_inet_socket = true;
	int ret;	
	
	ret = soe_thread_create("client mon", &mon_client_thread, mon_client_routine, NULL);
	if (ret < 0) {
		soe_err("fail to create the client monitor thread");	
		return -1;
	}
	ret = create_listen_ports(bindaddr, port, create_listen_port_fn,
				   &is_inet_socket);
	if (ret < 0) {
		mon_client_is_closing = 1;
		soe_thread_join(mon_client_thread);
	}
	return ret;
}

int create_net_cache(void)
{
	soe_cache_client_info = soe_cache_init("client info cache", sizeof(struct client_info), 4096);
	if (soe_cache_client_info == NULL) {
		soe_err("failed to create client info cache");
		return -1;
	}

	soe_cache_request = soe_cache_init("request cache", sizeof(struct request), 4096);
	if (soe_cache_request == NULL) {
		soe_err("failed to create request cache");
		return -1;
	}
	soe_cache_request_data = soe_cache_init("request cache", 1024, 4096);
	if (soe_cache_request_data == NULL) {
		soe_err("failed to create request cache");
		return -1;
	}
	return 0;
}

void cleanup_net(void)
{
	/* close the listening sockets */	
	struct client_info *ci, *ltmp;
	struct listening_fd *fd, *tmp;
	if (mon_client_thread) {
		mon_client_is_closing = 1;
		soe_thread_join(mon_client_thread);
		mon_client_thread = NULL;
	}

	list_for_each_entry(fd, tmp, &listening_fd_list, list) {
		soe_info("clean up listening socket: %d", fd->fd);
		list_del(&fd->list);
		unregister_event(fd->fd);
		close(fd->fd);
		wfree(fd);
	}

	/* close all the clients */
	soe_mutex_lock(&client_fd_lock);
	list_for_each_entry(ci, ltmp, &client_fd_list, list) {
		soe_info("clean up client socket: %s:%d", ci->conn.ipstr, ci->conn.port);
		ci->conn.dead = true;
		//list_del(&ci->list);
		clear_client_info(ci);
	}
	soe_mutex_unlock(&client_fd_lock);
}

int register_shutdown_notifer(soe_notifier_t notifier)
{
	ci_shutdown_notifier = notifier;
}
