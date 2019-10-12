#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <termios.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/select.h>
#include "soe_proto.h"
#include "net.h"
#include "event.h"
#include "option.h"
#include "util.h"
#include "work.h"

#define PACKAGE_VERSION "1.0.0.3"

#define LOG_DIR_DEFAULT "/var/log"
#define MAX_REQ_DATA_SIZE 1024
typedef struct {
	int idx;
	int sockfd;
} sock_req_t;

#define SOE_CREATE_UART  _IO('Z', 0)
#define SOE_DESTROY_UART _IO('Z', 1)
#define SOE_GET_MAPPING  _IO('Z', 2)
#define SOE_SET_SOCK     _IO('Z', 3)
#define SOE_CLEAR_SOCK   _IO('Z', 4)
#define SOE_CLEAR_ERROR  _IO('Z', 5)
#define SOE_GET_CNT	 _IO('Z', 6)
#define SOE_CHECK_REOPEN _IO('Z', 7)

static int soe_port = SOE_LISTEN_PORT;
static uint32_t gl_seq = 0, gl_intrseq = 0;
static soe_cache_t req_buf_cache = NULL;  

#define MAX_UART_BUFFER 10240

#define FIFO_SIZE(w,r) (((w) >= (r))?((w)-(r)):((w) + MAX_UART_BUFFER - (r)))
#define FIFO_RX_SIZE(h_soe) FIFO_SIZE(((h_soe)->rb_wp), ((h_soe)->rb_rp))
#define FIFO_POS(p) ((p) % MAX_UART_BUFFER)

typedef struct soe_handle_s{
	struct soe_mutex int_lock;
	int interrupted;
	int int_refcnt;
	int intr_is_closing;
	int ping_is_closing;
	int pingerr;
	void * read_buf;
	int  rb_rp, rb_wp;
	struct soe_cond  intr_cond;
	struct soe_mutex intr_cond_lock;
	soe_thread_info_t intr_thread;
	soe_thread_info_t ping_thread; 

	/* remote  data structure */ 
	int remotefd; //connection handler
	struct soe_mutex remotefd_lock;
	int remoteline;
	
	struct soe_mutex remote_ref_lock;
	int remotefd_locked;
	int remote_refcnt;

	struct soe_mutex req_lock;
	struct list_head req_list;
	
	int is_remote_closing;
	int is_new_connection;
	struct work remote_work;
	struct work_queue * remote_io_queue;
	int remoteevent;
	char servername[256];

	/* local data structure */
	int kfd; /* kernel file handler */
	int localfd[2];
	int localline;
	struct work local_work;
	struct work_queue * local_io_queue;
	int localevent;
	int is_local_closing;

	int is_released;	
	int baudrate;
	int waittimeperchar;
	struct soe_mutex open_lock;
	int open_ref;
} *soe_handle_t; 

typedef struct {
	struct soe_cond pending_cond; 
	struct soe_mutex pending_lock;	
	struct soe_req rq;
	struct soe_rsp rp; 
	void * data;
	int  * plen;
	struct list_node node;
	int wakeup;
	int refcnt;
} soe_req_c_t;

struct system_info {
	enum soe_status status :8;
};

static struct system_info __sys;
struct system_info *sys = &__sys;

void soe_handle_event(int fd, int event, void *data);
int soe_get_cnt(soe_handle_t fd, struct soe_cnt * pcnt);
int soe_clr_int(soe_handle_t fd);
int soe_remote_ioctl(soe_handle_t fd, int cmd, void * inbuf, int inlen, void * outbuf, int* outlen, int wait);
int soe_open(soe_handle_t fd);
int soe_ping(soe_handle_t fd);
int soe_close(soe_handle_t fd);
int soe_read(soe_handle_t fd, char *buf, int len);
int soe_write(soe_handle_t fd, char *buf, int len);
int soe_setattr(soe_handle_t fd, struct termios * ptio);
int soe_getattr(soe_handle_t fd, struct termios *ptio);
int soe_get_cnt(soe_handle_t fd, struct soe_cnt * pcnt);
int soe_flush(soe_handle_t fd);
static void *soe_intr_thread(void *arg);
static void *soe_ping_thread(void *arg);

#if 0
static int soe_daemonize(bool daemonize)
{
	int ret, devnull_fd = 0, status = 0;
	int pipefd[2];

	if (daemonize) {
		ret = pipe(pipefd);
		if (ret < 0)
			panic("pipe() for passing exit status failed: %m");

		switch (fork()) {
			case 0:
				break;
			case -1:
				panic("fork() failed during daemonize: %m");
				break;
			default:
				close(pipefd[1]);
				ret = read(pipefd[0], &status, sizeof(status));
				if (ret != sizeof(status))
					panic("read exit status failed: %m");

				close(pipefd[0]);
				_exit(status);
				break;
		}

		if (setsid() == -1) {
			soe_err("becoming a leader of a new session failed: %m");
			status = 1;
			goto end;
		}

		switch (fork()) {
			case 0:
				break;
			case -1:
				soe_err("fork() failed during daemonize: %m");
				status = 1;
				goto end;
			default:
				_exit(0);
				break;
		}

		if (chdir("/")) {
			soe_err("chdir to / failed: %m");
			status = 1;
			goto end;
		}

		devnull_fd = open("/dev/null", O_RDWR);
		if (devnull_fd < 0) {
			soe_err("opening /dev/null failed: %m");
			status = 1;
			goto end;
		}
		/*
		 * now we can use base_dir/sheep.log for logging error messages,
		 * we can close 0, 1, and 2 safely
		 *
		 */
		dup2(devnull_fd, 0);
		dup2(devnull_fd, 1);
		dup2(devnull_fd, 2);

		close(devnull_fd);
end:
		close(pipefd[0]);
		ret = write(pipefd[1], &status, sizeof(status));
		if (ret != sizeof(status))
			panic("writing exit status failed: %m");
		close(pipefd[1]);

	}

	return status;
}
#endif
soe_req_c_t * find_req_from_list(soe_handle_t fd, struct soe_rsp *rsp)
{
	soe_req_c_t * req, *tmp; 
	soe_mutex_lock(&fd->req_lock);	
	list_for_each_entry(req, tmp, &fd->req_list, node) {
		if (rsp->opcode == req->rq.opcode && rsp->seq == req->rq.seq) {
			req->refcnt++;
			soe_mutex_unlock(&fd->req_lock);	
			return req;
		}
	}
	soe_mutex_unlock(&fd->req_lock);	
} 

void soe_set_remote_closing(soe_handle_t fd, int val)
{
	fd->is_remote_closing = val;
	if (val) {
		fd->is_new_connection = 0;
	}
}

int soe_is_remote_closing(soe_handle_t fd)
{
	return fd->is_remote_closing;
}

int soe_reconnect(soe_handle_t h_soe)
{
	int tmpfd, ret;
	static int rec_cnt = 0;
	if (!soe_is_remote_closing(h_soe)) 
		return 0;

	soe_mutex_lock(&h_soe->remote_ref_lock);
	h_soe->remotefd_locked = 1;
	while(h_soe->remote_refcnt) {
		soe_mutex_unlock(&h_soe->remote_ref_lock);
		sleep(0);
		soe_mutex_lock(&h_soe->remote_ref_lock);
	}
	soe_mutex_unlock(&h_soe->remote_ref_lock);

	soe_mutex_lock(&h_soe->remotefd_lock);	
	if (h_soe->remotefd) {
		unregister_event(h_soe->remotefd);
		close(h_soe->remotefd);
		h_soe->remotefd = 0;
	}
	soe_mutex_unlock(&h_soe->remotefd_lock);	
	
	while(!h_soe->is_released) {
		if (rec_cnt == 0) {
			soe_info("reconnecting to %s:%d", h_soe->servername, soe_port);
		}
		rec_cnt++;
		tmpfd = connect_to(h_soe->servername, soe_port);
		if (tmpfd > 0) {
			rec_cnt = 0;
			soe_mutex_lock(&h_soe->remotefd_lock);	
			if (h_soe->remotefd) {
				close(h_soe->remotefd);
			}
			h_soe->remotefd = tmpfd;
			if (register_event(tmpfd, soe_handle_event, h_soe) < 0) {
				close(h_soe->remotefd);
				h_soe->remotefd = 0;
				soe_mutex_unlock(&h_soe->remotefd_lock);
				sleep(2);	
				continue;
			}
			h_soe->pingerr = 0;
			soe_mutex_unlock(&h_soe->remotefd_lock);	
			break;
		} else {
			sleep(2);
		}
	}

	soe_mutex_lock(&h_soe->remote_ref_lock);	
	h_soe->remotefd_locked = 0;
	soe_mutex_unlock(&h_soe->remote_ref_lock);	

	h_soe->is_new_connection = 1;	
	soe_mutex_lock(&h_soe->open_lock);
	if (h_soe->open_ref) {
		ret = soe_remote_ioctl(h_soe, SOE_OP_EXT(SOE_OP_OPEN), NULL, 0, NULL, NULL, 3000);	
		if (ret < 0) {
			soe_err("failed to reopen the uart");
		} else {
			soe_set_remote_closing(h_soe, 0);
		}
	} else {
		soe_set_remote_closing(h_soe, 0);
	}
	soe_mutex_unlock(&h_soe->open_lock);
}

soe_handle_t soe_connect(char *servername, int localline, int remoteline)
{
	int ret, i;
	sock_req_t sr;
	struct linger linger_opt = {1, 0};
	soe_handle_t h_soe = wzalloc(sizeof(*h_soe));
	if (h_soe == NULL) {
		soe_err("failed to allocate the memory"); 
		return NULL;
	}

	h_soe->remoteline = remoteline;
	h_soe->localline = localline; 

	/* remote initialization */
	soe_init_mutex(&h_soe->remote_ref_lock);
	soe_init_mutex(&h_soe->remotefd_lock);

	strncpy(h_soe->servername,  servername, sizeof(h_soe->servername));

	h_soe->remotefd = connect_to(servername, soe_port);
	if (h_soe->remotefd <= 0) {
		soe_err("failed to connect to %s", servername); 
		h_soe->remotefd = 0;
		soe_set_remote_closing(h_soe, 1);
		//goto end;
	}

	h_soe->remote_refcnt = 0;	

	soe_init_mutex(&h_soe->req_lock);	
	INIT_LIST_HEAD(&h_soe->req_list);

	h_soe->remote_io_queue = create_work_queue("remote io queue");
	if (h_soe->remote_io_queue == NULL){
		soe_err("failed to create remote io queue;"); 
		goto failqueue;
	}

	if (h_soe->remotefd) {
		ret = register_event(h_soe->remotefd, soe_handle_event, h_soe); 
		if (ret < 0) {
			soe_err("failed to register remote event"); 
			goto failevent;
		}
	}
	
	/* local initialization */
	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, h_soe->localfd);
	if (ret < 0) {
		soe_err("failed to create socket pair"); 
		goto failsocket;
	}

	for (i = 0; i < 1; i++) {	
		ret = setsockopt(h_soe->localfd[i], SOL_SOCKET, SO_LINGER, &linger_opt,
				sizeof(linger_opt));
		if (ret < 0) {
			soe_err("failed to set SOL_SOCKET");
			goto failsockopt;
		}	
		
		ret = set_snd_timeout(h_soe->localfd[i]);
		if (ret < 0) {
			soe_err("failed to set send timeout:%m");
			goto failsockopt;
		}	
		ret = set_rcv_timeout(h_soe->localfd[i]);
		if (ret < 0) {
			soe_err("failed to set recv timeout:%m");
			goto failsockopt;
		}
	}

	h_soe->kfd = open("/dev/soe", O_RDWR|O_SYNC);	
	if (h_soe->kfd < 0) {
		soe_err("failed to open /dev/soe"); 
		goto failkfd; 
	}

	ret =  ioctl(h_soe->kfd, SOE_CREATE_UART, h_soe->localline);
	if (ret < 0) {
		if (errno != EEXIST) {
			soe_err("failed to create the local serial port %d", errno);
			goto failcreate;
		}
	}

	sr.idx = h_soe->localline;
	sr.sockfd = h_soe->localfd[0];
	ret = ioctl(h_soe->kfd, SOE_SET_SOCK, &sr);
	if (ret < 0) {
		soe_err("failed to bind the socket to the local port %d", errno);
		goto failbind;
	}	

	h_soe->local_io_queue = create_work_queue("local io queue");
	if (h_soe->local_io_queue == NULL) {
		soe_err("failed to create local io queue");
		goto faillocalqueue;
	}

	ret = register_event(h_soe->localfd[1], soe_handle_event, h_soe); 
	if (ret < 0) {
		soe_err("failed to register local event"); 
		goto faillocalevent;
	}

	soe_cond_init(&h_soe->intr_cond);	
	soe_init_mutex(&h_soe->intr_cond_lock);
	soe_init_mutex(&h_soe->int_lock);
	soe_init_mutex(&h_soe->open_lock);
	h_soe->open_ref = 0;
	h_soe->interrupted = 0;
	h_soe->int_refcnt = 0;
	h_soe->read_buf = malloc(MAX_UART_BUFFER);
	if (h_soe->read_buf == NULL) {
		goto failinreadbuf;
	}
	h_soe->rb_rp = h_soe->rb_wp = 0;

	if (soe_thread_create("intr thread", &h_soe->intr_thread, soe_intr_thread, h_soe) < 0) {
		h_soe->intr_thread = NULL;
		goto failintrthread;
	}

	if (soe_thread_create("ping thread", &h_soe->ping_thread, soe_ping_thread, h_soe) < 0) {
		h_soe->ping_thread = NULL;
		goto failpingthread;
	}

	soe_info("check if need to reopen the uart");
	ret =  ioctl(h_soe->kfd, SOE_CHECK_REOPEN, h_soe->localline);
	if (ret < 0) {
		soe_info("failed to reopen, need to open the uart manually");
	}
	return h_soe;
failpingthread:
	if (h_soe->intr_thread) {
		soe_mutex_lock(&h_soe->intr_cond_lock);
		h_soe->intr_is_closing = 1;
		soe_cond_signal(&h_soe->intr_cond);
		soe_mutex_unlock(&h_soe->intr_cond_lock);
		soe_thread_join(h_soe->intr_thread);
		h_soe->intr_is_closing = 0;
		h_soe->intr_thread = NULL; 
	}
failintrthread:
	if(h_soe->read_buf) {
		free(h_soe->read_buf);
		h_soe->read_buf = NULL;
	}
failinreadbuf:
	unregister_event(h_soe->localfd[1]);
faillocalevent:
	destroy_queue(h_soe->local_io_queue);
	ioctl(h_soe->kfd, SOE_CLEAR_SOCK, h_soe->localline);  	
faillocalqueue:
failbind:
failcreate:
failkevent:
	close(h_soe->kfd);
failsockopt:
failkfd:
	close(h_soe->localfd[0]);
	close(h_soe->localfd[1]);
failsocket:
	if (h_soe->remotefd) {
		unregister_event(h_soe->remotefd);
	}
failevent:
	destroy_queue(h_soe->remote_io_queue);
failqueue:
	if (h_soe->remotefd) {
		close(h_soe->remotefd);
	}
end:
	wfree(h_soe);
	return NULL;
}

void soe_release(soe_handle_t h_soe)
{
	if (h_soe) {
		soe_mutex_lock(&h_soe->remote_ref_lock);		
		h_soe->is_released = 1;
		while(h_soe->remote_refcnt || h_soe->remotefd_locked) {
			soe_mutex_unlock(&h_soe->remote_ref_lock);
			sleep(0);
			soe_mutex_lock(&h_soe->remote_ref_lock);		
		}
		soe_mutex_unlock(&h_soe->remote_ref_lock);
	
		if (h_soe->ping_thread) {
			h_soe->ping_is_closing = 1;		
			soe_thread_join(h_soe->ping_thread);
			h_soe->ping_is_closing = 0;
			h_soe->ping_thread = NULL;
		}

		if (h_soe->intr_thread) {
			soe_mutex_lock(&h_soe->intr_cond_lock);
			h_soe->intr_is_closing = 1;
			soe_cond_signal(&h_soe->intr_cond);
			soe_mutex_unlock(&h_soe->intr_cond_lock);
			soe_thread_join(h_soe->intr_thread);
			h_soe->intr_is_closing = 0;
			h_soe->intr_thread = NULL; 
		}
		if(h_soe->read_buf) {
			free(h_soe->read_buf);
			h_soe->read_buf = NULL;
		}
		unregister_event(h_soe->localfd[1]);
		destroy_queue(h_soe->local_io_queue);
		ioctl(h_soe->kfd, SOE_CLEAR_SOCK, h_soe->localline);  	
		close(h_soe->kfd);
		close(h_soe->localfd[0]);
		close(h_soe->localfd[1]);
			
				
		soe_mutex_lock(&h_soe->remotefd_lock);	
		if (h_soe->remotefd) {
			unregister_event(h_soe->remotefd);
			destroy_queue(h_soe->remote_io_queue);
			close(h_soe->remotefd);
			h_soe->remotefd = 0;
		}
		soe_mutex_unlock(&h_soe->remotefd_lock);	
		wfree(h_soe);
	}
}

	

int local_rx_ctl(soe_handle_t h_soe, int on)
{
	if (on)
		h_soe->localevent |= EPOLLIN;
	else 
		h_soe->localevent &= ~EPOLLIN;

	return modify_event(h_soe->localfd[1], h_soe->localevent);
}

void soe_handle_local_request(soe_handle_t h_soe, struct soe_req *req)
{
	struct soe_rsp rsp;
	void * iobuf = NULL;	
	int outlen = 0;
	int nowait = 0;
	int ret;
	if (req->magic != SOE_MSG_MAGIC)
		return;

	if (req->opcode != SOE_OP_PING) {
		soe_debug("local request: op = %x seq：%d", req->opcode, req->seq);	
	}
	if (req->len || req->readlen) {
		iobuf = soe_cache_alloc(req_buf_cache);
		if (iobuf == NULL) {
			return;
		}
		if (req->len) {
			ret = do_read(h_soe->localfd[1], iobuf, req->len, 3);
			if (ret < 0) {
				soe_err("Failed to read the request data:%x(%d)", req->opcode, req->seq); 
				soe_cache_free(req_buf_cache, iobuf);
				return;
			}
		}
	}

	memcpy(&rsp, req, sizeof(*req));
	rsp.len = rsp.readlen = 0;
	switch (req->opcode) {
		case SOE_OP_OPEN:
			rsp.result = soe_open(h_soe);
			nowait = 0;
			break;
		case SOE_OP_SET: 
			{
				struct soe_termios *recv_ios = iobuf; 
				struct termios tio;
				tio.c_cflag = recv_ios->c_cflag;
				tio.c_ispeed = recv_ios->c_ispeed;
				tio.c_ospeed = recv_ios->c_ospeed;
				rsp.result = soe_setattr(h_soe, &tio);
				nowait = 1;
				break;
			}
			break;
		case SOE_OP_WRITE:
			{
				rsp.result = soe_write(h_soe, iobuf, req->len); 
				nowait = 0;
			}
			break;
		case SOE_OP_GET_CNT:
			{
				rsp.result = soe_get_cnt(h_soe, iobuf); 
				outlen = sizeof(struct soe_cnt); 
				nowait = 0;
			}
			break;
		case SOE_OP_CLOSE:
			rsp.result = soe_close(h_soe);
			nowait = 1;
			break;
		default:
			rsp.result = SOE_RES_INVALID_PARMS;
			break;	
	}
	if (req->len && outlen == 0) {
		soe_cache_free(req_buf_cache, iobuf);
		iobuf = NULL;
	}
	if (outlen) {
		rsp.len = outlen;
	}
	soe_debug("local response: op = %x, %x, %p, %d, %d, nowait=%d",rsp.opcode, rsp.seq, iobuf, outlen, rsp.result, nowait);
	if (!nowait) {
		ret = send_req(h_soe->localfd[1], (struct soe_req *)&rsp, sizeof(rsp), iobuf, outlen, 3);
		if (ret < 0) {
			soe_err("failed to send out the response");	
		}
	}
	if (iobuf) {
		soe_cache_free(req_buf_cache, iobuf);
	}
}
static void *soe_ping_thread(void *arg)
{
	soe_handle_t h_soe = (soe_handle_t)arg;
	while (!soe_thread_should_stop()) {
		if (h_soe->ping_is_closing) {
			break;
		}
		if (!soe_is_remote_closing(h_soe)) {
			if (soe_ping(h_soe) < 0) {
				if (h_soe->pingerr >= 4) {
					soe_err("ping failed for %d times", h_soe->pingerr);
					soe_set_remote_closing(h_soe, 1);
					//unregister_event(h_soe->remotefd);
				}
			}  else {
				usleep(500000);
			}
		} else {
			sleep(1);
		}
		
	}	
}
static void *soe_intr_thread(void *arg)
{
	int ret;
	int cnt, len;
	struct soe_rsp rsp;
	soe_handle_t h_soe = (soe_handle_t)arg;
	struct soe_cnt iocnt;
	char read_buf[1024];
	soe_info("intr thread for ttySOE%d", h_soe->localline);
	rsp.magic = SOE_MSG_MAGIC;
	rsp.opcode = SOE_OP_INT;
	rsp.line = h_soe->localline;
	setpriority(PRIO_PROCESS, 0, -15);

	while (!soe_thread_should_stop()) {
		soe_mutex_lock(&h_soe->intr_cond_lock);
		if (!h_soe->intr_is_closing ) {
			if (!FIFO_RX_SIZE(h_soe)) {
				ret = soe_cond_wait_timeout(&h_soe->intr_cond, &h_soe->intr_cond_lock, 1000);
			}
		} else {
			soe_mutex_unlock(&h_soe->intr_cond_lock);
			break;
		}
		soe_mutex_unlock(&h_soe->intr_cond_lock);
		if (soe_is_remote_closing(h_soe)) {
			soe_reconnect(h_soe);	
			if (soe_is_remote_closing(h_soe)) {
				continue;
			}
		}		
		soe_mutex_lock(&h_soe->int_lock);
		if (h_soe->interrupted > 0) {
			h_soe->int_refcnt++;
		} else {
			soe_mutex_unlock(&h_soe->int_lock);
			soe_cond_init(&h_soe->intr_cond);	
			continue;
		}
		soe_mutex_unlock(&h_soe->int_lock);
		
		cnt = FIFO_RX_SIZE(h_soe);
		while (cnt) {
			len = min(cnt, 256); 	
			len = min(len, MAX_UART_BUFFER -  h_soe->rb_rp);
			rsp.seq = gl_intrseq++;	
			rsp.readlen = rsp.len = len;
			soe_debug("send to kernel:%d", len);
			ret = send_req(h_soe->localfd[1], (struct soe_req *)&rsp, sizeof(rsp), h_soe->read_buf + h_soe->rb_rp, len, 3);
			if (ret < 0) {
				soe_err("failed to send the interrupt response to the driver, the data is lost %d", ret);
			} else {
				h_soe->rb_rp = FIFO_POS(h_soe->rb_rp + len);	
			}
			cnt = FIFO_RX_SIZE(h_soe);
		}
		h_soe->int_refcnt--;
		soe_cond_init(&h_soe->intr_cond);	
	}
	soe_info("intr thread for ttySOE%d exit", h_soe->localline);
	return NULL;
}

static void local_rx_work(struct work *work)
{
	soe_handle_t h_soe = (soe_handle_t)work->priv;
	int ret;
	struct soe_req rq; 	

	ret = do_read(h_soe->localfd[1], &rq, sizeof(rq), 3);
	if (ret < 0) {
		soe_err("failed to read from driver"); 
		if (ret == -2) {
			h_soe->is_local_closing = 1;
			return;
		}
	} else {
		//soe_info("request: op =  %x", rq.opcode);
		if (rq.magic != SOE_MSG_MAGIC) {
			soe_err("read a corrupted response");
		} else {
			soe_handle_local_request(h_soe, &rq);
		}
	}
}

static void local_rx_work_done(struct work *work)
{
	//soe_handle_t h_soe = container_of(work, struct soe_handle_s, local_work);
	soe_handle_t h_soe = (soe_handle_t)work->priv;
	if (local_rx_ctl(h_soe, 1)) {
		h_soe->is_local_closing = 1;
		unregister_event(h_soe->localfd[1]);
		/* retry connection FIXME*/
	}
}


void soe_handle_kernel_event(soe_handle_t h_soe, int event)
{
	if (event & EPOLLERR) {
		ioctl(h_soe->kfd, SOE_CLEAR_ERROR, h_soe->localline);  	
	}
}

void soe_handle_local_event(soe_handle_t h_soe, int event)
{
	int ret;
	struct work * wk;
	if (event & (EPOLLERR | EPOLLHUP)) {
		/* connection closed */
		soe_err("the local connection is closed");
		h_soe->is_local_closing = 1;
		unregister_event(h_soe->localfd[1]);
		/* retry connection FIXME*/
		return;
	}

	if (event & EPOLLIN) {
		if (local_rx_ctl(h_soe, 0)) {
			h_soe->is_local_closing = 1;
			unregister_event(h_soe->localfd[1]);
			/* retry connection FIXME*/
			return;
		}
		wk = alloc_work(h_soe, 0);
		if (wk == NULL) {
			soe_err("failed to allocate the work item, try high priority");
			wk = alloc_work(h_soe, 1);
			if (wk == NULL) {
				soe_err("failed to allocate the work item");
				soe_assert(wk != NULL);	
			}
		}
		wk->fn =  local_rx_work;
		wk->done = local_rx_work_done;
		queue_work(h_soe->local_io_queue, wk);
	}
}

int remote_rx_ctl(soe_handle_t h_soe, int on)
{
	if (on)
		h_soe->remoteevent |= EPOLLIN;
	else 
		h_soe->remoteevent &= ~EPOLLIN;

	return modify_event(h_soe->remotefd, h_soe->remoteevent);
}

static char tmp_data[1024];

void soe_handle_remote_response(soe_handle_t h_soe, struct soe_rsp *rsp)
{
	int ret, old, free, cnt, getcnt, offset;
	soe_req_c_t * req;
	req = find_req_from_list(h_soe, rsp);
	if (req == NULL) {
		if (rsp->len) {
			/* read out all the following data */
			ret = do_read(h_soe->remotefd, tmp_data, rsp->len, 3); 
			if (rsp->opcode == SOE_OP_INT) {
				if (ret < 0) {
					soe_err("failed to read the interrupted data:%d", rsp->len);	
					return;
				} else {
					soe_mutex_lock(&h_soe->int_lock);
					h_soe->interrupted = 1;
					//soe_warn("get interrupt");
					free = MAX_UART_BUFFER - 1 - FIFO_RX_SIZE(h_soe);
					cnt = rsp->len;
					if (free < cnt)	{
						soe_err("lost %d data", cnt - free);
					}
					getcnt = min(free, cnt);	
					offset = 0;
					while(getcnt) {
						cnt = min(getcnt, MAX_UART_BUFFER -  h_soe->rb_wp);
						memcpy(h_soe->read_buf + h_soe->rb_wp, tmp_data + offset, cnt);
						getcnt -= cnt;
						offset += cnt;
						h_soe->rb_wp = FIFO_POS(h_soe->rb_wp + cnt);
					}
					soe_cond_signal(&h_soe->intr_cond);
					soe_mutex_unlock(&h_soe->int_lock);
					return;
				}
			}
		}
		if (rsp->opcode != SOE_OP_PING) {
			soe_warn("get a unmatched response:op= %d, seq = %d", rsp->opcode, rsp->seq);
		}

	} else {
		if (rsp->opcode != SOE_OP_PING) {
			soe_debug("remote response:%x, %d", rsp->opcode, rsp->seq);
		}
		memcpy(&req->rp, rsp, sizeof(*rsp));
		if (rsp->len && req->data) {
			ret = do_read(h_soe->remotefd, req->data, rsp->len, 3);
			if (ret < 0) {
				soe_err("failed to read from server"); 
				if (ret == -2) {
					req->rp.result = -SOE_RES_EIO;
					req->refcnt--;
					soe_mutex_lock(&req->pending_lock);
					req->wakeup = 1;
					soe_cond_signal(&req->pending_cond);
					soe_mutex_unlock(&req->pending_lock);
					soe_set_remote_closing(h_soe, 1);
					return;
				}
			} else {
				if (req->plen) {
					*req->plen = rsp->len;
				}
			}
		}
		soe_mutex_lock(&req->pending_lock);
		req->wakeup = 1;
		soe_cond_signal(&req->pending_cond);
		soe_mutex_unlock(&req->pending_lock);
		req->refcnt--;
	}
}

static void remote_rx_work(struct work *work)
{
	int ret;
	struct soe_rsp rsp; 	
	soe_handle_t h_soe = (soe_handle_t)work->priv;

	if (soe_is_remote_closing(h_soe) && !h_soe->is_new_connection) {
		return;
	}
	ret = do_read(h_soe->remotefd, &rsp, sizeof(rsp), 3);
	if (ret < 0) {
		soe_err("failed to read from server"); 
		if (ret == -2) {
			soe_set_remote_closing(h_soe, 1);
		}
	} else {
		if (rsp.opcode != SOE_OP_PING) {
			soe_debug("requst: %x %x", rsp.magic, rsp.opcode);
		}
		if (rsp.magic != SOE_MSG_MAGIC) {
			soe_err("read a corrupted response");
		} else {
			soe_handle_remote_response(h_soe, &rsp);
		}
	}
}

static void remote_rx_work_done(struct work *work)
{
	//soe_handle_t h_soe = container_of(work, struct soe_handle_s, remote_work);
	soe_handle_t h_soe = (soe_handle_t)work->priv;
	// soe_info("remote rx enable");
	
	if (soe_is_remote_closing(h_soe) && !h_soe->is_new_connection) {
		return;
	}

	if (remote_rx_ctl(h_soe, 1)) {
		soe_set_remote_closing(h_soe, 1);
	}

	//if (h_soe->is_remote_closing) {
	//	unregister_event(h_soe->remotefd);
	//}
}

void soe_handle_remote_event(soe_handle_t h_soe, int event)
{
	int ret, gotevt = 0;
	struct work *wk = NULL;
	if (event & (EPOLLERR | EPOLLHUP)) {
		/* connection closed */
		soe_err("the connection is closed");
		soe_set_remote_closing(h_soe, 1);
		unregister_event(h_soe->remotefd);
	}

	if (event & EPOLLIN) {
		if (remote_rx_ctl(h_soe, 0)) {
			soe_err("the connection is closed");
			soe_set_remote_closing(h_soe, 1);
			unregister_event(h_soe->remotefd);
		}
		gotevt = 1;
	}

	if (gotevt) {
		wk = alloc_work(h_soe, 0);
		if (wk == NULL) {
			soe_err("failed to allocate the work item, try high priority");
			wk = alloc_work(h_soe, 1);
			if (wk == NULL) {
				soe_err("failed to allocate the work item");
				soe_assert(wk != NULL);	
			}
		}
		wk->fn = remote_rx_work;
		wk->done = remote_rx_work_done;
		queue_work(h_soe->remote_io_queue, wk);
	}
}

void soe_handle_event(int fd, int event, void *data)
{
	soe_handle_t h_soe = (soe_handle_t)data;
	if (fd == h_soe->localfd[1]) {
		soe_handle_local_event(h_soe, event);
	} else { 
		soe_handle_remote_event(h_soe, event);
	}
}

int soe_remote_ioctl(soe_handle_t fd, int cmd, void * inbuf, int inlen, void * outbuf, int* outlen, int wait)
{
	soe_req_c_t req_c;
	int ret;
	int ext = is_soe_ext(cmd);

	if (soe_is_remote_closing(fd)) {
		if (ext) {
			cmd &= 0x7f;
		} else {
			return -EFAULT;
		}
	}
	
	if (cmd != SOE_OP_PING) {
		soe_debug("cmd = %d (%d)", cmd, gl_seq);
	}

	memset(&req_c, 0, sizeof(req_c));	
	req_c.rq.magic = SOE_MSG_MAGIC;
	req_c.rq.seq = gl_seq++;
	if (gl_seq == (uint32_t)-1) {
		gl_seq == 0;
	}
	req_c.rq.opcode = cmd;
	req_c.rq.line = fd->remoteline; 
	req_c.rq.len = inlen;	
	req_c.rq.readlen = (outlen == NULL)?0:*outlen;
	if (req_c.rq.readlen > MAX_REQ_DATA_SIZE) req_c.rq.readlen = MAX_REQ_DATA_SIZE; /* max size is 4096 */

	req_c.data = outbuf;
	req_c.plen = outlen;	

	if (cmd != SOE_OP_PING) {
		soe_debug("send req:op = %d, seq = %d", req_c.rq.opcode, req_c.rq.seq);
	}

	soe_cond_init(&req_c.pending_cond);
	soe_init_mutex(&req_c.pending_lock);

	soe_mutex_lock(&fd->remote_ref_lock);
	if (fd->remotefd_locked || fd->is_released) {
		soe_mutex_unlock(&fd->remote_ref_lock);		
		return -EIO;
	} else {
		fd->remote_refcnt++;
	}

	soe_mutex_unlock(&fd->remote_ref_lock);		

	soe_mutex_lock(&fd->req_lock);
	list_add_tail(&req_c.node, &fd->req_list);
	soe_mutex_unlock(&fd->req_lock);

	ret = send_req(fd->remotefd, &req_c.rq, sizeof(req_c.rq), inbuf, inlen, 3);
	if (ret < 0) {
		soe_mutex_lock(&fd->req_lock);	
		list_del(&req_c.node);
		soe_mutex_unlock(&fd->req_lock);

		soe_mutex_lock(&fd->remote_ref_lock);		
		fd->remote_refcnt--;
		soe_mutex_unlock(&fd->remote_ref_lock);		
		return ret;
	}
	
	soe_mutex_lock(&fd->remote_ref_lock);		
	fd->remote_refcnt--;
	soe_mutex_unlock(&fd->remote_ref_lock);		


	/* timeout 3 seconds */
	soe_mutex_lock(&req_c.pending_lock);
	if (!req_c.wakeup) {
		if (wait) {
			ret = soe_cond_wait_timeout(&req_c.pending_cond, &req_c.pending_lock, wait);
		} else {
			ret = soe_cond_wait(&req_c.pending_cond, &req_c.pending_lock);
		}
	}
	soe_mutex_unlock(&req_c.pending_lock);

	soe_mutex_lock(&fd->req_lock);	
	list_del(&req_c.node);
	while(req_c.refcnt > 0){
		soe_mutex_unlock(&fd->req_lock);
		usleep(1); 
		soe_mutex_lock(&fd->req_lock);	
	}
	soe_mutex_unlock(&fd->req_lock);

	if (ret == ETIMEDOUT) {
		if (cmd != SOE_OP_PING) {
			soe_err("cmd %d timeout", cmd);
		}
		return -ETIMEDOUT;
	} else {
		if (req_c.rp.result)	{
			if (cmd != SOE_OP_PING) {
				soe_debug("cmd end = %d", cmd);
			}
			return -req_c.rp.result;
		} else {
			if (cmd != SOE_OP_PING) {
				soe_debug("cmd end = %d", cmd);
			}
			return 0;
		}
	}
}

int soe_clr_remote_socket_buf(soe_handle_t fd)
{
	struct timeval tmout;      
	int ret;
	fd_set         fds;
	char tmp[2];

	tmout.tv_sec = 0;
	tmout.tv_usec = 0;
	FD_ZERO(&fds);
	FD_SET(fd->remotefd, &fds);
	memset(tmp, 0, sizeof(tmp));

	/* close the event first */		
	if (remote_rx_ctl(fd, 0)) {
		soe_err("the connection is closed");
		soe_set_remote_closing(fd, 1);
		//unregister_event(fd->remotefd);
		return -1;
	}

	while(1)
	{
		ret= select(FD_SETSIZE, &fds, NULL, NULL, &tmout);
		if(ret== 0)  break;
		recv(fd->remotefd, tmp, 1,0);
	}

	if (remote_rx_ctl(fd, 1)) {
		soe_err("the connection is closed");
		soe_set_remote_closing(fd, 1);
		//unregister_event(fd->remotefd);
		return -1;
	}
	return 0;
}

int soe_ping(soe_handle_t fd)
{	
	int ret;

	ret = soe_remote_ioctl(fd, SOE_OP_PING, NULL, 0, NULL, NULL, 200);	
	if (ret < 0) {
		if (ret != -SOE_RES_NO_OBJ) {
			fd->pingerr++;
		} else {
			fd->pingerr = 0;
			ret = 0;
		}
	} else {
		fd->pingerr = 0;
	}
	return ret;
}

int soe_open(soe_handle_t fd)
{
	/* clear the socket first */
	int ret;
	
	if (soe_is_remote_closing(fd))
	       	return -EFAULT;

	soe_mutex_lock(&fd->open_lock);
	if (fd->open_ref) {
		fd->open_ref++;
		soe_mutex_unlock(&fd->open_lock);
		soe_info("soe open: ref = %d", fd->open_ref);
		return 0; 	
	}
	soe_mutex_unlock(&fd->open_lock);

	ret = soe_remote_ioctl(fd, SOE_OP_OPEN, NULL, 0, NULL, NULL, 3000);	
	if (ret < 0) {
		soe_err("failed to open the uart port, errno:%d", ret);
	} else {
		soe_mutex_lock(&fd->open_lock);
		if (fd->open_ref == 0) {
			fd->rb_rp = fd->rb_wp = 0;
		}
		fd->open_ref = 1;
		soe_mutex_unlock(&fd->open_lock);
		soe_info("soe open: ref = %d", fd->open_ref);
	}
	return ret;
}

int soe_clr_int(soe_handle_t fd)
{
	int ret; 	
	ret = soe_remote_ioctl(fd, SOE_OP_CLR_INT, NULL, 0,NULL, NULL, 3000);
	if (ret < 0) {
		if (ret == -SOE_RES_AGAIN) {
			return -SOE_RES_AGAIN;
		}
		soe_err("failed to clear the interrupt");
		return ret;
	}
	return 0;

}

int soe_get_cnt(soe_handle_t fd, struct soe_cnt * pcnt)
{
	int ret, bytes; 	
	bytes = sizeof(struct soe_cnt);
	ret = soe_remote_ioctl(fd, SOE_OP_GET_CNT, NULL, 0,(char *) pcnt, &bytes, 3000);
	if (ret < 0) {
		soe_err("failed to get the count of serial port");
		return ret;	
	}
	return 0;
}

int soe_read(soe_handle_t fd, char *buf, int len)
{
	int ret, bytes = len;
	soe_debug("soe_read: %d", bytes);
	ret = soe_remote_ioctl(fd, SOE_OP_READ, NULL, 0, buf, &bytes, 3000);
	if (ret < 0) {
		soe_err("failed to read the serial port");	
		return ret;
	}
	return bytes;
}

int soe_write(soe_handle_t fd, char *buf, int len)
{
	int ret;
	int waittime;
	/* we need to compute the wait time here */
	if (fd->baudrate != 0) {
		waittime = len * 12000 / fd->baudrate; 	
	} else {
		waittime = 2000;
	}
	if (waittime < 200) {
		waittime = 200;
	}
	ret = soe_remote_ioctl(fd, SOE_OP_WRITE, buf, len, NULL, NULL, waittime);
	if (ret < 0) {
		soe_err("failed to write the serial port");	
		return ret;
	}
	return 0;
}

int soe_setattr(soe_handle_t fd, struct termios * ptio)
{
	int ret;
	int rbaud;
	ret = soe_remote_ioctl(fd, SOE_OP_SET, ptio, sizeof(struct termios), NULL, NULL, 3000);
	if (ret < 0) {
		soe_err("failed to set the serial attr");	
		return ret;
	}
	switch (ptio->c_cflag & CBAUD) {
		case B0: 	rbaud = 0; break;
		case B50:	rbaud = 50; break;
		case B75:	rbaud = 75; break;
		case B110:	rbaud = 110; break;
		case B134:	rbaud = 134; break;
		case B150:  	rbaud = 150; break;
		case B200:	rbaud = 200; break;
		case B300:	rbaud = 300; break;
		case B600:	rbaud = 600; break;
		case B1200: 	rbaud = 1200; break;
		case B1800: 	rbaud = 1800; break;
		case B2400: 	rbaud = 2400; break;
		case B4800: 	rbaud = 4800; break;
		case B9600: 	rbaud = 9600; break;
		case B19200:	rbaud = 19200; break;
		case B38400:	rbaud = 38400; break;
		case B57600:	rbaud = 57600; break;
		case B115200:	rbaud = 115200; break;
		default: rbaud = 9600;
			break;
	}
	fd->baudrate = rbaud;	
	return 0;
}  

int soe_getattr(soe_handle_t fd, struct termios *ptio)
{
	int ret;
	int bytes = sizeof(struct termios);
	ret = soe_remote_ioctl(fd, SOE_OP_GET, NULL, 0, ptio, &bytes, 3000);
	if (ret < 0) {
		soe_err("failed to get the serial attr");	
		return ret;
	}
	return 0;
}

int soe_flush(soe_handle_t fd) 
{
	int ret;
	ret = soe_remote_ioctl(fd, SOE_OP_FLUSH, NULL, 0, NULL, NULL, 3000);
	if (ret < 0) {
		soe_err("failed to flush the serial");
		return ret;
	}
	return 0;
}

int soe_close(soe_handle_t fd)
{
	int ret;
	soe_mutex_lock(&fd->open_lock);
	if (fd->open_ref > 1) {
		fd->open_ref--;
		soe_mutex_unlock(&fd->open_lock);
		soe_info("soe close: ref = %d", fd->open_ref);
		return 0;
	}
	soe_mutex_unlock(&fd->open_lock);
		
	ret = soe_remote_ioctl(fd, SOE_OP_CLOSE, NULL, 0, NULL, NULL, 10000);
	if (ret < 0) {
		soe_err("failed to open the uart port, errno:%d", ret);
	} else {
		soe_mutex_lock(&fd->open_lock);
		fd->open_ref = 0;
		soe_mutex_unlock(&fd->open_lock);
		soe_info("soe close: ref = %d", fd->open_ref);
	}
	return ret;
}


static void crash_handler(int signo, siginfo_t *info, void *context)
{
	soe_emerg("soed client exits unexpectedly (%s), "
			"si pid %d, uid %d, errno %d, code %d",
			strsignal(signo), info->si_pid, info->si_uid,
			info->si_errno, info->si_code);

	soe_backtrace();
	soe_dump_variable(__sys);

	//reraise_crash_signal(signo, 1);
	panic("crashed to core dump");
}

static const char program_name[] = "soe_map";
static char new_program_name[256];

static const char target_help[] =
"Example:\n\t$ soe_map -t 192.168.1.1:1 ...\n"
"This tries to map the /dev/ttyS1 on 192.168.1.1\n";

static const char log_help[] =
"Example:\n\t$ soed -l dir=/var/log/,level=debug ...\n"
"Available arguments:\n"
"\tdir=: path to the location of sheep.log\n"
"\tlevel=: log level of sheep.log\n"
"\tformat=: log format type\n"
"\tdst=: log destination type\n\n"
"if dir is not specified, use metastore directory\n\n"
"Available log levels:\n"
"  Level      Description\n"
"  emerg      system has failed and is unusable\n"
"  alert      action must be taken immediately\n"
"  crit       critical conditions\n"
"  err        error conditions\n"
"  warning    warning conditions\n"
"  notice     normal but significant conditions\n"
"  info       informational notices\n"
"  debug      debugging messages\n"
"default log level is info\n\n"
"Available log format:\n"
"  FormatType      Description\n"
"  default         raw format\n"
"  server          raw format with timestamp\n"
"  json            json format\n\n"
"Available log destination:\n"
"  DestinationType    Description\n"
"  default            dedicated file in a directory used by sheep\n"
"  syslog             syslog of the system\n"
"  stdout             standard output\n";

static struct soe_option soe_options[] = {
	{'t', "targetip", true, "specify the target ip ", target_help},
	{'p', "localport", true, "specify the local serial port number"},
	{'r', "remoteport", true, "specify the remote serial port number"},
	{'l', "log", true,
 	 "specify the log level, the log directory and the log format"
	 "(log level default: 6 [SOE_INFO])", log_help},
	{'h', "help", false, "display this help and exit"},
	{'f', "foreground", false, "make the program run in foreground"},
};

static void sighup_handler(int signo, siginfo_t *info, void *context)
{
	if (unlikely(logger_pid == -1))
		return;

	/* forward SIGHUP for log rotating */
	kill(logger_pid, SIGHUP);
}

static int log_level = SOE_INFO;

static void soelog_help(void)
{
	printf("Available log levels:\n"
			"  Level      Description\n"
			"  emerg      system has failed and is unusable\n"
			"  alert      action must be taken immediately\n"
			"  crit       critical conditions\n"
			"  err        error conditions\n"
			"  warning    warning conditions\n"
			"  notice     normal but significant conditions\n"
			"  info       informational notices\n"
			"  debug      debugging messages\n");
}

static int log_level_parser(const char *s)
{
	int level = loglevel_str2num(s);

	if (level < 0) {
		soe_err("Invalid log level '%s'", s);
		soelog_help();
		return -1;
	}

	log_level = level;
	return 0;
}

static char *logdir;

static int log_dir_parser(const char *s)
{
	logdir = realpath(s, NULL);
	if (!logdir) {
		soe_err("%m");
		exit(1);
	}
	return 0;
}



static const char *log_dst = "default"; /* default: dedicated file */

static int log_dst_parser(const char *s)
{
	log_dst = s;
	return 0;
}

static struct option_parser log_parsers[] = {
	{ "level=", log_level_parser },
	{ "dir=", log_dir_parser },
	{ "dst=", log_dst_parser },
	{ NULL, NULL },
};

static void usage(int status)
{
	if (status) {
		const char *help = option_get_help(soe_options, optopt);

		if (help) {
			printf("%s", help);
			goto out;
		}

		soe_err("Try '%s --help' for more information.", program_name);
	} else {
		struct soe_option *opt;

		printf("soe mapping daemon (version %s)\n"
				"Usage: %s [OPTION]... \n"
				"Options:\n", PACKAGE_VERSION, program_name);

		soe_for_each_option(opt, soe_options) {
			printf("  -%c, --%-18s%s\n", opt->ch, opt->name,
					opt->desc);
		}

		printf("\nTry '%s <option>', e.g., '%s -w', to get more detail "
				"about specific option\n", program_name, program_name);
	}
out:
	exit(status);
}
static int sigfd;

static void signal_handler(int listen_fd, int events, void *data)
{
        struct signalfd_siginfo siginfo;
        int uninitialized_var(ret);
        ret = read(sigfd, &siginfo, sizeof(siginfo));
        soe_assert(ret == sizeof(siginfo));
        soe_info("signal %d, ssi pid %d", siginfo.ssi_signo, siginfo.ssi_pid);
        switch (siginfo.ssi_signo) {
        case SIGTERM:
        case SIGINT:
                sys->status = SOE_STATUS_KILLED;
                break;
        default:
                soe_err("signal %d unhandled", siginfo.ssi_signo);
                break;
        }
}

static int init_signal(void)
{
        sigset_t mask;
        int ret, flag;

        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGINT);
        ret = sigprocmask(SIG_BLOCK, &mask, NULL);

#ifdef _SYS_SIGNALFD_H
        sigfd = signalfd(-1, &mask, SFD_NONBLOCK);
        if (sigfd < 0) {
                soe_err("failed to create a signal fd: %m");
                return -1;
        }
#else
	sigfd = syscall(__NR_signalfd, -1, &mask,  _NSIG / 8);
	if (sigfd < 0) {
                soe_err("failed to create a signal fd: %m");
                return -1;
	}

	flag = fcntl(sigfd, F_GETFL, 0);
	flag |= O_NONBLOCK;
	if (fcntl(sigfd, F_SETFL, flag) < 0) {
                soe_err("failed to set nonblock: %m");
		close(sigfd);
		return -1; 
	}

#endif

        ret = register_event(sigfd, signal_handler, NULL);
        if (ret) {
                soe_err("failed to register signal handler (%d)", ret);
                return -1;
        }

        soe_info("register signal_handler for %d", sigfd);

        return 0;
}

int main(int argc, char *argv[])
{
	soe_handle_t h_soe;
	bool  daemonize = true;
	struct option *long_options;
	const char * short_options;
  	int fd[2], kfd, i, off;
	char cmdline[256];
	struct stat logdir_st;
	int ch, longindex, ret;
	enum log_dst_type log_dst_type;
	int localport = -1, remoteport = -1;
	char * targetip = "127.0.0.1", log_path[PATH_MAX];

	install_crash_handler(crash_handler);
	signal(SIGPIPE, SIG_IGN);
	install_sighandler(SIGHUP, sighup_handler, false);
	
	long_options = build_long_options(soe_options);
	short_options = build_short_options(soe_options);

	off = 0;
	for (i = 0; i < argc; i++) {
		off += snprintf(cmdline + off, sizeof(cmdline) - off, "%s ", argv[i]);		
	}
	
	while ((ch = getopt_long(argc, argv, short_options, long_options,
					&longindex)) >= 0) {
		switch (ch) {
			case 't':
				if (!inetaddr_is_valid(optarg))
					exit(1);
				targetip = optarg;
				break;
			case 'p':
				localport = str_to_u16(optarg);
				if (errno != 0) {
					soe_err("Invalid port number '%s'", optarg);
					exit(1);
				}
				break;
			case 'r':
				remoteport = str_to_u16(optarg);
				if (errno != 0) {
					soe_err("Invalid port number '%s'", optarg);
					exit(1);
				}
				break;
			case 'l':
				if (option_parse(optarg, ",", log_parsers) < 0)
					exit(1);
				break;
			case 'h':
				usage(0);
				break;
			case 'f':
				daemonize = false;
				break;
			default:
				usage(1);
				break;
		}
	}

	if (localport == -1 || remoteport == -1) {
		soe_warn("the local/remote serial port number should be specified");
		return -EINVAL;
	}
	
	if (!strcmp(log_dst, "default"))
		log_dst_type = LOG_DST_DEFAULT;
	else if (!strcmp(log_dst, "stdout"))
		log_dst_type = LOG_DST_STDOUT;
	else if (!strcmp(log_dst, "syslog"))
		log_dst_type = LOG_DST_SYSLOG;
	else {
		soe_err("invalid type of log destination: %s", log_dst);
		exit(1);
	}

	if (logdir) {
		if (log_dst_type != LOG_DST_DEFAULT) {
			soe_err("logdir (%s) is specified but logging"
					" destination is %s", logdir,
					log_dst_type == LOG_DST_STDOUT
					? "stdout" : "syslog");
			exit(1);
		}

		memset(&logdir_st, 0, sizeof(logdir_st));
		ret = stat(logdir, &logdir_st);
		if (ret < 0) {
			soe_err("stat() failed on %s, %m", logdir);
			exit(1);
		}

		if (!S_ISDIR(logdir_st.st_mode)) {
			soe_err("log dir: %s is not a directory", logdir);
			exit(1);
		}
	}
	
	snprintf(log_path, sizeof(log_path), "%s/soe_port%d.log",
			logdir?:LOG_DIR_DEFAULT, localport);

	if (logdir) 
		wfree(logdir);

#if 0
	if (daemonize && log_dst_type == LOG_DST_STDOUT)
		daemonize = false;
#endif
	if (access("/sys/module/soe_uart", F_OK) != 0) {
		soe_err("kernel module is not loaded, exit");	
		goto end;
	}

#if 0
	if (soe_daemonize(daemonize)) {
		goto end;
	}
#endif
#if 1
	snprintf(new_program_name, sizeof(new_program_name), "%s %d", program_name, localport);
	ret = log_init(argv[0], new_program_name, log_dst_type, log_level, log_path, 0, 2);
	if (ret) {
		goto end;
	}
#endif

	soe_info("cmdline:%s", cmdline);	
	ret = init_event(256);
	if (ret) {
		soe_err("failed to init event");
		goto cleanup_log;	
	}
	
	ret = init_signal();
	if (ret) {
		soe_err("failed to init signal");
		goto cleanup_events;
	}

	req_buf_cache = soe_cache_init("request data cache", 1024, 64); 
	if (req_buf_cache == NULL) {
		goto cleanup_signal;			
	}
	
	ret = init_work_queue();
	if (ret) {
		goto cleanup_cache;
	}

	h_soe = soe_connect(targetip, localport, remoteport);
	if (!h_soe) {
		soe_err("failed to connect %s", targetip);
		goto cleanup_queue;;
	}

	soe_info("%s(%s): map %s ttyS%d to ttySOE%d", program_name, PACKAGE_VERSION,  targetip, remoteport, localport);
	while ((sys->status != SOE_STATUS_KILLED &&
		 	sys->status != SOE_STATUS_SHUTDOWN)) {
		event_loop(-1);
	}

	soe_release(h_soe);
cleanup_queue:
	cleanup_queue();		
cleanup_cache:
	soe_cache_cleanup();
cleanup_signal:
	unregister_event(sigfd);
	close(sigfd);
cleanup_events:
	soe_info("Cleanup: events");
	events_close();
cleanup_log:
	soe_info("soe mapping is exiting");
	log_close();
end:
	return 0;
}
