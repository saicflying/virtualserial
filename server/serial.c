

#include <termios.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "work.h" 
#include "list.h"
#include "util.h"
#include "serial.h" 
#define MAX_SERIAL_NUM 32
#define MAX_UART_BUFFER 4096

static int soe_detect_serials();
static void soe_ci_shutdown_notify(struct client_info *ci);
static int soe_serial_count = 0;
static pthread_t soe_serial_detect_thread = 0; 

#define FIFO_SIZE(w,r) (((w) >= (r))?((w)-(r)):((w) + MAX_UART_BUFFER - (r)))
#define FIFO_RX_SIZE(puart) FIFO_SIZE(((puart)->read_wp), ((puart)->read_rp))
#define FIFO_TX_SIZE(puart) FIFO_SIZE(((puart)->write_wp), ((puart)->write_rp))
#define FIFO_POS(p) ((p) % MAX_UART_BUFFER)

typedef struct phy_serial {
	struct list_node node;
	char name[50];
	int fd;
	int line;
	struct termios tio;
	struct list_head virt_map;
	struct client_info * active_client;

	struct soe_mutex evt_lock;			
	unsigned int events;
	struct soe_cond  read_pending_cond;
	struct soe_mutex read_pending_lock;
	struct soe_cond  write_pending_cond;
	struct soe_mutex write_pending_lock;
	struct work_queue *io_queue;

	struct soe_mutex lock;
	char * read_buf; 
	int    read_rp, read_wp; 	
	char * write_buf; 
	int    write_rp, write_wp; 	
	int  refcnt;
	int  notified;
	int  read_buffull;
	uint64_t notified_time_ms;  

	int  client_left;
	int  is_closing;
	soe_thread_info_t read_thread;
	soe_thread_info_t write_thread;
	int errwrite, errread, errothers;
	
	uint32_t send_seq;
} phy_serial_t;

struct soe_op_template {
	const char *name;
        int (*process_work)(struct request *req);
        int (*process_main)(const struct soe_req *req, struct soe_rsp *rsp,
	                           void *data);  
};

struct soe_mutex phy_serials_lock = SOE_MUTEX_INITIALIZER;  
static LIST_HEAD(phy_serials_list);

static phy_serial_t *soe_find_serial_by_connection(struct client_info * ci);
static phy_serial_t *soe_find_serial_by_line(int line);
static phy_serial_t *soe_find_serial(const char *name);
static int soe_map_serial(struct request *);
static int soe_open_serial(struct request *);
static int soe_get_serial_cnt(struct request *);
static int soe_clr_int(struct request *);
static int soe_ping(struct request * req);
static int soe_close_serial(struct request *);
static int soe_get_serial(struct request *);
static int soe_set_serial(struct request *);
static int soe_read_serial(struct request *);
static int soe_write_serial(struct request *);
static int soe_flush_serial(struct request *);
static void soe_notify_serial(phy_serial_t *);
static int soe_init_serial(phy_serial_t *);
static void soe_deinit_serial(phy_serial_t * puart);
static void *serial_write_thread(void *arg);
static void *serial_read_thread(void *arg);

static int serial_open(phy_serial_t *, struct client_info *);
static int serial_close(phy_serial_t *);
static int serial_write(phy_serial_t *, char *, int);
static int serial_read(phy_serial_t *, char *, uint16_t *);
static int serial_rx_on(phy_serial_t *);
static int serial_rx_off(phy_serial_t *);
static int serial_tx_on(phy_serial_t *); 
static int serial_tx_off(phy_serial_t *); 
static int serial_err_process(phy_serial_t *); 


struct soe_op_template soe_ops[] = {
#if 0
		[SOE_OP_MAP] = {
			.name = "Map Serial",
			.process_work = soe_map_serial,
			.process_main = NULL,
		},
#endif
		[SOE_OP_GET_CNT] = {
			.name = "Get Serial Count",
			.process_work = soe_get_serial_cnt,
			.process_main = NULL,
		},
		[SOE_OP_OPEN] = {
			.name = "Open Serial",
			.process_work = soe_open_serial,
			.process_main = NULL,
		},
		[SOE_OP_CLOSE] = {
			.name = "Close Serial",
			.process_work = soe_close_serial,
			.process_main = NULL,
		},
		[SOE_OP_SET] = {
			.name = "Set Serial attributes",
			.process_work = soe_set_serial,
			.process_main = NULL,
		},
		[SOE_OP_GET] = {
			.name = "Get Serial attributes",
			.process_work = soe_get_serial,
			.process_main = NULL,
		},
		[SOE_OP_READ] = {	
			.name = "Read Serial",
			.process_work = soe_read_serial,
			.process_main = NULL,
		},
		[SOE_OP_WRITE] = {	
			.name = "Write Serial",
			.process_work = soe_write_serial,
			.process_main = NULL,
		},
		[SOE_OP_FLUSH] = {	
			.name = "Flush Serial",
			.process_work = soe_flush_serial,
			.process_main = NULL,
		},
		[SOE_OP_CLR_INT] = {
			.name = "Clear Int",
			.process_work = soe_clr_int,
			.process_main = NULL,
		},
		[SOE_OP_PING] = {
			.name = "Ping",
			.process_work = soe_ping, 	
			.process_main = NULL,
		},
};

static void soe_serial_event(int fd, int events, void *data)
{
	phy_serial_t * puart = (phy_serial_t *)data;
	if (events & (EPOLLERR | EPOLLHUP)) {
		soe_err("event find EPOLLERR|EPOLLHUP:%x", events);
	}

	if (events & EPOLLIN) {
		serial_rx_off(puart);
		soe_debug("signal");
		soe_cond_signal(&puart->read_pending_cond);
	}
}

#define UART_CONFIG_FILE "/root/.uart.config.%d"
static int store_serial_config(phy_serial_t *puart)
{
	char filename[256];
	FILE * fp;
	snprintf(filename, sizeof(filename), UART_CONFIG_FILE, puart->line);
	fp = fopen(filename, "w");
	if (fp == NULL) {
		soe_warn("failed to find the uart configuration for ttyS%d", puart->line);
		return SOE_RES_EIO;
	}

	fprintf(fp, "c_cflag=0x%08x\n", puart->tio.c_cflag);
	fprintf(fp, "c_ispeed=0x%08x\n", puart->tio.c_ispeed);
	fprintf(fp, "c_ospeed=0x%08x\n", puart->tio.c_ospeed);
	fclose(fp);
	return SOE_RES_SUCCESS;	
}

static int load_serial_config(phy_serial_t *puart)
{
	char filename[256];
	FILE * fp;
	unsigned int c_cflag, c_ispeed, c_ospeed;
	snprintf(filename, sizeof(filename), UART_CONFIG_FILE, puart->line);
	fp = fopen(filename, "r");
	if (fp == NULL) {
		soe_warn("failed to find the uart configuration for ttyS%d", puart->line);
		return -1;
	}
	if (fscanf(fp, "c_cflag=0x%08x\n", &c_cflag) != 1) {
		soe_err("failed to get c_cflag");
		fclose(fp);
		return -2;
	}
		
	if (fscanf(fp, "c_ispeed=0x%08x\n", &c_ispeed) != 1) {
		soe_err("failed to get c_cflag");
		fclose(fp);
		return -2;
	}
	
	if (fscanf(fp, "c_ospeed=0x%08x\n", &c_ospeed) != 1) {
		soe_err("failed to get c_cflag");
		fclose(fp);
		return -3;
	}
	puart->tio.c_cflag  = c_cflag;
	puart->tio.c_ispeed = c_ispeed;
	puart->tio.c_ospeed = c_ospeed;

	fclose(fp);
	return 0;
}

static int soe_init_serial(phy_serial_t * puart)
{
	char qname[256];
	int ret;
	struct epoll_event ev;

	soe_init_mutex(&puart->lock);
	soe_init_mutex(&puart->evt_lock);

	soe_init_mutex(&puart->read_pending_lock);
	soe_cond_init(&puart->read_pending_cond);

	soe_init_mutex(&puart->write_pending_lock);
	soe_cond_init(&puart->write_pending_cond);

	ret = register_event(puart->fd, soe_serial_event, puart); 
	if (ret < 0) {
		goto failend;
	}	

	cfsetspeed(&puart->tio, B9600);
	puart->tio.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);	
	puart->tio.c_iflag &= ~(IXON | IXOFF | IXANY);
	puart->tio.c_oflag &= ~OPOST;
	puart->tio.c_cc[VMIN] = 1;
	puart->tio.c_cc[VTIME] = 10;
	
	load_serial_config(puart);
	
	soe_info("set ttyS%d as c_cflag = %08x", puart->line, puart->tio.c_cflag);
	if (tcsetattr(puart->fd, TCSANOW, &puart->tio) < 0) {
		goto failend;
	}
		
	puart->read_buf = wmalloc(MAX_UART_BUFFER);
	puart->read_rp = puart->write_rp = 0;
	puart->write_buf = wmalloc(MAX_UART_BUFFER);
	puart->read_wp = puart->write_wp = 0;

	if (puart->read_buf == NULL || puart->write_buf == NULL) {
		goto failend;	
	}

	snprintf(qname, sizeof(qname), "%s io queue", puart->name);
	puart->io_queue = create_work_queue(qname);
	if (!puart->io_queue) {
		goto failend;	
	}
	INIT_LIST_HEAD(&puart->virt_map);

	puart->refcnt = 0;
	if (soe_thread_create(puart->name, &puart->read_thread, serial_read_thread, puart) < 0) {
		puart->read_thread = NULL;
		goto failend;
	}

	if (soe_thread_create(puart->name, &puart->write_thread, serial_write_thread, puart) < 0) {
		puart->write_thread = NULL;
		goto failend;
	}
	return 0;
failend:
	soe_deinit_serial(puart);
	return -1;	
}

static void soe_deinit_serial(phy_serial_t * puart)
{
	puart->is_closing = 1;

	unregister_event(puart->fd);

	if (puart->read_thread) {
		soe_cond_signal(&puart->read_pending_cond);
		soe_thread_join(puart->read_thread);
		puart->read_thread = NULL;
	}

	if (puart->write_thread) {
		soe_cond_signal(&puart->write_pending_cond);
		soe_thread_join(puart->write_thread);
		puart->write_thread = NULL;
	}

	if (puart->io_queue) {
		destroy_queue(puart->io_queue);
		puart->io_queue = NULL;
	}
	if (puart->read_buf) {
		wfree(puart->read_buf);
		puart->read_buf = NULL;
	}
	if (puart->write_buf) {
		wfree(puart->write_buf);
		puart->write_buf = NULL;
	}

}


static int serial_err_process(phy_serial_t * puart)	
{
	return 0;	
}

static int serial_open(phy_serial_t * pserial, struct client_info * ci)
{
	soe_mutex_lock(&pserial->lock);
	if (pserial->active_client) {
		soe_err("serial busy: original: %s, %d, curr: %s, %d", pserial->active_client->conn.ipstr, 
				pserial->active_client->conn.port, 
				ci->conn.ipstr, ci->conn.port);
		soe_mutex_unlock(&pserial->lock);
		return SOE_RES_BUSY;
	}
	/* re-init the serial */
	pserial->active_client = ci;
	pserial->active_client->priv_data = pserial;
	pserial->read_rp = pserial->read_wp = 0;
	pserial->write_rp = pserial->write_wp = 0;
	pserial->send_seq = 0;
	/* turn on rx, turn off tx */
	tcflush(pserial->fd, TCIFLUSH);
	serial_rx_on(pserial);
	//serial_tx_off(pserial);
	soe_mutex_unlock(&pserial->lock);
	soe_info("ttyS%d is opened by %s:%d", pserial->line,   ci->conn.ipstr, ci->conn.port);
	return 0;
}

static int serial_close(phy_serial_t * pserial)
{
	pserial->client_left = 1;
	soe_info("ttyS%d is closing by %s:%d", pserial->line, pserial->active_client->conn.ipstr, pserial->active_client->conn.port);
	soe_mutex_lock(&pserial->lock);
	while(pserial->refcnt) {
		soe_mutex_unlock(&pserial->lock);
		sleep(0);
		soe_mutex_lock(&pserial->lock);
	}
	soe_info("ttyS%d is closed by %s:%d", pserial->line, pserial->active_client->conn.ipstr, pserial->active_client->conn.port);
	pserial->active_client->priv_data = NULL;
	pserial->active_client = NULL; /* clear the owner infomation */
	pserial->client_left = 0;
	serial_rx_off(pserial);
	//serial_tx_off(pserial);
	pserial->read_rp = pserial->read_wp = 0;
	pserial->write_rp = pserial->write_wp = 0;
	soe_mutex_unlock(&pserial->lock);
	return 0;
}

static int serial_write(phy_serial_t * puart, char * buf, int len)
{
	int one_len;
	int free_len;
	static int total_len = 0;
	int total_time = 0;
	total_len += len;
	soe_debug("serial write:%d, %d, %d tl:%d", len, FIFO_TX_SIZE(puart), MAX_UART_BUFFER - 1 - FIFO_TX_SIZE(puart), total_len);
	soe_mutex_lock(&puart->lock);
	while(len) {
		free_len = MAX_UART_BUFFER - 1 - FIFO_TX_SIZE(puart);
		if (free_len == 0) {
			soe_mutex_unlock(&puart->lock);
			soe_warn("the write buffer is full");
			usleep(1000);
			soe_mutex_lock(&puart->lock);
			continue;
		}
		one_len = min(len, min(free_len, MAX_UART_BUFFER - puart->write_wp));
		memcpy(puart->write_buf + puart->write_wp, buf, one_len); 	
		puart->write_wp = FIFO_POS(puart->write_wp + one_len);
		len -= one_len;
		buf += one_len;
		//serial_tx_on(puart);
	}
	/* waiting for empty */
	while(FIFO_TX_SIZE(puart)) {
		soe_cond_signal(&puart->write_pending_cond);
		soe_mutex_unlock(&puart->lock);
		usleep(10);
		soe_mutex_lock(&puart->lock);
		total_time += 10;
		if (total_time >= 1000000UL) {
			/* total time is over 1 second */
			break;
		}
	}
	soe_mutex_unlock(&puart->lock);
	return 0;
}

static int serial_read(phy_serial_t * puart, char * buf, uint16_t * plen)
{
	int datainbuf;  
	int readlen;
	int one_len;

	soe_mutex_lock(&puart->lock);
	datainbuf = FIFO_RX_SIZE(puart);  
	readlen = min(datainbuf, (int)*plen);
	*plen = readlen;
	while(readlen) {
		one_len = min(readlen, MAX_UART_BUFFER - puart->read_rp); 
		memcpy(buf, puart->read_buf + puart->read_rp, one_len);
		puart->read_rp = FIFO_POS(puart->read_rp + one_len);
		readlen -= one_len;
		buf	+= one_len;	
	}
	soe_mutex_unlock(&puart->lock);
	return 0;
}

static void *serial_read_thread(void *arg) 
{
	int i, nr;
	int bytes, ret, recvleft;
	struct epoll_event event;
	int len, count = 0, errcnt = 0;
	phy_serial_t * puart = (phy_serial_t *)arg;	
	soe_info("read thread for %s", puart->name);

	setpriority(PRIO_PROCESS, 0, -15);
	while(!soe_thread_should_stop()) {
		soe_mutex_lock(&puart->read_pending_lock);
		ret = soe_cond_wait_timeout(&puart->read_pending_cond, &puart->read_pending_lock, 1000);
		soe_mutex_unlock(&puart->read_pending_lock);
		if (puart->is_closing) {
			break;
		}
serial_in:
		soe_mutex_lock(&puart->lock);
		if (puart->active_client && !puart->client_left) {
			puart->refcnt++;
		} else {
			tcflush(puart->fd, TCIFLUSH);
			soe_mutex_unlock(&puart->lock);
			serial_rx_on(puart);
			sleep(0);
			continue;
		}
		soe_mutex_unlock(&puart->lock);

		bytes = recvleft = 0;
		ret = ioctl(puart->fd, FIONREAD, &bytes);
		if (ret < 0) {
			soe_err("failed to get the data count for serial %s", puart->name);
			puart->errothers++;
			errcnt++;
		} else {
			if (bytes) {
				recvleft = bytes;
				soe_debug("/dev/ttyS%d uart has: %d", puart->line, bytes);
				bytes = min(bytes, MAX_UART_BUFFER - 1 - FIFO_RX_SIZE(puart));
				if (bytes == 0) {
					soe_info("/dev/ttyS%d uart buffer full", puart->line);
					puart->read_buffull = 1;
				} else {
					while (bytes) {
						count++;
						len = min(bytes, MAX_UART_BUFFER - puart->read_wp);
						ret = read(puart->fd, puart->read_buf + puart->read_wp, len); 
						if (ret < 0) {
							soe_err("failed to read the data from serial:%s", puart->name); 
							errcnt++;
							puart->errread++;
							if (errcnt > 3) {
								break;
							}
						} else {
							soe_debug("/dev/ttyS%d read: %d(%d)", puart->line, ret, len);
							recvleft -= ret;
							bytes -= ret;
							puart->read_wp = FIFO_POS(puart->read_wp + ret);
						}
						count++;
						if (count > 5) 
							break;
					}
				}
			}
			if (FIFO_RX_SIZE(puart) > 0) {
				soe_debug("/dev/ttyS%d fifo rx: %d", puart->line, FIFO_RX_SIZE(puart));
				soe_notify_serial(puart);
			}
			if (recvleft <= 0) {
				serial_rx_on(puart);
			}
		}

		soe_cond_init(&puart->read_pending_cond);
		soe_mutex_lock(&puart->lock);
		puart->refcnt--;
		if (recvleft > 0) {
			soe_mutex_unlock(&puart->lock);
			goto serial_in;
		}
		soe_mutex_unlock(&puart->lock);
	}

	soe_info("read thread exit for %s", puart->name);
	return NULL;
}
static void *serial_write_thread(void *arg)
{
	int i, nr;
	int bytes, ret, sendleft, recvleft;
	struct epoll_event event;
	int len, count = 0, errcnt = 0;
	phy_serial_t * puart = (phy_serial_t *)arg;	
	soe_info("write thread for %s", puart->name);

	setpriority(PRIO_PROCESS, 0, -15);
	while(!soe_thread_should_stop()) {
		soe_mutex_lock(&puart->write_pending_lock);
		ret = soe_cond_wait_timeout(&puart->write_pending_cond, &puart->write_pending_lock, 1000);
		soe_mutex_unlock(&puart->write_pending_lock);
		if (puart->is_closing) {
			break;
		}

serial_out:
		soe_mutex_lock(&puart->lock);
		if (puart->active_client) {
			puart->refcnt++;
		} else {
			tcflush(puart->fd, TCOFLUSH);
			soe_mutex_unlock(&puart->lock);
			continue;
		}
		soe_mutex_unlock(&puart->lock);

		bytes = min(256, FIFO_TX_SIZE(puart));
		if (bytes) {
			count = 0;
			while (bytes) {
				len = min(bytes, MAX_UART_BUFFER - puart->write_rp);
				soe_debug("/dev/ttyS%d send out %d",puart->line, len);
				ret = write(puart->fd, puart->write_buf + puart->write_rp, len); 
				if (ret < 0) {
					soe_err("failed to write the data to serial:%s, errno = %d", puart->name, errno); 
					errcnt++;
					puart->errwrite++;
					if (errcnt > 3) {
						break;
					}
				} else {
					tcdrain(puart->fd);
					bytes -= ret;	
					puart->write_rp = FIFO_POS(puart->write_rp + ret);
				}
				count++;
				if (count > 5) 
					break;
			}
		} 

		soe_mutex_lock(&puart->lock);
		soe_cond_init(&puart->write_pending_cond);
		puart->refcnt--;
		if (FIFO_TX_SIZE(puart) && puart->client_left == 0) {
			soe_mutex_unlock(&puart->lock);
			sleep(0);
			goto serial_out;
		}
		soe_mutex_unlock(&puart->lock);
	}
	soe_info("write thread exit for %s", puart->name);
	return NULL;
}

static int soe_map_serial(struct request * req)
{
	return 0;	
}

static int soe_ping(struct request * req) 
{
	req->ci->conn.timestamp_ping = times(NULL);	
	// soe_info("timestamp:%ld, %ld", req->ci->conn.timestamp_ping, sysconf(_SC_CLK_TCK));
	return SOE_RES_SUCCESS;
}

static int soe_clr_int(struct request * req)
{
	phy_serial_t * pserial = soe_find_serial_by_connection(req->ci);
	phy_serial_t * ptgt_serial = (phy_serial_t *)req->priv_data;
	struct soe_cnt * pcnt = req->data;
	if (pserial) {
		if (pserial->line == req->rq.line) {
			soe_mutex_lock(&pserial->lock);
			pserial->notified = 0;
			if (FIFO_RX_SIZE(pserial)) {
				soe_mutex_unlock(&pserial->lock);
				return SOE_RES_AGAIN; 
			}
			soe_mutex_unlock(&pserial->lock);
			return SOE_RES_SUCCESS;
		}
	}
	return SOE_RES_NO_AUTH;
}

static int soe_get_serial_cnt(struct request * req)
{
	phy_serial_t * pserial = soe_find_serial_by_connection(req->ci);
	phy_serial_t * ptgt_serial = (phy_serial_t *)req->priv_data;
	struct soe_cnt * pcnt = req->data;
	uint64_t curtime = get_msec_time();	

	if (pserial) {
		if (pserial->line == req->rq.line) {
			soe_mutex_lock(&pserial->lock);
			pserial->notified_time_ms = curtime;
			soe_mutex_unlock(&pserial->lock);
			pcnt->rxcnt    = FIFO_RX_SIZE(pserial);
			pcnt->txcnt    = MAX_UART_BUFFER - 1 - FIFO_TX_SIZE(pserial);
			pcnt->errwrite = pserial->errwrite;
			pcnt->errread  = pserial->errread;
			pcnt->errothers = pserial->errothers;
			req->rp.readlen = sizeof(struct soe_cnt);
			req->rp.len = sizeof(struct soe_cnt);
			return SOE_RES_SUCCESS;
		}
	}
	return SOE_RES_NO_AUTH;
}

static int soe_open_serial(struct request * req)
{
	phy_serial_t * pserial = soe_find_serial_by_connection(req->ci);
	phy_serial_t * ptgt_serial = (phy_serial_t *)req->priv_data;
	if (pserial) {
		if (pserial->line == req->rq.line) {
			/* already opened */
			return 0;	
		}
		serial_close(pserial);
	}

	return serial_open(ptgt_serial, req->ci);
}

static int soe_close_serial(struct request * req)
{
	phy_serial_t * pserial = soe_find_serial_by_connection(req->ci);
	phy_serial_t * ptgt_serial = (phy_serial_t *)req->priv_data;
	if (pserial) {
		if (pserial->line == req->rq.line) {
			serial_close(pserial);
			return 0;
		}
	}
	return SOE_RES_NO_AUTH; 
}

static int soe_get_serial(struct request * req)
{
	phy_serial_t * pserial = soe_find_serial_by_connection(req->ci);
	phy_serial_t * ptgt_serial = (phy_serial_t *)req->priv_data;
	struct termios * ptio = req->data;
	if (pserial) {
		if (pserial->line == req->rq.line) {
			memcpy(ptio, &pserial->tio, sizeof(struct termios));
			req->rp.readlen = sizeof(*ptio);
			req->rp.len = req->rp.readlen; 
			return SOE_RES_SUCCESS;
		}
	}
	return SOE_RES_NO_AUTH;
}

static int soe_set_serial(struct request * req)
{
	phy_serial_t * pserial = soe_find_serial_by_connection(req->ci);
	phy_serial_t * ptgt_serial = (phy_serial_t *)req->priv_data;
	struct termios * ptio = req->data, tmpios; 
	int ret;
	if (pserial) {
		if (pserial->line == req->rq.line) {
			if (req->rq.len != sizeof(struct termios)) {
				return SOE_RES_INVALID_PARMS;
			}
			memcpy(&tmpios, &pserial->tio, sizeof(tmpios));
			soe_mutex_lock(&pserial->lock);
			tmpios.c_cflag = ptio->c_cflag;
			tmpios.c_ispeed = ptio->c_ispeed;
			tmpios.c_ospeed = ptio->c_ospeed;
			
			ret = tcsetattr(pserial->fd, TCSANOW, &tmpios);
			if (ret < 0) {	
				soe_mutex_unlock(&pserial->lock);
				return SOE_RES_UNKNOWN;
			}
			soe_mutex_unlock(&pserial->lock);
			memcpy(&pserial->tio, &tmpios, sizeof(struct termios));
			
			return store_serial_config(pserial);
		}
	}
	return SOE_RES_NO_AUTH;
}

static int soe_read_serial(struct request * req)
{
	int ret;
	phy_serial_t * pserial = soe_find_serial_by_connection(req->ci);
	phy_serial_t * ptgt_serial = (phy_serial_t *)req->priv_data;
	if (pserial) {
		if (pserial->line == req->rq.line) {
			ret = serial_read(pserial, req->data, &req->rq.readlen);
			req->rp.readlen = req->rq.readlen;
			req->rp.len = req->rp.readlen; 
			if (pserial->read_buffull) {
				pserial->read_buffull = 0;
				soe_cond_signal(&pserial->read_pending_cond);
			}
			return ret;
		}
	}
	return SOE_RES_NO_AUTH;
}

static int soe_write_serial(struct request * req)
{
	phy_serial_t * pserial = soe_find_serial_by_connection(req->ci);
	phy_serial_t * ptgt_serial = (phy_serial_t *)req->priv_data;
	
	if (pserial) {
		if (pserial->line == req->rq.line) {
			return serial_write(pserial, req->data, req->rq.len);
		}
	}
	return SOE_RES_NO_AUTH;
}

static int soe_flush_serial(struct request * req)
{
	phy_serial_t * pserial = soe_find_serial_by_connection(req->ci);
	phy_serial_t * ptgt_serial = (phy_serial_t *)req->priv_data;
	if (pserial) {
		if (pserial->line == req->rq.line) {
			soe_mutex_lock(&pserial->lock);
			while(pserial->refcnt) {
				soe_mutex_unlock(&pserial->lock);
				sleep(0);
				soe_mutex_lock(&pserial->lock);
			}
			tcflush(pserial->fd, TCIOFLUSH);
			pserial->read_rp = pserial->read_wp = 0;
			pserial->write_rp = pserial->write_wp = 0;
			soe_mutex_unlock(&pserial->lock);
		}
	}
	return SOE_RES_NO_AUTH;
}

static void soe_notify_serial(phy_serial_t * pserial)
{
#if 1
	struct request *req = NULL;
	uint64_t curtime = get_msec_time();	
	int    count;

	soe_mutex_lock(&pserial->lock);
#if 0
	if (pserial->notified) {
		if (curtime <= pserial->notified_time_ms + 2) {
			soe_mutex_unlock(&pserial->lock);
			return;
		}
	}
#endif
	soe_debug("send notify");
	if (pserial->active_client && !pserial->client_left) {
		req = alloc_request(pserial->active_client, 256);	
		if (req == NULL) {
			goto fail;
		}

		req->rp.magic = SOE_MSG_MAGIC;
		req->rp.seq = (uint32_t)pserial->send_seq++; 
		req->rp.opcode = SOE_OP_INT; 
		req->rp.line = pserial->line;

		count = min(FIFO_RX_SIZE(pserial), 256);
		count = min(MAX_UART_BUFFER - pserial->read_rp, count);
		memcpy(req->data, pserial->read_buf + pserial->read_rp, count);
		pserial->read_rp = FIFO_POS(pserial->read_rp + count);

		req->rp.readlen = req->rp.len = count;
		req->rp.flags = SOE_FLAG_DATA_READY; 
		req->rp.result = SOE_RES_SUCCESS;
		
		pserial->notified_time_ms = curtime;
	}
fail:
	soe_mutex_unlock(&pserial->lock);
	if (req) {
		pserial->notified = 1;
        	put_request(req);
	}
#endif
}

int soe_get_serial_count()
{
	if (0 == soe_serial_count) {
		soe_serial_count = soe_detect_serials();
		register_shutdown_notifer(soe_ci_shutdown_notify);
	}
	return soe_serial_count;
}

const struct soe_op_template *get_soe_op(uint8_t opcode)
{
	return soe_ops + opcode;
}

const char *op_name(const struct soe_op_template *op)
{
	if (op == NULL)
		return "(invalid opcode)";

	return op->name;
}

bool has_process_work(const struct soe_op_template *op)
{
	return op != NULL && !!op->process_work;
}

bool has_process_main(const struct soe_op_template *op)
{
	return op != NULL && !!op->process_main;
}

static void soe_ci_shutdown_notify(struct client_info *ci)
{
	phy_serial_t * pserial = soe_find_serial_by_connection(ci);
	if (pserial) {
		serial_close(pserial);
	}
}

static int serial_rx_on(phy_serial_t * puart)
{
	soe_mutex_lock(&puart->evt_lock);
	if (puart->events & EPOLLIN) {
		soe_mutex_unlock(&puart->evt_lock);
		return 0;
	}
	soe_mutex_unlock(&puart->evt_lock);
	puart->events |= EPOLLIN; 	
	return modify_event(puart->fd, puart->events);
}

static int serial_rx_off(phy_serial_t * puart)
{
	soe_mutex_lock(&puart->evt_lock);
	if (!(puart->events & EPOLLIN)) {
		soe_mutex_unlock(&puart->evt_lock);
		return 0;
	}
	puart->events &= ~EPOLLIN; 	
	soe_mutex_unlock(&puart->evt_lock);
	return modify_event(puart->fd, puart->events);
}

#if 0
static int serial_tx_on(phy_serial_t * puart)
{
	soe_debug("tx on");
	soe_mutex_lock(&puart->evt_lock);
	if (puart->events & EPOLLOUT) {
		soe_mutex_unlock(&puart->evt_lock);
		return 0;
	}
	puart->events |= EPOLLOUT; 	
	soe_mutex_unlock(&puart->evt_lock);

	return serial_modify_evt(puart);
}

static int serial_tx_off(phy_serial_t * puart)
{
	soe_mutex_lock(&puart->evt_lock);
	if (FIFO_TX_SIZE(puart)) {
		soe_mutex_unlock(&puart->evt_lock);
		return 0;
	}
	soe_debug("tx off");
	if (!(puart->events & EPOLLOUT)) {
		soe_mutex_unlock(&puart->evt_lock);
		return 0;
	} 
	puart->events &= ~EPOLLOUT; 	
	soe_mutex_unlock(&puart->evt_lock);
	return serial_modify_evt(puart);
}
#endif
void do_process_work(struct work *work)
{
	//struct request *req = container_of(work, struct request, work);
	struct request *req = (struct request *)work->priv;
	int ret = SOE_RES_SUCCESS;

	if (req->rq.opcode != SOE_OP_PING) {
		soe_debug("line=%d op = %x, seq = %d", req->rq.line, req->rq.opcode, req->rq.seq);
	}

	if (req->op->process_work)
		ret = req->op->process_work(req);

	if (ret != SOE_RES_SUCCESS) {
		soe_err("failed: %x, %s", req->rq.opcode, soe_strerror(ret));
	}
	soe_assert(req->rp.len <= req->rq.readlen);
	req->rp.result = ret;
}

int do_process_main(const struct soe_op_template *op, const struct soe_req *req,
		struct soe_rsp *rsp, void *data)
{
	return op->process_main(req, rsp, data);
}

static phy_serial_t *soe_find_serial_by_connection(struct client_info * ci)
{
	phy_serial_t * pserial = NULL, *tmp;	
	soe_mutex_lock(&phy_serials_lock);
	list_for_each_entry(pserial, tmp, &phy_serials_list, node) {
		if (pserial->active_client == ci) {
			soe_mutex_unlock(&phy_serials_lock);
			return pserial;
		}
	}
	soe_mutex_unlock(&phy_serials_lock);
	return NULL;
}

static phy_serial_t *soe_find_serial_by_line(int line)
{
	phy_serial_t * pserial = NULL, *tmp;	
	soe_mutex_lock(&phy_serials_lock);
	list_for_each_entry(pserial, tmp, &phy_serials_list, node) {
		if (pserial->line == line) {
			soe_mutex_unlock(&phy_serials_lock);
			return pserial;
		}	
	}
	soe_mutex_unlock(&phy_serials_lock);
	return NULL;
}

static phy_serial_t *soe_find_serial(const char *name)
{
	phy_serial_t * pserial = NULL, *tmp;	
	soe_mutex_lock(&phy_serials_lock);
	list_for_each_entry(pserial, tmp, &phy_serials_list, node) {
		if (strcmp(name, pserial->name) == 0) {
			soe_mutex_unlock(&phy_serials_lock);
			return pserial;
		}	
	}
	soe_mutex_unlock(&phy_serials_lock);
	return NULL;
}

static int soe_serial_is_console(int line)
{
	static char consoles[MAX_SERIAL_NUM * 7 + 1] = {'\0'};
	char filename[PATH_MAX], *psz;
	struct stat sts;
	snprintf(filename, PATH_MAX, "ttyS%d ", line);
	if (consoles[0] == '\0') {
		FILE *fp;
		char buf[256];
		if (stat("/proc/consoles", &sts) == 0) {
			fp = popen("cat /proc/consoles | awk '{print $1}'", "r");
			if (fp == NULL) {
				soe_err("failed to open /proc/cmdline");
				return 0;
			}
			while (fgets(buf, sizeof(buf), fp)) {
				psz = buf;	
				while(isalnum(*psz)) psz++;
				*psz = '\0';
				strcat(buf, " ");
				strcat(consoles, buf);
			}
			fclose(fp);
		}
	}
	if (consoles[0] != '\0') {
		return (NULL != strstr(consoles, filename));
	}
	return 0;
}

static int soe_phy_serial_probe(int line)
{
	phy_serial_t * pserial;
	int ret = 0;
	int dev;
	char filename[PATH_MAX];

	snprintf(filename, PATH_MAX, "/dev/ttyS%d", line);
	if (soe_serial_is_console(line)) {
		soe_warn("%s is a console, failed to join", filename);
		return -EBUSY;	
	}
	dev = open(filename, O_RDWR | O_NOCTTY);
	if (dev > 0) {
		struct termios tio;
		if (tcgetattr(dev, &tio) == 0) {
			pserial = wzalloc(sizeof(phy_serial_t));
			if (!pserial) {
				close(dev);
				soe_err("failed to allocate the memory, errno=%d", errno);
				return -ENOMEM;
			}
			pstrcpy(pserial->name, sizeof(pserial->name), filename);	
			pserial->fd = dev;
			pserial->line = line;
			memcpy(&pserial->tio, &tio, sizeof(tio));
			
			/* initialize the serial */
			if (soe_init_serial(pserial) < 0) {
				goto failinit;
			}
			soe_mutex_lock(&phy_serials_lock);
			list_add_tail(&pserial->node, &phy_serials_list);		
			soe_mutex_unlock(&phy_serials_lock);
		} else {
			ret = -errno;
			close(dev);
		}
	} else {
		ret = -errno;
	}
	return ret;
failinit:
	close(dev);
	wfree(pserial);
	soe_err("failed to create read queue");
	return -EFAULT;
}

static int soe_detect_serials()
{
	int i, count = 0;
	for ( i = 0; i < MAX_SERIAL_NUM; i++) {
		if (0 == soe_phy_serial_probe(i)) {
			count++;	
		}
	}
	return count;
}

static void soe_op_done(struct work *work)
{
        //struct request *req = container_of(work, struct request, work);
	struct request *req = (struct request *)work->priv;
	phy_serial_t * ptgt_serial = (phy_serial_t *)req->priv_data;
	int cmd = req->rq.opcode;

        if (has_process_main(req->op)) {
                req->rp.result = do_process_main(req->op, &req->rq,
                                                 &req->rp, req->data);
        }
        put_request(req);
	if (cmd == SOE_OP_READ) {
		ptgt_serial->notified = 0;
	}
}

int  queue_serial_request(struct request *req)
{
	struct soe_req *hdr = &req->rq;
	struct work * wk;
	phy_serial_t * pserial = NULL;	
	pserial = soe_find_serial_by_line(hdr->line);
	if (pserial == NULL) {
		return -1;
	}

	wk = alloc_work(req, 0);
	if(wk == NULL) {
		dump_works();
		return -2;
	}
	wk->fn   = do_process_work;
	wk->done = soe_op_done; 
	req->priv_data = pserial;

	queue_work(pserial->io_queue, wk);	
	return 0;
}


void init_serial()
{
	soe_get_serial_count();
}

void cleanup_serial()
{
	phy_serial_t * pserial = NULL, *tmp;	
	soe_info("serial cleanup");
	if (list_empty(&phy_serials_list)) 
		return;
	soe_mutex_lock(&phy_serials_lock);
	list_for_each_entry(pserial, tmp, &phy_serials_list, node) {
		list_del(&pserial->node);
		soe_info("close serial %s", pserial->name);
		soe_deinit_serial(pserial);
		close(pserial->fd);
		wfree(pserial);	
	}
	soe_mutex_unlock(&phy_serials_lock);
}

#ifdef TEST
int main(int argc, void **argv)
{
	if (geteuid() != 0) {
		fprintf(stderr, "** Wrong User: geteuid = %d\n", geteuid());
		return -1;
	}

	printf("ttyS ok：%d\n", soe_detect_serials());
	return 0;
}

#endif
