
#include <linux/major.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/ioctl.h>
#include <linux/mutex.h>
#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <linux/net.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/debugfs.h>
#include <linux/serial.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/serial_core.h>
#include <linux/uaccess.h>
#include <asm/types.h>
#include "soe_uart.h"


#define DEVICE_NAME "soe"
#define SOE_MSG_MAGIC 0xcbdefabc
#define SOE_UART_VERSION "1.0.0.1"

static int soe_debug = 0;
module_param(soe_debug, int, 0644);

static int soe_uart_timeout = 1000; /* 1 second */
module_param(soe_uart_timeout, int, 0644);

static int soe_char_major = 0;
module_param(soe_char_major, int, 0);
MODULE_PARM_DESC(soe_char_major, "Set the major number of the serial over ethernet char device");

static int soe_tty_major = 234;
module_param(soe_tty_major, int, 0);
MODULE_PARM_DESC(soe_tty_major, "Set the major number of the serial over ethernet tty device");



struct soe_virt_sock {
	int    sockfd;
	struct mutex  sock_lock; 
	struct socket *sock;
	struct task_struct *task_recv;
	struct task_struct *task_send;
	char  *xmit_buf;
	int    is_closing;
	wait_queue_head_t waiting_for_clean[2];
	struct soe_virt_port *port;
	int refcnt;
};


struct soe_virt_port {
	struct uart_port port;

	struct soe_virt_sock socket;

	spinlock_t queue_lock;
	struct list_head queue_head;	/* Requests waiting result */
	wait_queue_head_t waiting_wq;

	bool timedout;
	bool disconnect; /* a disconnect has been requested by user */

	int magic;
	int bused;
	atomic_t recv_threads;
	wait_queue_head_t send_wait;
	struct mutex config_lock;
	struct mutex int_lock;
	int interruptcnt;
	void * interrupt_buf;
	int askforreopen;	
	int bopened;
	int rx_enable;
	int tx_enable;

	int charssentpersec; /* the ability to send out the chars in one second */
	int baudrate;
	
	int lasterrno;
	int errcnt;
};


static uint32_t req_seq = 0;

#define MAX_SOE_DEVICE 100
static struct class *soe_class;
static struct mutex  soe_port_lock;
static struct soe_virt_port soe_ports[MAX_SOE_DEVICE];

static int sock_xmit(struct soe_virt_sock *sock, int send, void *buf, int size, int msg_flags);
void soe_sock_clear(struct soe_virt_sock *s, int from);
static int soe_thread_recv(void *data);
static int soe_thread_send(void *data);
static int soe_send_request(struct soe_virt_port * port, struct soe_request_item * req, int wait_ms);
static int soe_uart_startup(struct uart_port *port);

static void soe_mark_io_flag(struct soe_virt_port *port, int err)
{
	struct uart_port * uport = &port->port; 
	struct uart_state *state;
	state = uport->state;
	if (state && state->port.tty) {
		if (err) {
			set_bit(TTY_IO_ERROR, &state->port.tty->flags);
		} else {
			clear_bit(TTY_IO_ERROR, &state->port.tty->flags);
		}
	}
}

int soe_sock_create(int fd, struct soe_virt_sock * s) 
{
	int ret, err;
	struct soe_virt_port * port = container_of(s, struct soe_virt_port, socket);   
	struct task_struct *thread;

	if (soe_debug) {
		printk("set socket:%d, %d\n", port->port.line, fd);		
	}
	mutex_lock(&s->sock_lock);
	 
	if (s->sock) {
		if (s->is_closing) {
			printk("ttySOE%d: found a obsolete socket, close it first\n", port->port.line);
			mutex_unlock(&s->sock_lock);
			soe_sock_clear(&port->socket, 0);	
			mutex_lock(&s->sock_lock);

		} else {
			mutex_unlock(&s->sock_lock);
			return -EBUSY;
		}
	}
	
	s->sock = sockfd_lookup(fd, &err);
	if (!s->sock) {
		mutex_unlock(&s->sock_lock);
		printk(KERN_ERR "ttySOE%d:Failed to look up the socket:%d, %d\n", port->port.line, fd, err);
		return err;
	}
	s->sockfd = fd;

		
	thread = kthread_run(soe_thread_recv, s, "recv for ttySOE%d", port->port.line);
	if (IS_ERR(thread)){
		ret = PTR_ERR(thread);
		printk(KERN_ERR "failed to create the recv thread for ttySOE%d\n", port->port.line);
		goto failed;
	}
	s->task_recv = thread;

	s->xmit_buf = kmalloc(1024, GFP_KERNEL); 
	if (s->xmit_buf == NULL) {
		goto failed;
	}

	thread = kthread_run(soe_thread_send, s, "send for ttySOE%d", port->port.line);
	if (IS_ERR(thread)){
		ret = PTR_ERR(thread);
		printk(KERN_ERR "failed to create the recv thread for ttySOE%d\n", port->port.line);
		goto failed;
	}
	s->task_send = thread;

	init_waitqueue_head(&s->waiting_for_clean[0]);
	init_waitqueue_head(&s->waiting_for_clean[1]);
	
	s->refcnt = 0;	
	mutex_unlock(&s->sock_lock);
	soe_mark_io_flag(port, 0);
	if (soe_debug) {
		printk("set socket ok:%d, %d\n", port->port.line, fd);		
	}

	return 0;
failed:
	if (s->xmit_buf) {
		kfree(s->xmit_buf);
		s->xmit_buf = NULL;
	}
	s->is_closing = 10;
	kernel_sock_shutdown(s->sock, SHUT_RDWR);
	if (s->task_send) {
		kthread_stop(s->task_send);
		s->task_send = NULL;
	}
	if (s->task_recv) {
		kthread_stop(s->task_recv);
		s->task_recv = NULL;
	}
	sockfd_put(s->sock);
	s->sock = NULL;
	s->is_closing = 0;
	mutex_unlock(&s->sock_lock);
	return -1;
}

void soe_sock_clear(struct soe_virt_sock *s, int from) {
	mutex_lock(&s->sock_lock);
	s->is_closing = 10;
	if (s->sock) {
		kernel_sock_shutdown(s->sock, SHUT_RDWR);
		while(s->refcnt) {
			mutex_unlock(&s->sock_lock);
			schedule();
			mutex_lock(&s->sock_lock);
		}
		wake_up(&s->waiting_for_clean[0]);
		kthread_stop(s->task_send);
		wake_up(&s->waiting_for_clean[1]);
		kthread_stop(s->task_recv);
		s->task_recv = NULL;
		s->task_send = NULL;
		if (s->xmit_buf) {
			kfree(s->xmit_buf);
			s->xmit_buf = NULL;
		}
		printk(KERN_INFO "ttySOE%d shutting down socket\n", s->port->port.line);
		sockfd_put(s->sock);
		s->sock = NULL;
	}
	s->is_closing = 0;
	mutex_unlock(&s->sock_lock);
}

static  struct soe_request_item * find_active_request(struct soe_virt_port * port, struct soe_reply * rsp )
{
	struct soe_request_item *req;

	if (list_empty(&port->queue_head)) 
		return NULL;
	
	spin_lock(&port->queue_lock);	
	list_for_each_entry(req, &port->queue_head, node) {
		if (req->rq.hdr.opcode == rsp->hdr.opcode && req->rq.hdr.seq == rsp->hdr.seq) {
			req->refcnt++;
			spin_unlock(&port->queue_lock);	
			return req;
		}
	}
	spin_unlock(&port->queue_lock);
	return NULL;
} 

static int soe_thread_send(void *data)
{
	struct soe_virt_sock *sock = (struct soe_virt_sock*)data;
	struct soe_virt_port *port = sock->port;
	struct circ_buf *xmit = &port->port.state->xmit;
	int    count;
	struct soe_request_item req; 
	int ret;
	int wait_time;

	printk("soe_thread_send for /dev/ttySOE%d\n", port->port.line);
	while(!kthread_should_stop()) {
		if (sock->is_closing) {
			wait_event_timeout(sock->waiting_for_clean[0], sock->is_closing >=10 , 1 * HZ);
			schedule();
			continue;
		}
		wait_event_interruptible_timeout(port->send_wait, 
			(port->askforreopen || (port->tx_enable && !uart_circ_empty(xmit))), 1 * HZ);	

		if (port->askforreopen) {
			if (soe_uart_startup(&port->port) == 0) {
				port->askforreopen = 0;
			} else {
				init_waitqueue_head(&port->send_wait);	
				schedule();
				continue;
			}
		}
		if (!port->tx_enable || uart_circ_empty(xmit)) {
			init_waitqueue_head(&port->send_wait);	
			continue;
		}
		//printk("soe thread send start\n");

		count = 0;
		while(count < port->charssentpersec) {
			sock->xmit_buf[count] = xmit->buf[xmit->tail];
			xmit->tail = (xmit->tail + 1) & (UART_XMIT_SIZE - 1);
			count++;
			port->port.icount.tx++;

			if (!port->tx_enable || uart_circ_empty(xmit)) {
				break;
			}
		}

		if (!port->tx_enable) {
			init_waitqueue_head(&port->send_wait);	
			continue;
		}

		if (soe_debug) {
			printk("soe thread send %d data\n", count);
		}
		memset(&req, 0, sizeof(req));
		req.rq.hdr.seq = req_seq++;
		req.rq.hdr.opcode = SOE_OP_WRITE;
		req.rq.hdr.len = count;	

		req.data = sock->xmit_buf; 
		
		if (port->baudrate == 0) {
			wait_time = 2000;   
		} else {
			wait_time =  count * 12000 / port->baudrate; 
			if (wait_time < 200) wait_time = 200;
		}
		ret = soe_send_request(port, &req, wait_time);
		if (ret >= 0) {
			if (soe_debug) {
				printk(KERN_INFO "ttySOE%d:send write data = %d(%d)\n", port->port.line, count, port->charssentpersec);
			}
		} else {
		}

		if (uart_circ_chars_pending(xmit) < WAKEUP_CHARS) {
			uart_write_wakeup(&port->port);
		}

		init_waitqueue_head(&port->send_wait);	
	}

	printk("soe_thread_send for /dev/ttySOE%d exit\n", port->port.line);
	return 0;
}

static void soe_uart_rx_chars(struct soe_virt_port * p, char * buf, int len)
{
	struct uart_port *port = &p->port;
	unsigned char flag;
	int i;
	flag = TTY_NORMAL;
	for ( i= 0; i < len; i++) {
		port->icount.rx++;
		if (uart_handle_sysrq_char(port, buf[i]))
			continue;

		uart_insert_char(port, 0, 0, buf[i], flag);
	}

	tty_flip_buffer_push(&port->state->port);
}

static int soe_thread_recv(void *data)
{
	struct soe_request_item *req;
	struct soe_reply rsp;
	int result, len;
	
	struct soe_virt_sock *sock = (struct soe_virt_sock*)data;
	struct soe_virt_port *port = sock->port; 	

	printk("soe_thread_recv for /dev/ttySOE%d\n", port->port.line);
	sk_set_memalloc(sock->sock->sk);
	while(!kthread_should_stop()) {
		if (sock->is_closing) {
			wait_event_timeout(sock->waiting_for_clean[1], sock->is_closing >= 10, 1 * HZ);
			schedule();
			continue;	
		}
		//printk("recieving response\n");
		memset(&rsp, 0 ,sizeof(rsp));
		result = sock_xmit(sock, 0, &rsp, sizeof(rsp), MSG_WAITALL); 
		if (result < 0) {
			if (result == -EPIPE) {
				printk(KERN_INFO"the connection is closed for ttySOE%d\n", port->port.line);
				sock->is_closing++;
				soe_mark_io_flag(port, 1);
			}
			continue;
		}

		if (rsp.hdr.magic != SOE_MSG_MAGIC) {
			printk(KERN_ERR "ttySOE%d: Received a corrupted packet, magic=%x", port->port.line, rsp.hdr.magic);
			continue;
		}
		
		//printk("got a rsp\n");
		req = find_active_request(port, &rsp);
		if (req) {
			//printk("find a req\n");
			memcpy(&req->rp, &rsp, sizeof(struct soe_reply));
			len = rsp.hdr.len;
			if (len && req->data) {
				result = sock_xmit(sock, 0, req->data, len, MSG_WAITALL);	
				if (result < 0) {
					req->refcnt--;
					if (result == -EPIPE) {
						printk(KERN_INFO"the connection is closed for ttySOE%d\n", port->port.line);
						sock->is_closing++;
						soe_mark_io_flag(port, 1);
					} else 
						printk(KERN_ERR "ttySOE%d: Received a corrupted packet with op:%x, seq:%x\n", port->port.line, rsp.hdr.opcode, rsp.hdr.seq);
					continue;
				}
			}
			if (req->plen) {
				*req->plen = len;
			}
			req->wakeup = 1;
			//printk("wake up");
			wake_up(&req->wait);
			req->refcnt--;
		} else {
			if (rsp.hdr.opcode == SOE_OP_INT) {
				mutex_lock(&port->int_lock);
				port->interruptcnt++;	
				mutex_unlock(&port->int_lock);
				len = rsp.hdr.len;	
				result = sock_xmit(sock, 0, port->interrupt_buf, len, MSG_WAITALL);
				if (result < 0) {
					if (result == -EPIPE) {
						printk(KERN_INFO"the connection is closed for ttySOE%d\n", port->port.line);
						sock->is_closing++;
						soe_mark_io_flag(port, 1);
					} else 
						printk(KERN_ERR "ttySOE%d: Received a corrupted packet with op:%x, seq:%x\n", port->port.line, rsp.hdr.opcode, rsp.hdr.seq);
				} else {
					if (port->rx_enable) {
						soe_uart_rx_chars(port, port->interrupt_buf, len);
					}
				}
			} else {
				len = rsp.hdr.len;
				if (len) {
					result = sock_xmit(sock, 0, port->interrupt_buf, len, MSG_WAITALL);
					if (soe_debug) {
						printk(KERN_INFO"drop %d bytes for ttySOE%d\n", len, port->port.line);
					}
				}
			}
		}
	}
	printk("soe_thread_recv for /dev/ttySOE%d exit\n", port->port.line);
	return 0;
}

static int sock_xmit(struct soe_virt_sock *s, int send, void *buf, int size,
		int msg_flags)
{
	struct socket *sock = s->sock;
	int result;
	struct msghdr msg;
	struct kvec iov;
	unsigned long pflags = current->flags;

	mutex_lock(&s->sock_lock);
	if (unlikely(!sock) || s->is_closing) {
		printk(KERN_ERR "Attempted %s on closed socket in sock_xmit\n",
				(send ? "send" : "recv"));
		mutex_unlock(&s->sock_lock);
		return -EINVAL;
	}
	s->refcnt++;	
	mutex_unlock(&s->sock_lock);

	current->flags |= PF_MEMALLOC;
	do {
		sock->sk->sk_allocation = GFP_NOIO | __GFP_MEMALLOC;
		iov.iov_base = buf;
		iov.iov_len = size;
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = msg_flags | MSG_NOSIGNAL;

		if (send)
			result = kernel_sendmsg(sock, &msg, &iov, 1, size);
		else
			result = kernel_recvmsg(sock, &msg, &iov, 1, size,
						msg.msg_flags);
		
		if (result <= 0) {
			if (result == 0) 
				result = -EPIPE; /* short read */
			break;
		}
		size -= result;
		buf += result;
	} while (size > 0);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	tsk_restore_flags(current, pflags, PF_MEMALLOC);
#else
	current_restore_flags(pflags, PF_MEMALLOC);
#endif

	mutex_lock(&s->sock_lock);
	s->refcnt--;
	mutex_unlock(&s->sock_lock);
	return result;
}

static int soe_open(struct inode *inode, struct file *file)
{
	if (soe_debug) {
		printk(KERN_INFO "%s %d\n", __FUNCTION__, __LINE__);
	}
	return 0;
}

static int soe_release(struct inode *inode, struct file *file)
{
	if (soe_debug) {
		printk(KERN_INFO "%s %d\n", __FUNCTION__, __LINE__);
	}
	return 0;
}

struct soe_cnt {
	uint32_t rxcnt; 
	uint32_t txcnt; 
	uint32_t errwrite;
	uint32_t errread;
	uint32_t errothers;
}__attribute__((packed)); 

static unsigned int soe_uart_tx_empty(struct uart_port *port)
{	
	struct soe_virt_port * soe_port = (struct soe_virt_port *)port;
	struct soe_request_item req; 
	struct soe_cnt iocnt;
	int len = 0; 
	int ret;

	memset(&req, 0, sizeof(req));
	req.rq.hdr.seq = req_seq++;
	req.rq.hdr.opcode = SOE_OP_GET_CNT;
	req.rq.hdr.readlen = sizeof(struct soe_cnt);
	req.rq.hdr.len = 0;

	req.data = &iocnt;
	req.plen = &len;	

	ret = soe_send_request(soe_port, &req, soe_uart_timeout);
	if (ret < 0) {
		return ret;
	}
	if (soe_debug) {
		printk(KERN_INFO "%s %d, tx buf:%d\n", __FUNCTION__, port->line, iocnt.txcnt);
	}
	return iocnt.txcnt > 2048;
}

static void soe_uart_set_mctrl(struct uart_port *port, unsigned int mctrl)
{
	/* we don't care mctrl */
}

static void soe_uart_enable_ms(struct uart_port *port)
{

}

static unsigned int soe_uart_get_mctrl(struct uart_port *port)
{
	/* we don't care mctrl */
	return TIOCM_CAR;
}

static void soe_uart_stop_tx(struct uart_port *port)
{
	
	struct soe_virt_port * soe_port = (struct soe_virt_port *)port;
	soe_port->tx_enable = 0;
	if (soe_debug) {
		printk(KERN_INFO "%s %d\n", __FUNCTION__, port->line);
	}
}

static void soe_uart_start_tx(struct uart_port *port)
{
	struct soe_virt_port * soe_port = (struct soe_virt_port *)port;
	soe_port->tx_enable = 1;
	wake_up(&soe_port->send_wait);		
	if (soe_debug) {
		printk(KERN_INFO "%s %d\n", __FUNCTION__, port->line);
	}
}

static void soe_uart_stop_rx(struct uart_port *port)
{
	struct soe_virt_port * soe_port = (struct soe_virt_port *)port;
	soe_port->rx_enable = 0;
	if (soe_debug) {
		printk(KERN_INFO "%s %d\n", __FUNCTION__, port->line);
	}
}

static void soe_uart_break_ctl(struct uart_port *port, int break_state)
{
}

static int soe_uart_startup(struct uart_port *port)
{
	struct soe_virt_port * soe_port = (struct soe_virt_port *)port;
	struct soe_virt_sock * sock = &soe_port->socket;
	int ret;
	struct soe_request_item req; 
	memset(&req, 0, sizeof(req));
	if (soe_debug) {
		printk(KERN_INFO "%s %d\n", __FUNCTION__, port->line);
	}
	/* clear the socket buffer first */
			
	mutex_lock(&sock->sock_lock);
	if (!sock->sock) {
		mutex_unlock(&sock->sock_lock);
		return -EIO;
		
	}
	mutex_unlock(&sock->sock_lock);

	memset(&req, 0, sizeof(req));
	req.rq.hdr.seq = req_seq++;
	req.rq.hdr.opcode = SOE_OP_OPEN;
	req.rq.hdr.len = 0;	

	ret = soe_send_request(soe_port, &req, soe_uart_timeout * 2);
	if (ret >= 0) {
		soe_port->bopened = true;
		soe_port->rx_enable = 1;
	}
	if (soe_debug) {
		printk(KERN_INFO "%s return %d\n", __FUNCTION__, ret);
	}
	return ret;
}

static void soe_uart_shutdown(struct uart_port *port)
{
	struct soe_virt_port * soe_port = (struct soe_virt_port *)port;
	int ret;
	struct soe_request_item req; 

	soe_port->bopened = false;
	soe_port->tx_enable = 0;
	soe_port->rx_enable = 0;
	if (soe_debug) {
		printk(KERN_INFO "%s %d\n", __FUNCTION__, port->line);
	}
	memset(&req, 0, sizeof(req));
	req.rq.hdr.seq = req_seq++;
	req.rq.hdr.opcode = SOE_OP_CLOSE;
	req.rq.hdr.len = 0;

	ret = soe_send_request(soe_port, &req, 0);
}

static int soe_send_request(struct soe_virt_port * port, struct soe_request_item * req, int wait_ms)
{
	int result = 0;
	struct soe_virt_sock * sock = &port->socket;
	char *xmit_buf;

	INIT_LIST_HEAD(&req->node);
	mutex_init(&req->lock);
	init_waitqueue_head(&req->wait);

	xmit_buf = kmalloc(req->rq.hdr.len + sizeof(req->rq), GFP_KERNEL);
	if (xmit_buf == NULL) {
		printk("not enough memory\n");
		return -ENOMEM;
	}
	req->rq.hdr.magic = SOE_MSG_MAGIC;
	req->wakeup = 0;
	req->refcnt = 0;
	memcpy(xmit_buf, &req->rq, sizeof(req->rq));
	memcpy(xmit_buf + sizeof(req->rq), req->data, req->rq.hdr.len);

	if (wait_ms) {
		// if nowait, no need to add to the list	
		spin_lock(&port->queue_lock);
		list_add_tail(&req->node, &port->queue_head);
		spin_unlock(&port->queue_lock);
		wait_ms = (wait_ms < 100)?100:wait_ms;  //at least 100ms
	}

	if (soe_debug) {
		printk("ttySOE%d:send request: op: %d, seq:%d\n", port->port.line, req->rq.hdr.opcode, req->rq.hdr.seq);
	}
	result = sock_xmit(sock, 1, xmit_buf, req->rq.hdr.len + sizeof(req->rq), MSG_WAITALL);
	if (result < 0) {
		if (port->lasterrno != result) {
			port->errcnt = 0;
		}
		if (port->errcnt == 0) {
			printk(KERN_ERR "ttySOE%d: Failed to send the request %d\n", port->port.line, req->rq.hdr.opcode);
		}
		port->errcnt++;
		port->lasterrno = result;
		kfree(xmit_buf);
		spin_lock(&port->queue_lock);
		list_del(&req->node);
		spin_unlock(&port->queue_lock);
		return result;	
	} else if (0 == wait_ms) {
		return 0;
	}
	
	if (!req->wakeup) {
		result = wait_event_timeout(req->wait, req->wakeup, wait_ms * HZ / 1000); 
	}
	
	result = 0;
	spin_lock(&port->queue_lock);
	while(req->refcnt) {
		spin_unlock(&port->queue_lock);
		schedule();
		spin_lock(&port->queue_lock);
	}
	list_del(&req->node);	
	spin_unlock(&port->queue_lock);
	kfree(xmit_buf);
	if (soe_debug) {
		printk("ttySOE%d:result = %x, req->wakeup:%d\n", port->port.line,result, req->wakeup); 
	}
	
	if (req->wakeup == 0) {
		if (port->lasterrno != -ETIMEDOUT) {
			port->errcnt = 0;
		}
		if (port->errcnt == 0) {
			printk(KERN_ERR "ttySOE%d: Failed to send the request(op=%d) %d\n", port->port.line, req->rq.hdr.opcode, -ETIMEDOUT);
		} 
		port->errcnt++;
		port->lasterrno = -ETIMEDOUT;
	} else if (req->rp.result < 0) {
		if (port->lasterrno != req->rp.result) {
			port->errcnt = 0;
		}
		if (port->errcnt == 0) {
			printk(KERN_ERR "ttySOE%d: Failed to send the request(op=%d) %d\n", port->port.line, req->rq.hdr.opcode, req->rp.result);
		} 
		port->errcnt++;
		port->lasterrno = req->rp.result;
	} else {
		if (port->errcnt) {
			printk(KERN_INFO "ttySOE%d: Successfully send the request\n", port->port.line);
		}
		port->errcnt = 0;
		port->lasterrno = 0;
	}
	
	return (req->wakeup == 0)?-ETIMEDOUT:req->rp.result;
}

static int soe_uart_set_send_ability(struct soe_virt_port *port, int baud)
{
	int ret = baud;
	int rbaud = 0;
	switch (baud) {
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
		case B0:
		default:
			rbaud = 9600;
			ret = B9600;
			break;
	}
	port->charssentpersec = min(rbaud / 8 + 1, 1024); 
	port->baudrate = rbaud;
	return ret;
}

static void soe_uart_set_termios(struct uart_port *port,
                                 struct ktermios *termios,
                                 struct ktermios *old)
{
	struct soe_virt_port * soe_port = (struct soe_virt_port *)port;
	struct soe_termios xmit_termios;
	int ret;
	int mybaud;
	struct soe_request_item req; 

	memset(&req, 0, sizeof(req));
	req.rq.hdr.seq = req_seq++;
	req.rq.hdr.opcode = SOE_OP_SET;
	req.rq.hdr.len = sizeof(xmit_termios);	
	
	xmit_termios.c_iflag = termios->c_iflag;	
	xmit_termios.c_oflag = termios->c_oflag;	
	xmit_termios.c_lflag = termios->c_lflag;	
	
	xmit_termios.c_ispeed = termios->c_ispeed;	
	xmit_termios.c_ospeed = termios->c_ospeed;	

	mybaud = soe_uart_set_send_ability(soe_port, termios->c_cflag & CBAUD);
	termios->c_cflag &= ~CBAUD;
	termios->c_cflag |= mybaud;
	
	xmit_termios.c_cflag = termios->c_cflag;	
	req.data = &xmit_termios;
	ret = soe_send_request(soe_port, &req, 0);
	if (ret < 0) {
		return;
	}
}

static const char *soe_uart_type(struct uart_port *port)
{
	return "PORT_SoE";
}

static void soe_uart_release_port(struct uart_port *port)
{
	if (soe_debug) {
		printk(KERN_INFO "%s %d\n", __FUNCTION__, port->line);
	}
}

static int soe_uart_request_port(struct uart_port *port)

{
	if (soe_debug) {
		printk(KERN_INFO "%s %d\n", __FUNCTION__, port->line);
	}
	return 0;
}

static void soe_uart_config_port(struct uart_port *port, int flags)
{
	if (soe_debug) {
		printk(KERN_INFO "%s %d\n", __FUNCTION__, port->line);
	}
}

static int soe_uart_verify_port(struct uart_port *port,
				struct serial_struct *ser)
{
	if (soe_debug) {
		printk(KERN_INFO "%s %d\n", __FUNCTION__, port->line);
	}
	return 0;
}

static struct uart_driver soe_reg = {
	.owner = THIS_MODULE,
	.driver_name = "ttySOE",
	.dev_name    = "ttySOE",
	.major	     = 0,
	.minor 	     = 0, 
	.nr 	     = MAX_SOE_DEVICE,
};

static struct uart_ops soe_uart_pops = {
	.tx_empty	= soe_uart_tx_empty,
	.set_mctrl	= soe_uart_set_mctrl,
	.get_mctrl	= soe_uart_get_mctrl,
	.enable_ms      = soe_uart_enable_ms,
	.stop_tx	= soe_uart_stop_tx,
	.start_tx	= soe_uart_start_tx,
	.stop_rx	= soe_uart_stop_rx,
	.break_ctl	= soe_uart_break_ctl,
	.startup	= soe_uart_startup,
	.shutdown	= soe_uart_shutdown,
	.set_termios	= soe_uart_set_termios,
	.type		= soe_uart_type,
	.release_port	= soe_uart_release_port,
	.request_port	= soe_uart_request_port,
	.config_port	= soe_uart_config_port,
	.verify_port	= soe_uart_verify_port,
};


static int soe_create_uart(unsigned long data)
{
	int i, ret = -1;
	struct soe_virt_port * soe_port = NULL;

	i = data;	 
	
	if (i >= MAX_SOE_DEVICE) {
		return -EINVAL;
	}
	
	mutex_lock(&soe_port_lock);	
	if  (soe_ports[i].bused) {
		mutex_unlock(&soe_port_lock);
		return -EEXIST;
	}
	soe_ports[i].bused = 1;
	mutex_unlock(&soe_port_lock);
	
	soe_port = &soe_ports[i];

	soe_port->port.line = i;	
	soe_port->port.type = 117;
	soe_port->port.ops = &soe_uart_pops;
	soe_port->port.uartclk = 1843200; /* fake baud */
	soe_port->port.mapbase = 0x8000 + i * 0x8;  /* fake one */
	soe_port->port.iotype = UPIO_MEM;
	soe_port->port.fifosize = 4096;
	spin_lock_init(&soe_port->port.lock);
	soe_port->port.irq = 0;
	INIT_LIST_HEAD(&soe_port->queue_head);
	init_waitqueue_head(&soe_port->send_wait);	
	mutex_init(&soe_port->int_lock);
	mutex_init(&soe_port->socket.sock_lock);
	
	soe_port->socket.sock = NULL;
	soe_port->socket.port = soe_port;
	soe_port->charssentpersec = 1024;
	
	soe_port->lasterrno = 0;
	soe_port->errcnt = 0;
	soe_port->interrupt_buf = kmalloc(1024, GFP_KERNEL);
	if (soe_port->interrupt_buf == NULL) {
		goto failed;
	}

	ret = uart_add_one_port(&soe_reg, &soe_port->port);
	if (ret < 0) {
		goto failed;
	}

	return i;
failed:
	if (soe_port->interrupt_buf) {
		kfree(soe_port->interrupt_buf);
	}
	mutex_lock(&soe_port_lock);	
	soe_port->bused = 0;
	mutex_unlock(&soe_port_lock);

	return ret;
}

typedef struct {
	int idx;
	int sockfd;
} sock_req_t;

static int soe_set_sock(unsigned long data)
{
	int ret;
	sock_req_t ioctl_req;
	struct soe_virt_port * soe_port;
	ret = copy_from_user(&ioctl_req, (char *)data, sizeof(sock_req_t));
	if (ret < 0) {
		return -EFAULT;		
	}
	if (ioctl_req.idx >= MAX_SOE_DEVICE) {
		return -EINVAL;	
	}

	soe_port = soe_ports + ioctl_req.idx;
	if (!soe_port->bused) {
		return -ENOENT;
	}

	return soe_sock_create(ioctl_req.sockfd, &soe_port->socket);
}

static int soe_clear_sock(int idx) 
{
	if (idx >= MAX_SOE_DEVICE) 
		return -EINVAL;
	
	soe_sock_clear(&soe_ports[idx].socket, 0);
	return 0;
}

static void soe_clear_queue(struct soe_virt_port *port)
{
	struct soe_request_item *req;
	while(!list_empty(&port->queue_head)) {
		spin_lock(&port->queue_lock);	
		list_for_each_entry(req, &port->queue_head, node) {
			req->rp.result = -EINTR;
			req->wakeup = 1;
			//printk("req:%p clear\n", req);
			wake_up(&req->wait);
		}
		spin_unlock(&port->queue_lock);
	}
}

static int soe_get_mapping(unsigned long idx)
{
	struct soe_virt_port * soe_port = soe_ports + idx;
	if (idx >= MAX_SOE_DEVICE) 
		return -EINVAL;
	
	mutex_lock(&soe_port_lock);	
	if  (!soe_ports[idx].bused) {
		mutex_unlock(&soe_port_lock);
		return -ENOENT;
	}
	mutex_unlock(&soe_port_lock);
	
	mutex_lock(&soe_port->socket.sock_lock);
	if (soe_port->socket.sock) {
		if (soe_port->socket.is_closing) {
			mutex_unlock(&soe_port->socket.sock_lock);
			return -ENOTTY;
		}
	} else {
		mutex_unlock(&soe_port->socket.sock_lock);
		return -ENOMEM;
	}
	mutex_unlock(&soe_port->socket.sock_lock);
	return 0;
}

static int soe_destroy_uart(unsigned long idx)
{
	struct soe_virt_port * soe_port = soe_ports + idx;
	if (idx >= MAX_SOE_DEVICE) 
		return -EINVAL;

	mutex_lock(&soe_port_lock);
	if  (soe_port->bused) {
		/* shut down all the communication first */
		soe_sock_clear(&soe_port->socket, 0);	
		soe_clear_queue(soe_port);	
		if (soe_port->interrupt_buf) {
			kfree(soe_port->interrupt_buf);
		}
		uart_remove_one_port(&soe_reg, &soe_ports[idx].port);
		soe_port->bused = 0;	
	}
	mutex_unlock(&soe_port_lock);
	return 0;
}

static int soe_ioctl(struct file *file, unsigned int cmd, unsigned long data)
{
	
	switch(cmd) {
		case SOE_CREATE_UART:
			return 	soe_create_uart(data);
		case SOE_DESTROY_UART:
			return  soe_destroy_uart(data);
		case SOE_SET_SOCK:
			return soe_set_sock(data);
		case SOE_CLEAR_SOCK:
			return soe_clear_sock(data);
		case SOE_GET_MAPPING:
			return soe_get_mapping(data);
		case SOE_CHECK_REOPEN:
			{
				int idx = data; 
				struct soe_virt_port * soe_port = soe_ports + idx;
				if (idx >= MAX_SOE_DEVICE) {
					return -EINVAL;
				}
				if (soe_port->bused && soe_port->bopened) {
					soe_port->askforreopen = 1;
					wake_up(&soe_port->send_wait);		
				}
				return 0;
			}
			break;
	}
	return -ENOTTY;
}

static long soe_unlocked_ioctl(struct file   *file,
			        unsigned int  cmd,
				unsigned long data)
{
	int ret;
	ret = soe_ioctl(file, cmd, data);
	return ret;
}


static const struct file_operations soe_char_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= soe_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = soe_unlocked_ioctl,
#endif
	.open		= soe_open,
	.release	= soe_release,
};


static int __init soe_uart_init(void)
{
	int rv;

	memset(&soe_ports, 0, sizeof(soe_ports));

	if (soe_char_major < 0) {
		return -EINVAL;
	}
	printk(KERN_INFO "Serial Over Ethernet Driver " SOE_UART_VERSION "\n");

	soe_class = class_create(THIS_MODULE, "soe"); 
	if (IS_ERR(soe_class)) {
		printk(KERN_ERR "soe: can't register device class\n");
		return PTR_ERR(soe_class);
	}
	
	rv = register_chrdev(soe_char_major, DEVICE_NAME, &soe_char_fops);
	if (rv < 0) {
		class_destroy(soe_class);
		printk(KERN_ERR "soe: can't get major %d\n", soe_char_major);
		return rv;
	}

	if (soe_char_major == 0) {
		soe_char_major = rv;
	}

	device_create(soe_class, NULL, MKDEV(soe_char_major, 0),
			NULL, DEVICE_NAME);
	soe_reg.major = soe_tty_major;

	mutex_init(&soe_port_lock);

	rv = uart_register_driver(&soe_reg);
	if (rv) {
		unregister_chrdev(soe_char_major, DEVICE_NAME);
		class_destroy(soe_class);
		soe_class = NULL;
		soe_char_major = 0;
		return rv;
	}
	
	return 0;
	
}

static void __exit soe_uart_exit(void)
{
	int i;		
	printk(KERN_INFO "Unload Serial Over Ethernet Driver\n");
	for (i = 0; i < MAX_SOE_DEVICE; i++) {
		soe_destroy_uart(i);		 
	}

	uart_unregister_driver(&soe_reg);

	if (soe_char_major > 0) {
		device_destroy(soe_class, MKDEV(soe_char_major, 0));
		unregister_chrdev(soe_char_major, DEVICE_NAME);
	}
	if (soe_class) {
		class_destroy(soe_class);
	}
}

module_init(soe_uart_init);
module_exit(soe_uart_exit);

MODULE_AUTHOR("Long Wang(saicflying@163.com)");
MODULE_DESCRIPTION("Serial Over Ethernet driver $Revision: 0.01 $");
MODULE_LICENSE("GPL");
