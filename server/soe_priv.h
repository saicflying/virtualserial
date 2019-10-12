#ifndef __SOED_PRIV_H__
#define __SOED_PRIV_H__

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

#include "work.h"
#include "event.h"
#include "soe_proto.h"
#include "list.h"
#include "net.h"


struct client_info {
	struct connection conn;
	struct work_queue * q; /* work queue for the client */

	struct request *rx_req;
	struct work rx_work;
	refcnt_t rx_refcnt;
	

	struct request *tx_req;
	struct work tx_work;
	refcnt_t tx_refcnt;

	struct soe_mutex conn_lock;
	struct list_head done_reqs;
	
	struct soe_mutex ref_lock; 
	refcnt_t refcnt;

	void  *priv_data;
	int    role;
	struct list_node list;
};

typedef void (* soe_notifier_t)(struct client_info * ci);	
int register_shutdown_notifer(soe_notifier_t notifier);

struct system_info {
	enum soe_status status :8;
	struct list_head req_wait_queue;
};

enum REQUST_STATUS {
	REQUEST_INIT,
	REQUEST_QUEUED,
	REQUEST_DONE,
	REQUEST_DROPPED
};

struct request_iocb {
	uint32_t count;
	int efd;
	int result;
};

struct request {
	struct soe_req rq;
	struct soe_rsp rp;

	const struct soe_op_template *op;

	void *data;
	unsigned int data_length;

	struct client_info *ci;
	void * priv_data;
	struct list_node request_list;
	struct list_node pending_list;

	int local;
	refcnt_t refcnt;
	int local_req_efd;

	struct work work;
	enum REQUST_STATUS status;
	bool stat; /* true if this request is during stat */
};


#ifdef HAVE_TRACE
#define MAIN_FN_SECTION ".sd_main"
#define WORKER_FN_SECTION ".sd_worker"

#define main_fn __attribute__((section(MAIN_FN_SECTION)))
#define worker_fn __attribute__((section(WORKER_FN_SECTION)))
#else
#define main_fn
#define worker_fn
#endif

void queue_request(struct request *req);

struct request *alloc_request(struct client_info *ci, uint32_t data_length);
main_fn void put_request(struct request *req);

int create_net_cache(void);
int create_listen_port(const char *bindaddr, int port);
const struct soe_op_template *get_soe_op(uint8_t opcode);
const char *op_name(const struct soe_op_template *op);

bool has_process_work(const struct soe_op_template *op);
bool has_process_main(const struct soe_op_template *op);
void do_process_work(struct work *work);
int do_process_main(const struct soe_op_template *op, const struct soe_req *req,
		struct soe_rsp *rsp, void *data);

extern struct system_info *sys;

static inline const char *soe_strerror(int err)
{
	static const char *descs[256] = {
		/* from sheepdog_proto.h */
		[SOE_RES_SUCCESS] = "Success",
		[SOE_RES_UNKNOWN] = "Unknown error",
		[SOE_RES_NO_OBJ] = "No object found",
		[SOE_RES_EIO] = "I/O error",
		[SOE_RES_INVALID_PARMS] = "Invalid parameters",
		[SOE_RES_SYSTEM_ERROR] = "System error",
		[SOE_RES_READ] = "Failed to read from requested",
		[SOE_RES_WRITE] = "Failed to write to requested",
		[SOE_RES_STARTUP] = "System is still booting",
		[SOE_RES_SHUTDOWN] = "System is shutting down",
		[SOE_RES_NO_MEM] = "Out of memory on server",
		[SOE_RES_VER_MISMATCH] = "Protocol version mismatch",
		[SOE_RES_NO_SPACE] = "Server has no space for new objects",
                [SOE_RES_HALT] = "IO has halted ",
		[SOE_RES_READONLY] = "read-only",
		[SOE_RES_BUSY] = "device is busy",
		[SOE_RES_NO_AUTH] = "device is not ready",

		/* from internal_proto.h */
		[SOE_RES_NETWORK_ERROR] = "Network error between sheep",
		[SOE_RES_BUFFER_SMALL] = "The buffer is too small",
		[SOE_RES_NO_SUPPORT] = "Operation is not supported",
		[SOE_RES_KILLED] = "Node is killed",
		[SOE_RES_AGAIN] = "Ask to try again",
	};

	if (!(0 <= err && err < ARRAY_SIZE(descs)) || descs[err] == NULL) {
		static __thread char msg[32];
		snprintf(msg, sizeof(msg), "Invalid error code %x", err);
		return msg;
	}

	return descs[err];
}


const char *op_name(const struct soe_op_template *op);
const struct soe_op_template *get_soe_op(uint8_t opcode);
void  cleanup_net(void);

#endif
