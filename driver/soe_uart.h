#ifndef __SOE_UART_H__
#define __SOE_UART_H__

#include <linux/types.h>

#define SOE_CREATE_UART  _IO('Z', 0)
#define SOE_DESTROY_UART _IO('Z', 1)
#define SOE_GET_MAPPING  _IO('Z', 2)
#define SOE_SET_SOCK     _IO('Z', 3)
#define SOE_CLEAR_SOCK   _IO('Z', 4)
#define SOE_CLEAR_ERROR  _IO('Z', 5)
#define SOE_GET_CNT	 _IO('Z', 6)
#define SOE_CHECK_REOPEN _IO('Z', 7)


#define SOE_OP_OPEN    0x01
#define SOE_OP_CLOSE   0x02
#define SOE_OP_SET     0x03
#define SOE_OP_GET     0x04
#define SOE_OP_READ    0x05
#define SOE_OP_WRITE   0x06
#define SOE_OP_FLUSH   0x07
#define SOE_OP_DEGRADE 0x08
#define SOE_OP_MAP     0x09
#define SOE_OP_GET_CNT 0x0A
#define SOE_OP_INT     0x0B
#define SOE_OP_CLR_INT 0x0C

struct soe_xmit_data_hdr {
	uint32_t magic;
	uint32_t seq;
	uint8_t  opcode;
	uint8_t  line;
	uint16_t readlen;
	uint16_t len;
}__attribute__((packed));

struct soe_request {
	struct soe_xmit_data_hdr hdr;
}__attribute__((packed));

struct soe_reply {
	struct soe_xmit_data_hdr hdr;
	uint16_t flags;	
	int16_t result;	
}__attribute__((packed));

struct soe_request_item {
	struct mutex lock;
	struct soe_request rq;
	struct soe_reply   rp;		
	void   * data;
	int    * plen;

	struct list_head node;
	wait_queue_head_t  wait;
	int waiting;
	int wakeup;
	int refcnt;	
}__attribute__((packed));

struct soe_termios
{
    tcflag_t c_iflag;		/* input mode flags */
    tcflag_t c_oflag;		/* output mode flags */
    tcflag_t c_cflag;		/* control mode flags */
    tcflag_t c_lflag;		/* local mode flags */
    speed_t c_ispeed;		/* input speed */
    speed_t c_ospeed;		/* output speed */
}__attribute__((packed));

#endif
