#ifndef __SOE_PROTO_H__
#define __SOE_PROTO_H__

#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <termios.h>
#include <linux/limits.h>
#include <stddef.h>

#define SOE_PROTO_VER 0x01

#define SOE_LISTEN_PORT 5000


#define SOE_MSG_MAGIC 0xcbdefabc

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
#define SOE_OP_PING    0x0D
#define SOE_OP_EXT(op) (0x80 | (op))

#define is_soe_ext(op) (0x80 & (op))

#define SOE_RES_ERR_BASE(err)      (0x8000 + (err))

#define SOE_RES_SUCCESS       0x00 /* Success */
#define SOE_RES_UNKNOWN       (0x01) /* Unknown error */
#define SOE_RES_NO_OBJ        (0x02) /* No object found */
#define SOE_RES_EIO           (0x03) /* I/O error */
#define SOE_RES_INVALID_PARMS (0x05) /* Invalid parameters */
#define SOE_RES_SYSTEM_ERROR  (0x06) /* System error */
#define SOE_RES_READ          (0x0A) /* Cannot read requested */
#define SOE_RES_WRITE         (0x0B) /* Cannot write requested */
#define SOE_RES_STARTUP       (0x0F) /* Sheepdog is on starting up */
#define SOE_RES_SHUTDOWN      (0x11) /* Sheepdog is shutting down */
#define SOE_RES_NO_MEM        (0x12) /* Cannot allocate memory */
#define SOE_RES_VER_MISMATCH  (0x14) /* Protocol version mismatch */
#define SOE_RES_NO_SPACE      (0x15) /* Server has no room for new objects */
#define SOE_RES_HALT          (0x19) /* stopped doing IO */
#define SOE_RES_READONLY      (0x1A) /* Object is read-only */
#define SOE_RES_BUSY          (0x1B) /* object is in use */
#define SOE_RES_NO_AUTH       (0x1C) /* no authentication */

/* internal error return values, must be above 0x80 */
#define SOE_RES_NETWORK_ERROR (0x86) /* Network error between sheep */
#define SOE_RES_BUFFER_SMALL  (0x88) /* The buffer is too small */
#define SOE_RES_NO_SUPPORT    (0x8B) /* Operation is not supported by backend store */
#define SOE_RES_KILLED        (0x8D) /* Node is killed */
#define SOE_RES_AGAIN         (0x8F) /* Ask to try again */
#define SOE_RES_NOT_FOUND     (0x93) /* Cannot found target */
#define SOE_RES_INCOMPLETE    (0x94) /* Object (in kv) is incomplete uploading */
/* sheep is collecting cluster wide status, not ready for operation */
/* Node doesn't have a required entry of checkpoint */

struct soe_req {
	uint32_t magic;
	uint32_t seq;
	uint8_t  opcode;
	uint8_t  line;
	uint16_t readlen;
	uint16_t len;
}__attribute__((packed));

struct soe_rsp {
	uint32_t magic;
	uint32_t seq;
	uint8_t  opcode;
	uint8_t  line;
	uint16_t readlen;
	uint16_t len;
#define SOE_FLAG_DATA_READY (1 << 0)
	uint16_t flags; 
	int16_t  result;
}__attribute__((packed)); 

struct soe_termios
{
    tcflag_t c_iflag;           /* input mode flags */
    tcflag_t c_oflag;           /* output mode flags */
    tcflag_t c_cflag;           /* control mode flags */
    tcflag_t c_lflag;           /* local mode flags */
    speed_t c_ispeed;           /* input speed */
    speed_t c_ospeed;           /* output speed */
}__attribute__((packed));

struct soe_cnt {
	uint32_t rxcnt; 
	uint32_t txcnt; 
	uint32_t errwrite;
	uint32_t errread;
	uint32_t errothers;
}__attribute__((packed)); 

#endif
