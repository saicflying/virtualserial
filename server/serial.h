
#ifndef SOE_SERIAL_H
#define SOE_SERIAL_H

#include "compiler.h"
#include "soe_proto.h"
#include "soe_priv.h"

void init_serial(void);
void cleanup_serial(void);
int  queue_serial_request(struct request *req);

#endif /* SOE_SERIAL_H */
