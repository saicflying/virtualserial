
PROJECT(SOE_CLIENT)

SET(SOE_CLIENT_SRCS	
	client.c
	../lib/work.c
	../lib/net.c
	../lib/logger.c	
	../lib/event.c	
	../lib/option.c	
	../lib/rbtree.c	
	../lib/common.c	
	../lib/util.c
	)

ADD_EXECUTABLE(soe_map ${SOE_CLIENT_SRCS})

target_link_libraries(soe_map pthread bfd dl)
