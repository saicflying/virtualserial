
PROJECT(SOE_SERVER)

SET(SOE_SERVER_SRCS	
	server.c
	serial.c
	request.c
	../lib/work.c
	../lib/util.c
	../lib/net.c
	../lib/option.c
	../lib/logger.c	
	../lib/common.c	
	../lib/event.c	
	../lib/rbtree.c	
	../lib/license.c
	)

ADD_EXECUTABLE(soed ${SOE_SERVER_SRCS})

target_link_libraries(soed pthread bfd dl)
