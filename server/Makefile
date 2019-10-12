
TARGET ?=soed

LDFLAGS += -lpthread -ldl

BFDLD ?= 0

ifeq ($(BFDLD), 1)
	LDFLAGS += -lbfd 
endif

CFLAGS += -DCONFIG_BFD=$(BFDLD)

SOURCE := server.c serial.c request.c ../lib/work.c ../lib/common.c \
	../lib/util.c ../lib/option.c ../lib/net.c ../lib/logger.c \
	../lib/event.c ../lib/rbtree.c ../lib/license.c
OBJS := $(patsubst %.c, %.o, ${SOURCE}) 

all:$(TARGET)

$(TARGET):$(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o:%.c
	$(CC) ${CFLAGS} -c -o $@ $^ 

install:
	@cp -f $(TARGET) $(INSTALLDIR)/$(EMBD)/
clean:
	rm -f ${OBJS} $(TARGET)
