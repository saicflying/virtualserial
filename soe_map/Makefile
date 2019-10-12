TARGET ?=soe_map

LDFLAGS += -lpthread -ldl
BFDLD ?= 0

ifeq ($(BFDLD), 1)
	LDFLAGS += -lbfd
endif

SOURCE := client.c ../lib/work.c ../lib/common.c \
	../lib/util.c ../lib/option.c ../lib/net.c ../lib/logger.c \
	../lib/event.c ../lib/rbtree.c 
OBJS := $(patsubst %.c, %.o, ${SOURCE}) 

all:$(TARGET)

$(TARGET):$(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o:%.c
	$(CC) ${CFLAGS} -c -o $@ $^ 

install:
	@cp -f $(TARGET) $(INSTALLDIR)

clean:
	rm -f ${OBJS} $(TARGET)
