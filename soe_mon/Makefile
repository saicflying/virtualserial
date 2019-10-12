TARGET ?=soe_mon

SOURCE := soe_mon.c 
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
