
PWD = $(shell pwd)  
KERNEL_SRC = /lib/modules/`uname -r`/build/

CONFIG_MODULE_SIG=n

obj-m := soe_uart.o  
test-objs := soe_uart.o  
   
all:  
	       $(MAKE) -C $(KERNEL_SRC) M=$(PWD) modules  
	         
install:
		cp  -f soe_uart.ko $(INSTALLDIR)
clean:  
	       rm  -f *.ko  *.o *.mod.* .*cmd
