DBGTYPE		:= debug
TOPDIR  	:= $(shell pwd)
INCDIR  	:= $(TOPDIR)/include
INSTALLDIR 	:= $(TOPDIR)/bin
SUBDIR		:= server soe_map driver soe_mon


C_CC := gcc
C_LD := ld

ifeq ("x$(EMBD)", "x")
EMBD := x86
BFDLD := `tools/getglibcver.sh ${CC} 0224`
EMBD_C :=
endif 

ifeq ("$(EMBD)", "arm")
BFDLD := 0
EMBD_C := /home/wangl40/tools-dev/cross_compiler/crosstool-ng-1.21.0-174-g7d3ef02-am335x-on-i686/bin/arm-cortex_a8-linux-gnueabi-
endif

SERVER_CC      := $(EMBD_C)gcc
SERVER_LD	:= $(EMBD_C)ld

CFLAGS  := -I $(INCDIR) -D__USE_GNU=1 -D_GNU_SOURCE
LDFLAGS :=
ifeq ($(DBGTYPE), debug)
CFLAGS += -g
LDFLAGS += -g
else
CFLAGS += -O2
LDFLAGS += -O2
endif

export TOPDIR INSTALLDIR INCDIR  CFLAGS LDFLAGS EMBD
prefix = $(HOME)

all: subdirs

driver: 
	$(MAKE) -C driver
		
subdirs:
	@for n in $(SUBDIR); do	\
		echo "*****************************";	\
		echo $$n;	\
		echo "*****************************";	\
		if [ $$n = "server" ]; then \
			EMBD=$(EMBD) CC=$(SERVER_CC) BFDLD=$(BFDLD) $(MAKE) -C $$n || exit 1;	\
		else	\
			rm -rf 	$(TOPDIR)/lib/*.o;	\
			CC=$(C_CC) BFDLD=$(BFDLD) $(MAKE) -C $$n || exit 1; \
		fi \
	done

install:
	if [ ! -d bin/$(EMBD) ]; then	\
		mkdir -p bin/$(EMBD);	\
	fi
	for n in $(SUBDIR); do                 \
		echo "******************";     \
		echo $$n;                      \
		echo "******************";     \
		$(MAKE) -C $$n install || exit 1; \
	done
	cp tools/install_client.sh bin/
	cp tools/install_server.sh bin/
	cp tools/soe_cli bin/
	cp tools/soe_init bin/
	cp tools/soed_init bin/
	cp tools/soed_monitor.sh bin/

.PHONY:dist_clean
dist_clean: clean
	rm -rf $(TOPDIR)/bin/*

.PHONY:clean
clean:
	for n in $(SUBDIR); do                 \
		echo "******************";     \
		echo $$n;                      \
		echo "******************";     \
		$(MAKE) -C $$n clean|| exit 1; \
	done
