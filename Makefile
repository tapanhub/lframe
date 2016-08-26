#KDIR=/lib/modules/$(shell uname -r)/build
KDIR=/home/tapan/digichip/linux/linux-4.0
obj-m += lframe.o
lframe-objs := lframe_init.o tcp_probe.o lframe_ctl.o tcp_io.o lframe_hash.o
ldflags-y += -T$(M)/lframe.lds

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
