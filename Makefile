KDIR=/lib/modiles/$(shell uname -r)/build
obj-m += lframe.o
lframe-objs := lframe_init.o tcp_probe.o
ldflags-y += -T$(M)/lframe.lds

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
