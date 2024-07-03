obj-m += netfilter_module.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /libn/modules/$(shell uname -r)/build M=$(PWD) clean
