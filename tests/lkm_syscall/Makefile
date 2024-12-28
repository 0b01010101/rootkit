obj-m += lkm_syscall.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
test:
	sudo dmesg -C
	sudo insmod lkm_syscall.ko
	sudo rmmod lkm_syscall.ko
	dmesg

