obj-m += lkm_task.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
test:
	sudo dmesg -C
	sudo insmod lkm_task.ko
	sudo rmmod lkm_task.ko
	dmesg
