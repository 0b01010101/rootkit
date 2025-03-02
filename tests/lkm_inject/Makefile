
obj-m := lkm_inj.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
test:
	rm -f *.mod *.mod.o .*.cmd .*.flags *.mod.c *.order lkm_inj.o
	rm -f .*.*.cmd *.symvers 
	sudo insmod lkm_inj.ko
	sudo rmmod lkm_inj
	sudo insmod zzz.ko
	sudo rmmod mod 


