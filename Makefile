OBJNAME = om4
SRC := src/${OBJNAME}.c  src/test.c src/net.c src/keylog.c src/file.c src/task.c src/module.c src/symb.c
CC = gcc

$(OBJNAME)-objs = $(SRC:.c=.o)
obj-m := ${OBJNAME}.o

.PHONY: all clean test
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
test:
	sudo dmesg -C
	sudo insmod $(OBJNAME).ko
	#sudo rmmod $(OBJNAME).ko
	dmesg
