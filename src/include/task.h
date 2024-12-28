#ifndef	LKM_TASK_H
#define LKM_TASK_H

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/pid_namespace.h>
#include <linux/cred.h>
#include <linux/kprobes.h>

struct lkm_hide_struct {
	struct task_struct *task;
	bool   hide;
};

#endif
