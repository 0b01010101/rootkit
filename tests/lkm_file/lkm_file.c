#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/namei.h>
 
ssize_t lkm_file_write(struct file *f, const void *ptr, size_t len, loff_t *offs); 
ssize_t lkm_file_read(struct file *f, void *ptr, size_t len, loff_t *offs); 
static struct file *lkm_file_open(const char *name); 
static int lkm_file_close(struct file *f);
static int lkm_file_rm(char *name);
static int lkm_file_stat(const char *name, struct kstat *stat); 

static int lkm_file_rm(char *name) {

	int ret = -1;
	struct subprocess_info *info;
	static char *rm[] = {"/bin/rm", "-f", NULL, NULL};

	if(!name) return ret;
    	rm[2] = name;

	info = call_usermodehelper_setup(rm[0], rm, NULL, GFP_KERNEL, NULL, NULL, NULL);
	if(info) {
		ret = call_usermodehelper_exec(info, UMH_WAIT_EXEC);
		if(ret) return ret;
	}

	return ret;
}

static int lkm_file_stat(const char *name, struct kstat *stat) {

	struct path path;
	int ret = -1;

	if(!name||!stat) return ret;

    	ret = kern_path(name, LOOKUP_FOLLOW, &path);
	if(ret) return ret;

	ret = vfs_getattr(&path, stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
	if(ret) return ret;
	path_put(&path);

	return 0;
}

ssize_t lkm_file_read(struct file *f, void *ptr, size_t len, loff_t *offs) {

	if(!f) return -1;
	return kernel_read(f, ptr, len, offs);
}

ssize_t lkm_file_write(struct file *f, const void *ptr, size_t len, loff_t *offs) {

	if(!f) return -1;
	return kernel_write(f, ptr, len, offs);
}

static struct file *lkm_file_open(const char *name) {

	struct file *f;
	if(!name) return NULL;

    	f = filp_open(name, O_RDWR|O_LARGEFILE, 0600);
	if(IS_ERR(f)) return NULL;

	return f;
}

static int lkm_file_close(struct file *f) {

	if(!f) return -1;
	return filp_close(f, NULL);
}

////////////////// TEST ////////////////////////////////////
static int lkm_file_test(const char *name) {

	struct file *f;
	int a;
	int buf_len = 0xFF;
	void *buf;

	buf = kmalloc(buf_len, GFP_KERNEL);
	if(!buf) return 0;

	f = lkm_file_open(name);
	if(!f) {
	       	printk(KERN_INFO "faild open file(%s)\n", name);
		goto exi_tst;
	}
/*
	a = lkm_file_read(f, buf, buf_len, 0);
	printk(KERN_INFO "read bytes(%d)\n", a);
	if(a>0) {
		printk(KERN_INFO "read: %s\n", (char*)buf);
	}

	loff_t offs = 6;
	char *str = "OWERWRITE strInG (;";
	a = lkm_file_write(f, str, strlen(str), &offs);
	printk(KERN_INFO "write bytes(%d), offs(%d)\n", a, offs);

	a = lkm_file_read(f, buf, buf_len, 0);
	printk(KERN_INFO "read bytes(%d)\n", a);
	if(a>0) {
		printk(KERN_INFO "read: %s\n", (char*)buf);
	}
*/
	struct kstat stat;
	lkm_file_stat(name, &stat);
	printk(KERN_INFO "size(%d), blocks(%d), block_sz(%d), lnks(%d), inod(%ld), acces(%o)\n", stat.size, stat.blocks, stat.blksize, stat.nlink, stat.ino, stat.mode);

	lkm_file_close(f);
exi_tst:
	kfree(buf);
	printk(KERN_INFO "end lkm_file_test()\n");
	return 0;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int __init lkm_net_init(void) {
	printk(KERN_INFO "++++++ LKM_FILE, Hale-halE-HaLE-OP ++++++\n");

	lkm_file_test("/home/drweb/kern/lkm_file/hello.txt");
	lkm_file_test("/proc/modules");
	lkm_file_test("/proc/kallsyms");
	return 0;
}
static void __exit lkm_net_exit(void) {

	printk(KERN_INFO "++++++ LKM_FILE, HN-Hn-hn ++++++\n");
	return;
}

module_init(lkm_net_init);
module_exit(lkm_net_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PARFIK");
MODULE_DESCRIPTION("NET LKM...");
MODULE_VERSION("0.01");
