#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/namei.h>
 
ssize_t lkm_file_write(struct file *f, const void *ptr, size_t len, loff_t *offs); 
ssize_t lkm_file_read(struct file *f, void *ptr, size_t len, loff_t *offs); 
struct file *lkm_file_open(const char *name); 
int lkm_file_close(struct file *f);
static int lkm_file_rm(char *name);
int lkm_file_stat(const char *name, struct kstat *stat); 

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

int lkm_file_stat(const char *name, struct kstat *stat) {

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

	if(!f || !ptr) return -1;

	loff_t *off;
	if(!offs) { off = &f->f_pos; }
	else { off = offs; }

	ssize_t a = kernel_read(f, ptr, len, off);
	if(a!=len) return -1;
	return a;
}

ssize_t lkm_file_write(struct file *f, const void *ptr, size_t len, loff_t *offs) {

	if(!f || !ptr) return -1;
	
	loff_t *off;
	if(!offs) { off = &f->f_pos; }
	else { off = offs; }

	ssize_t a = kernel_write(f, ptr, len, off);
	//printk(KERN_INFO "FILE_WRITE=%d | need_len=%d\n", a, len);
	if(a!=len) return -1;
	return a;
}

struct file *lkm_file_open(const char *name) {

	struct file *f;
	if(!name) return NULL;

    	f = filp_open(name, O_RDWR|O_LARGEFILE, 0600);
    	//f = filp_open(name, O_RDWR|O_APPEND|O_CREAT, 0600);
	if(IS_ERR(f)) return NULL;

	return f;
}

int lkm_file_close(struct file *f) {

	if(!f) return -1;
	return filp_close(f, NULL);
}
