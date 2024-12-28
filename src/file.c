#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/namei.h>
 
ssize_t lkm_file_write(struct file *f, const void *ptr, size_t len, loff_t *offs); 
ssize_t lkm_file_read(struct file *f, void *ptr, size_t len, loff_t *offs); 
struct file *lkm_file_open(const char *name); 
int lkm_file_rm(char *name);
int lkm_file_close(struct file *f);
int lkm_file_stat(const char *name, struct kstat *stat); 

int lkm_file_rm(char *name) {

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

	if(!f) return -1;
	return kernel_read(f, ptr, len, offs);
}

ssize_t lkm_file_write(struct file *f, const void *ptr, size_t len, loff_t *offs) {

	if(!f) return -1;
	return kernel_write(f, ptr, len, offs);
}

struct file *lkm_file_open(const char *name) {

	struct file *f;
	if(!name) return NULL;

    	f = filp_open(name, O_CREAT|O_RDWR|O_APPEND|O_LARGEFILE, 0666);
	if(IS_ERR(f)) return NULL;

	return f;
}

int lkm_file_close(struct file *f) {

	if(!f) return -1;
	return filp_close(f, NULL);
}
