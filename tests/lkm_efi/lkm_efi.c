#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/efi.h>

struct lkm_efi_struct {
	efi_char16_t 	*name;
	efi_guid_t	guid;
	u32		attr;
	void		*data;
	long		size;
	efi_status_t 	status;
};
struct lkm_efi_struct *lkm_efi_var = NULL;

static int lkm_efi_var_set(struct lkm_efi_struct *v);
static int lkm_efi_var_get(struct lkm_efi_struct *v);
static void lkm_efi_var_close(struct lkm_efi_struct *v);
static struct lkm_efi_struct *lkm_efi_var_open(efi_char16_t *name, efi_guid_t guid);
//////////////////////// DEBUG //////////////////////////////////////////////////////////////
static void lkm_efi_dump(void) {
	long flag = efi.flags;
	char *stat;
	long addr;

	printk(KERN_INFO "------------- START_EFI_DUMP:");
	printk(KERN_INFO "	--- FLAGS(0x%lx)", (long)efi.flags);

	stat = "FAIL";
	addr = (long)efi.get_variable;
	if((flag & EFI_RT_SUPPORTED_GET_VARIABLE) && efi.get_variable) {
		stat = "  OK";

	}
	printk(KERN_INFO "	--- GET_VAR:%s|addr:0x%lx", stat, addr);

	stat = "FAIL";
	addr = (long)efi.set_variable;
	if((flag & EFI_RT_SUPPORTED_SET_VARIABLE) && efi.set_variable) {
		stat = "  OK";

	}
	printk(KERN_INFO "	--- SET_VAR:%s|addr:0x%lx", stat, addr);

	stat = "FAIL";
	addr = (long)efi.get_time;
	if((flag & EFI_RT_SUPPORTED_GET_TIME) && efi.get_time) {
		stat = "  OK";

	}
	printk(KERN_INFO "	--- GET_TIME:%s|addr:0x%lx", stat, addr);

	stat = "FAIL";
	addr = (long)efi.set_time;
	if((flag & EFI_RT_SUPPORTED_SET_VARIABLE) && efi.set_time) {
		stat = "  OK";

	}
	printk(KERN_INFO "	--- SET_TIME:%s|addr:0x%lx", stat, addr);

	stat = "FAIL";
	addr = (long)efi.update_capsule;
	if((flag & EFI_RT_SUPPORTED_UPDATE_CAPSULE) && efi.update_capsule) {
		stat = "  OK";

	}
	printk(KERN_INFO "	--- UPDATE_CAPSULE:%s|addr:0x%lx", stat, addr);

	stat = "FAIL";
	addr = (long)efi.get_next_variable;
	if((flag & EFI_RT_SUPPORTED_GET_NEXT_VARIABLE_NAME) && efi.get_next_variable) {
		stat = "  OK";

	}
	printk(KERN_INFO "	--- GET_NEXT_VAR_NAME:%s|addr:0x%lx", stat, addr);

	stat = "FAIL";
	addr = (long)efi.reset_system;
	if((flag & EFI_RT_SUPPORTED_RESET_SYSTEM) && efi.reset_system) {
		stat = "OK";

	}
	printk(KERN_INFO "	--- RESET_SYSTEM:%s|addr:0x%lx", stat, addr);
	printk(KERN_INFO "------------- END_EFI_DUMP ----------------------");
	return;
}
static void lkm_efi_var_dump(struct lkm_efi_struct *var) {
	printk(KERN_INFO "------------- START:EFI_VAR_DUMP ----------------------");

	u32 attr = var->attr;
	if(attr&EFI_VARIABLE_NON_VOLATILE) {
		printk(KERN_INFO "	attr:NON_VOLATILE");
	}
	if(attr&EFI_VARIABLE_BOOTSERVICE_ACCESS) {
		printk(KERN_INFO "	attr:BOOTSERVICE_ACCESS");
	}
	if(attr&EFI_VARIABLE_RUNTIME_ACCESS) {
		printk(KERN_INFO "	attr:RUNTIME_ACCESS");
	}
	if(attr&EFI_VARIABLE_HARDWARE_ERROR_RECORD) {
		printk(KERN_INFO "	attr:HARDWARE_ERROR_RECORD");
	}
	if(attr&EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) {
		printk(KERN_INFO "	attr:TIME_BASED_AUTHENTICATED_WRITE_ACCESS");
	}
	if(attr&EFI_VARIABLE_APPEND_WRITE) {
		printk(KERN_INFO "	attr:APPEND_WRITE");
	}
	if(attr&EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS) {
		printk(KERN_INFO "	attr:AUTHENTICATED_WRITE_ACCESS");
	}
	efi_status_t status = var->status;
	if(status==EFI_SUCCESS) {
		printk(KERN_INFO "	status:SUCCESS!!!\n");
	}
	else if(status==EFI_WRITE_PROTECTED) {
		printk(KERN_INFO "	status:WRITE_PROTECT!!!\n");
	}
	else if(status==EFI_SECURITY_VIOLATION) {
		printk(KERN_INFO "	status:SECURITY_VIOLATION!!!\n");
	}
	else if(status==EFI_INVALID_PARAMETER) {
		printk(KERN_INFO "	status:INVALID_PARAM!!!\n");
	}
	printk(KERN_INFO "	size:%ld\n", var->size);
	printk(KERN_INFO "------------- END:EFI_VAR_DUMP ----------------------");
	return;
}
static void test_var(efi_char16_t *vname, efi_guid_t guid, char *name) {
	printk(KERN_INFO "------------- TEST_EFI_VAR(%s) ----------------------", name);

	struct lkm_efi_struct *var = lkm_efi_var_open(vname, guid);
	printk(KERN_INFO "	EFI_VAR_GET... 0x%s\n", name);
	if(!lkm_efi_var_get(var)) {
	       	printk(KERN_INFO "!OK: GET VAR:%s", name);
	}
	else {
	       	printk(KERN_INFO "!FAIL: GET VAR:%s", name);

	}
	lkm_efi_var_dump(var);
	printk(KERN_INFO "	EFI_VAR_SET... 0x%s\n", name);
	if(!lkm_efi_var_set(var)) {
	       	printk(KERN_INFO "!OK: SET VAR:%s", name);
	}
	else {
	       	printk(KERN_INFO "!FAIL: SET VAR:%s", name);
	}
	lkm_efi_var_dump(var);
	lkm_efi_var_close(var);
	printk(KERN_INFO "-----------------------------------------------");
	return;
}
static void test1(void) {

	lkm_efi_dump();
	test_var(L"Boot0000", EFI_GLOBAL_VARIABLE_GUID, "Boot0000");
	test_var(L"BootCurrent", EFI_GLOBAL_VARIABLE_GUID, "BootCurrent");
	test_var(L"SecureBoot", EFI_GLOBAL_VARIABLE_GUID, "SecureBoot");
	return;
}
//////////////////////////////////////////////////////////////////////////////////////
static struct lkm_efi_struct *lkm_efi_var_open(efi_char16_t *name, efi_guid_t guid) {
	if(!name) return NULL;

	struct lkm_efi_struct *v = kmalloc(sizeof(struct lkm_efi_struct), GFP_KERNEL);
	if(!v) return NULL;
	v->guid = guid;
	v->name = name;
	v->status = 0;
	v->size = 0;
	return v;
}
static void lkm_efi_var_close(struct lkm_efi_struct *v) {
	if(!v) return;
	if(v->data) kfree(v->data);
	kfree(v);
}
static int lkm_efi_var_get(struct lkm_efi_struct *v) {
	if(!v || !v->name) return -1;
	efi_status_t status;
	char *data = NULL;
	unsigned long data_size = 0;

	if(v->data) {
		kfree(v->data);
	}
	v->size = 0;

	status = efi.get_variable(v->name, &v->guid, &v->attr, &data_size, data);
	if(status==EFI_BUFFER_TOO_SMALL) {

   		data = (char*)kmalloc(data_size, GFP_KERNEL);
		if(!data) return -4;

		status = efi.get_variable(v->name, &v->guid, &v->attr, &data_size, data);
		v->status = status;
		if(status!=EFI_SUCCESS) {
			kfree(data);
			return -2;
		}
		else {

			v->data = (void*)data;
			v->size = (long)data_size;
			return 0;
		}

	}
	else if(status==EFI_NOT_FOUND) {
			return -3;
	}
	v->status = status;
	return -1;
}
static int lkm_efi_var_set(struct lkm_efi_struct *v) {
	if(!v||!v->name||!v->data||!v->size) return -1;

	v->status = efi.set_variable(v->name, &v->guid, v->attr, v->size, v->data);
	if(v->status!=EFI_SUCCESS) return -1;
	return 0;
}

static int __init lkm_efi_init(void) {
	printk(KERN_INFO "++++++ LKM_EFI, ale-alE-aLE-OP ++++++\n");
	long flag = efi.flags;

	if(!(flag & EFI_RT_SUPPORTED_TIME_SERVICES)) {
		printk(KERN_INFO "BIOS!!!!");
		return 0;
	}
	test1();

	return 0;
}
static void __exit lkm_efi_exit(void) {

	printk(KERN_INFO "++++++ LKM_EFI, HN-Hn-hn ++++++\n");
	//lkm_efi_var_close(lkm_efi_var);
	return;
}
module_init(lkm_efi_init);
module_exit(lkm_efi_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PARFIK");
MODULE_DESCRIPTION("Efi LKM...");
MODULE_VERSION("0.01");
