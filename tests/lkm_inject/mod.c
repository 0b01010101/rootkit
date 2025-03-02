#include <linux/init.h> 
#include <linux/module.h>
#include <linux/kernel.h>

static int __init mod_init(void) {
	printk(KERN_INFO "++++++ LKM_INF, ale-alE-aLE-OP ++++++\n");
	return 0;
}
static void __exit mod_exit(void) {

	printk(KERN_INFO "++++++ LKM_INF, HN-Hn-hn ++++++\n");
	return;
}
module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PARFIK");
MODULE_DESCRIPTION("LKM_INF...");
MODULE_VERSION("1.0");
