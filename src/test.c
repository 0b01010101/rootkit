#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

int t_init(void);
int t_exit(void);

int t_init(void) {

	printk(KERN_INFO "++++++ LKM_TEST, Hale-halE-HaLE-OP ++++++\n");
	return 0;
}
int t_exit(void) {

	printk(KERN_INFO "++++++ LKM_TEST, HN-Hn-hn ++++++\n");
	return 0;
}
