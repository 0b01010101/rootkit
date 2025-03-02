#include <linux/module.h>
#include <linux/kernel.h>

int init_module(void);
void cleanup_module(void);

 __attribute__((__section__(".init.text"))) int inje_module (void) {
	int a, c, b, d;
	a++;
	b++;
	c++;
	d++;
	a = a + c + b + d;
	printk ("Injected\n");
	init_module();
	printk ("Cntinue...Injected\n");
	return 0;
}

 __attribute__((__section__(".exit.text"))) int cnje_module (void) {
	printk ("By-By Injected ;}\n");
	 cleanup_module();
	return 0;
}

