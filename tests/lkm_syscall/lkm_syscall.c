#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kernel_read_file.h>

//#define KPROBES_HAVE 1

#define SYM_FIND_START_LOW	sprint_symbol	//из экспортируемых ближе всего расположена к началу загрузки кода ядра(symbol-"_text")
#define SYM_FIND_START_POINT	filp_close	// "tcp_close"/"close_fd"/"file_close_fd" .. any exportable(by VMLINUX) symb_lol!!!
#define SYM_FIND_RANGE		0x200000	//range back from addr(from which we find pattern). !!!depends on SYM_START_POIN!!!

#ifdef KPROBES_HAVE
	#include <linux/kprobes.h>
#endif

#define SIGNATURE_FUNC	0x53, 0x48, 0x83, 0xec, 0x10, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0, \
			0x48, 0x89, 0x44, 0x24, 0x08, 0x31, 0xc0, 0x80, 0x3f, 0, 0xc7, 0x44, 0x24, 0x04, 0, 0, 0, 0, \
			0x75, 0x1e, 0x48, 0x8b, 0x54, 0x24, 0x08, 0x65, 0x48, 0x2b, 0x14, 0x25, 0x28, 0, 0, 0, \
			0x0f, 0x85, 0x83, 0, 0, 0, 0x48, 0x83, 0xc4, 0x10, 0x5b, 0xe9, 0x12, 0x78, 0xd4, 0, \
			0x31, 0xd2, 0x48

#define CR0_disable()		   \
	asm volatile(		   \
	 "push %rax\n"	  	   \
	 "mov %cr0, %rax \n"	   \
	 "or $0x0000000000010000, %rax \n"\
	 "mov %rax, %cr0 \n"	   \
	 "pop %rax \n"		   \
	 "sti"); 

#define CR0_enable()		    \
	asm volatile(		    \
	 "cli \n"	            \
	 "push %rax \n"	    	    \
	 "mov %cr0, %rax \n"	    \
	 "and $0xfffffffffffeffff, %rax \n"\
	 "mov %rax, %cr0 \n"	    \
	 "pop %rax");

/*return(in addr) RIP == first instruction of difine(push %%rax)*/
#define get_rip(addr)	\
	__asm__ volatile (		\
		"push %%rax\n\t"	\
		"call .+5\n\t"		\
		"pop %%rax\n\t"		\
		"sub $6, %%rax\n\t"	\
		"mov %%rax, %0\n\t"	\
		"pop %%rax\n\t"		\
		: "=r"(addr)::"%rax");
extern int SYM_FIND_START_POINT(struct file *, fl_owner_t);
extern int SYM_FIND_START_LOW(char *buf, unsigned long addr);

/////////////// DEBUGS() ///////////////////
static void lkm_test_all(void);
static void lkm_test_other(void);
static void lkm_test_sym2addr(void);
static void lkm_test_get_sym_sign(void);
static void lkm_test_get_sym_sprintf(void);
////////////////////////////////////////////

/*
 * Находит адрес(в RAM) символа из symbols_table linux kernel, 
 * вызывая функцию sym2addr(const char *name);
 * 	sym2addr() ищет адреса символов, вызывая kalls_lookup_name(const char *name),
 * 	но её адрес надо как-то найти: 
 * 		1. register_kprobe(struct kprobe *kp): использует интерфейс ядра KPROBES.
 * 			!!! НЕ ДАЁТ некоторые адреса !!!;
 *
 * 		2. get_sym_sprintf(char *name, unsigned long range): использует всегда
 * 			экспортируемую функцию sprintf_symbol(). Вычисляет(какой может) 
 * 			минимальный адрес загрузки ядра(kernTxTbase())->передаёт подряд 
 * 			с текущей позиции адреса в sprintf_symbol()->а она рассказывает,
 * 			какому символу соответствует адрес, или ошибка.Так ищет в цикле...;
 *
 * 		3. get_sym_sign(char *pattern, int size_pattern): ищет сигнатуру в заданном
 * 			диапазоне относительно адреса(до/после) всегда экспортируемой 
 * 			функции filp_close();
 *
 * 		4. get_sym_procfs(char *name): !!НАДО ДОПИСАТЬ!!Проблема: ядро палит, что
 * 			модуль запущен процессом insmod, и запрещает читать некоторые файлы.
 * 			Суть: просто читать /proc/kallsyms из модуля ядра.
 *		
 *		5. Можно: НАПИСАТЬ, чтобы в модуль передавались параметры с нужным адресом...
 *
 * TESTED kernel virsion: 6.8.11-amd64(kali linux)
 */

static int byt2byt(void *where, int size_where, void *pattern, int size_pattern);
static unsigned long long msr64get(int msr);
static unsigned long kernTxTbase(void);
static unsigned long sym2addr(const char *name);
static unsigned long SignInRange(unsigned long start, unsigned long range, char *pattern, int size_pattern);
static unsigned long get_find_sym(void);
static unsigned long get_sym_procfs(char *name);
static unsigned long get_sym_sprintf(char *name, unsigned long range);
static unsigned long get_sym_sign(char *pattern, int size_pattern);

static unsigned long (*find_sym)(const char *name) = NULL;		//Will be "kallsyms_lookup_name()"
static char sign_kallsyms_lookup_name[] = {SIGNATURE_FUNC};		//signature in linux kernel

static unsigned long long msr64get(int msr) {

	unsigned long msrl = 0, msrh = 0;
	asm volatile("rdmsr" : "=a"(msrl), "=d"(msrh) : "c"(msr));
	// NOTE: rdmsr is always return EDX:EAX pair value 
	return ((unsigned long long)msrh << 32) | msrl;
}

static int byt2byt(void *where_src, int size_where, void *pattern_src, int size_pattern) {
	char *where = where_src;
	char *pattern = pattern_src;

	for(int i=0; i<size_where; i++) {
		for(int g=0; g<size_pattern; g++) {
			if(where[i+g]==pattern[g]) {
				if(g==size_pattern-1) {
					return i;
				}
				continue;
			}
			break;
		}
	}
	return -1;
}

static unsigned long kernTxTbase(void) {

	unsigned long base = (unsigned long)SYM_FIND_START_LOW;
	base &= 0xFFFFFFFFFFE00000;		
	return base;
}

static unsigned long get_sym_sprintf(char *name, unsigned long range) {
	char *fname;
	char *curr_name;
	unsigned long base = kernTxTbase();
	int flen = strlen(name)+5;

	curr_name = kmalloc(8*26, GFP_KERNEL);
	if(!curr_name) return 0;
	fname = kmalloc(flen+8, GFP_KERNEL);
	if(!fname) goto gs_end; 

	strcpy(fname, name);
	strcat(fname, "+0x0/");
	range += base;

	for(; base<=range; base+=0x10) {
		sprint_symbol(curr_name, base);
	//	printk(KERN_INFO "range==%lx||base==%lx||curr_name(%s)|\n", range, base, curr_name);
		if(strncmp(curr_name, fname, flen) == 0) {
			kfree(curr_name);
			kfree(fname);
			return base;
		}
	}

	kfree(fname);
gs_end:
	kfree(curr_name);
	return 0;
}

static unsigned long SignInRange(unsigned long start, unsigned long range, char *pattern, int size_pattern) {
	
	unsigned long target = 0;
	unsigned long from = 0;
	
	from = start -= range; //SYM_FIND_RANGE;
	from &= (unsigned long)0xFFFFFFFFFFF00000;

	target = byt2byt((void*)from, start-from, (void*)pattern, size_pattern);
	if(target>=0) return target+from;

	target = byt2byt((void*)start, range, (void*)pattern, size_pattern);
	if(target>=0) return target+from;

	return 0;
}

static unsigned long get_sym_sign(char *pattern, int size_pattern) {
	return SignInRange((unsigned long)SYM_FIND_START_POINT, SYM_FIND_RANGE, pattern, size_pattern);

}
static unsigned long get_sym_procfs(char *name) {
	void *data = NULL;
	char *path = "/proc/kallsyms";
	size_t fsize = 0;

	int a = kernel_read_file_from_path(path, 0, &data, 0, &fsize, READING_POLICY);
	//printk(KERN_INFO "ret==%x|size==%x|data(%s)\n", a, fsize, data);
	kfree(data);
	if(a<=0) return 0;

	return 0;
}

static unsigned long get_find_sym(void) {
		char *need_name = "kallsyms_lookup_name";
	#ifdef KPROBES_HAVE
		struct kprobe kp = {
			.symbol_name = need_name,
		};

	//	printk(KERN_INFO "	find by kprobe...\n");
		if(register_kprobe(&kp) < 0) return 0;

		find_sym = (unsigned long(*)(const char *name))kp.addr;
		unregister_kprobe(&kp);
		if(find_sym==-1) find_sym = 0;
	#else
	//	printk(KERN_INFO "	find by Signature...\n");
		find_sym = (unsigned long(*)(const char *name))get_sym_sign(sign_kallsyms_lookup_name, sizeof(sign_kallsyms_lookup_name));
		if(find_sym) return (unsigned long)find_sym;
		
	//	printk(KERN_INFO "	find by sprint_symbol()...\n");
		find_sym = (unsigned long(*)(const char *name))get_sym_sprintf(need_name, 0x200000);
		if(find_sym) return (unsigned long)find_sym;

	//	printk(KERN_INFO "	find by procfs...\n");
		find_sym = (unsigned long(*)(const char *name))get_sym_procfs(need_name);
		//if(find_sym) return find_sym;
	#endif
	return (unsigned long)find_sym;
}

static unsigned long sym2addr(const char *name) {

	if(!find_sym) {
		get_find_sym();
	}
	if(name && find_sym) return find_sym(name);

	return 0;
}

static void lkm_test_get_sym_sign(void) {
	long a;
	printk(KERN_INFO "++++ TEST_START: get_sym_sign() ++++\n");

	a = get_sym_sign(sign_kallsyms_lookup_name, sizeof(sign_kallsyms_lookup_name));
	printk(KERN_INFO "TEST: kallsyms_lookup_name addr: %lx\n", a);

	printk(KERN_INFO "____ TEST_END: get_sym_sprintf() ____\n");
	return;
}

static void lkm_test_get_sym_sprintf(void) {
	printk(KERN_INFO "++++ TEST_START: get_sym_sprinf() ++++\n");

	char *n = "kallsyms_lookup_name";
	char *n1 = "sprint_symbol";
	char *n2 = "startup_64";
	char *n3 = "filp_close";
	char *n4 = "sys_call_table";
	long a, a1, a2, a3, a4;
	a  = get_sym_sprintf(n,  0x200000);
	a1 = get_sym_sprintf(n1, 0x200000);
	a2 = get_sym_sprintf(n2, 0x200000);
	a3 = get_sym_sprintf(n3, 0x200000);
	a4 = get_sym_sprintf(n4, 0x200000);
	printk(KERN_INFO "%s|%lx\n%s|%lx\n%s|%lx\n%s|%lx\n%s|%lx\n", n, a, n1, a1, n2, a2, n3, a3, n4, a4);

	printk(KERN_INFO "____ TEST_END: get_sym_sprintf() ____\n");
	return;
}

static void lkm_test_sym2addr(void) {
	long a;
	printk(KERN_INFO "++++ TEST_START: sym2addr() ++++\n");

	a = sym2addr("kallsyms_lookup_name");
	printk(KERN_INFO "TEST: kallsyms_lookup_name addr: %lx\n", a);

	a = sym2addr("sys_call_table");
	printk(KERN_INFO "TEST: sys_call_table[] addr: %lx\n", a);

	a = sym2addr("startup_64");
	printk(KERN_INFO "TEST: startup_64 addr: %lx\n", a);
	
	a = sym2addr("_text");
	printk(KERN_INFO "TEST: _text addr: %lx\n", a);


	printk(KERN_INFO "____ TEST_END: sym2addr() ____\n");
	return;
}

static void lkm_test_other(void) {
	long a;
	printk(KERN_INFO "++++ TEST_START: OTHER() ++++\n");

	a = kernTxTbase();
	printk(KERN_INFO "kernel 'text' segment: %lx\n", a);
	
	a = msr64get(MSR_LSTAR);
	printk(KERN_INFO " ENTRY64 handler addr: %lx\n", a);

	get_rip(a);
	printk(KERN_INFO "RIP: (%lx), func_addr(%lx)\n", a, (unsigned long)lkm_test_other);

	printk(KERN_INFO "____ TEST_END: OTHER() ____\n");
	return;
}

static void lkm_test_all(void) {

	lkm_test_sym2addr();
	lkm_test_get_sym_sprintf();
	lkm_test_get_sym_sign();
	lkm_test_other();
	return;
}

static int __init lkm_syscall_init(void) {
	printk(KERN_INFO "++++++ LKM_SYSCALL, HI! ++++++\n");
	lkm_test_all();
	return 0;
}

static void __exit lkm_syscall_exit(void) {
	printk(KERN_INFO "++++++ LKM_SYSCALL, By-by ++++++\n");
	return;
}

module_init(lkm_syscall_init);
module_exit(lkm_syscall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PARFIK");
MODULE_DESCRIPTION("Find symbols from kernel");
MODULE_VERSION("1.11");
