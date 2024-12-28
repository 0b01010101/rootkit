#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

#define HOOK_INDX_MAX		   0x10		//maximal index in sys_call_table

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

#define push_rax() __asm__ volatile("push %rax");
#define push_regs()	\
	__asm__ volatile (		\
			"push %rax\n\t"	\
			"push %rbx\n\t"	\
			"push %rcx\n\t"	\
			"push %rdx\n\t"	\
			"push %rsi\n\t"	\
			"push %rdi\n\t"	\
			"push %rbp\n\t"	\
			"push %r8\n\t"	\
			"push %r9\n\t"	\
			"push %r10\n\t"	\
			"push %r11\n\t"	\
			"push %r12\n\t"	\
			"push %r13\n\t"	\
			"push %r14\n\t"	\
			"push %r15\n\t"	\
			"pushf");

#define pop_regs()	\
	__asm__ volatile (		\
			"popf\n\t"	\
			"pop %r15\n\t" 	\
			"pop %r14\n\t" 	\
			"pop %r13\n\t" 	\
			"pop %r12\n\t" 	\
			"pop %r11\n\t" 	\
			"pop %r10\n\t" 	\
			"pop %r9\n\t" 	\
			"pop %r8\n\t"	\
			"pop %rbp\n\t"	\
			"pop %rdi\n\t"	\
			"pop %rsi\n\t"	\
			"pop %rdx\n\t"	\
			"pop %rcx\n\t"	\
			"pop %rbx\n\t"	\
			"pop %rax");	
#define ret() __asm__ volatile("ret");

#define hook_prolog_x64(hook_t)			   \
	push_regs();				   \
	CR0_enable();				   \
	memcpy((void*)hook_t.code_addr, hook_t.code, 5);\
	CR0_disable();

#define hook_epilog_x64(hook_t)	\
	pop_regs()		\
	hook_t.orig();		\
	push_regs();		\
	hook_func(&hook_t);	\
	pop_regs();		\
	ret();			

#define __void		__attribute__ ((__noinline__)) __attribute__((naked)) void   
#define	__noinline	__attribute__ ((__noinline__))
#define ENTR(hook_t)	hook_prolog_x64(hook_t);
#define LEAV(hook_t)	hook_epilog_x64(hook_t);

typedef struct hook_sys {
	unsigned long table;	//addr of sys_call_table;
	unsigned long hook;	//addr of hook() function;
	unsigned long orig;	//addr of original sys_call();
	int	      indx;	//index of syscall in sys_call_table;
} hook_sys_t;

typedef struct hook_func {
	void (*orig)(void);	//addr of original function
	void (*hook)(void);	//addr of hook function
	unsigned long code_addr;//addr where we got code from
	char	   code[8];	//vziatiu code
}hook_func_t;

/*
 *
 * Чтобы поставить "jmp" на свою hook()-ю, надо вызвать inject_func(), передав в неё
 * 	sruct hook_func*, адреса куда(вставлять) и на что(прыгать) писать "jmp".
 * 	!!! sruct hook_func* - это ссылка для struct в модуле! одна struct привязана к одной hook()!!!
 * 	!!! в hook() надо писать "{ENTR(struct hook_func); body; LEAV(struct hook_func)} "!!!
 * 	!!! hook() должна имееть прототип __void hook(void). __void - это макрос.
 * 	!!! hook()-attr((naked)) поэтому в ней ЛУЧШЕ СРАЗУ делать вызов в другую функцию!!!
 * 	inject_func() заполняет структуру адресами и передаёт её адрес в hook_func();
	hook_func() просто записывает "call" на нашу hook() и сохраняет перезаписанные байты в struct
 * 		!!! struct должна быть создана при КОМПИЛЯЦИИ в модуле, а не динамически!!!
 *
 * sys()->вызывает orig()(в начале orig "jmp" на нашу hook())-> прыгает в нашу hook()->...:
 *	hook(): 1. резервирует место в стеке; сохраняет все регистры в стеке;
 *		3. восстанавливает байты в orig из struct hook_func(ОНА ГЛОБАЛЬНА и АДРЕС ВШИТ В hook())
 *		4. делает что хочет!!!лучше сразу вызвать другую функцию!!!
 *		5. восстанавливает регистрыж;
 *		5. вызывает orig() по адресу из struct;
 *		7. сохраняет регистры;
 *		6. как в первый раз... заражает orig(), вызывая inject_func();
 *		7. восстанавливает регистры
 *...-> возвращается в sys().
 */

void inject_func(struct hook_func *ht, void *orig, void *hook);
int hook_func(struct hook_func *hook_t);
int rest_func(struct hook_func *hook_t);

static unsigned long hook_syscall_table(struct hook_sys *hs);
static unsigned long rest_syscall_table(struct hook_sys *hs);

static unsigned long (*find_sym)(const char *name) = NULL;	//Will be "kallsyms_lookup_name()"
								
static unsigned long sym2addr(const char *name) {
	if(!find_sym) {
		struct kprobe kp = {
			.symbol_name = "kallsyms_lookup_name",
		};

		if(register_kprobe(&kp) < 0) return 0;
		find_sym = (unsigned long(*)(const char *name))kp.addr;
		unregister_kprobe(&kp);
	}

	return find_sym(name);
}

int rest_func(struct hook_func *hook_t) {

	CR0_enable();				   \
	memcpy((void*)hook_t->code_addr, hook_t->code, 5);
	memset((void*)hook_t, 0, sizeof(hook_func));
	CR0_disable();
	return 0;
}

int hook_func(struct hook_func *hook_t) {

	unsigned long hook = (unsigned long)hook_t->hook;
	unsigned long orig = (unsigned long)hook_t->orig;
	int code = *(unsigned int*)orig;
	if(code==0xFA1E0FF3) orig += 4;

	hook_t->code_addr = orig;
	int jmp_offs = hook - orig-(sizeof(int)+1);
	char patch[1+sizeof(int)] = {0xe9};

	//printk(KERN_INFO "!!! 1_HOOK_FUNC ... orig(%lx)--0x%lx||\n", orig, *(unsigned long*)orig);

	memcpy(((void*)&patch)+1, &jmp_offs, sizeof(jmp_offs));
	memcpy((void*)hook_t->code, (void*)orig, sizeof(patch));
	CR0_enable();
	memcpy((void*)orig, &patch, sizeof(patch));
	CR0_disable();

	//printk(KERN_INFO "!!! 2_HOOK_FUNC ... orig(%lx)--0x%lx||\n", orig, *(unsigned long*)orig);
	return 0;
}

void inject_func(struct hook_func *ht, void *orig, void *hook) {
	
	ht->orig = (void(*)(void))orig;
	ht->hook = (void(*)(void))hook;
	hook_func(ht);
	return;
}

static unsigned long hook_syscall_table(struct hook_sys *hs) {
	unsigned long *sys_table = 0;
	int i = hs->indx;

	if(!hs->table) hs->table = sym2addr("sys_call_table");
	sys_table = (unsigned long*)hs->table;
	if((sys_table==0) || i>HOOK_INDX_MAX || (hs->hook==0)) return 0;

	hs->orig = (unsigned long)sys_table[i];
	CR0_enable();
//SAVE POINT:
//	sys_table[i] = (unsigned long)hs->hook;
	CR0_disable();
		printk(KERN_INFO "HOOK syscall OK\n");

	return hs->orig;
}

static unsigned long rest_syscall_table(struct hook_sys *hs) {

	hs->hook = hs->orig;
	return hook_syscall_table(hs);
}
///////// TESTS ///////////////////////////////////
struct hook_sys sys_hook_close;
struct hook_func hk_math1;
struct hook_func hk_math2;
struct hook_func hk_math3;
struct hook_func hk_math4;
struct hook_func hk_math5;

int math1(void);
int math2(void);
int math3(void);
int math4(void);
int math5(void);
void hook_math1(void);
void hook_math2(void);
void hook_math3(void);
void hook_math4(void);
void hook_math5(void);
static void lkm_test_3(void);
static void test_hook_syscalltable(void);
void tst_math_all(void);
void tst_inj_all(void);
void tst_rest_all(void);

__void hook_math1(void){
	ENTR(hk_math1);		//hook_prolog_x64(hk_math1);
	printk(KERN_INFO "HOOK1 work-work-work .::::.. OK.\n");
	LEAV(hk_math1);		//hook_epilog_x64(hk_math1);
}

__void hook_math2(void) {
	hook_prolog_x64(hk_math2);
	printk(KERN_INFO "HOOK2 work-work-work... OK.\n");
	hook_epilog_x64(hk_math2);
}
__void hook_math3(void) {
	ENTR(hk_math3);
	printk(KERN_INFO "HOOK3 work-work-work... OK.\n");
	LEAV(hk_math3);
}
__void hook_math4(void) {
	ENTR(hk_math4);
	printk(KERN_INFO "HOOK4 work-work-work... OK.\n");
	LEAV(hk_math4);
}
__void hook_math5(void) {
	ENTR(hk_math5);
	printk(KERN_INFO "HOOK5 work-work-work... OK.\n");
	LEAV(hk_math5);
}
__attribute__ ((__noinline__)) int  math1(void) {
	long rip;
       	get_rip(rip);
	int f = 60+444;
	printk(KERN_INFO "MATH1...%x, rip(%lx)\n", f, rip);
	return f;
}

__noinline int math2(void) {
	int f = 60+444;
	printk(KERN_INFO "MATH2....\n");
	return f;
}

__noinline int math3(void) {
	int f = 60+444;
	printk(KERN_INFO "MATH3....\n");
	return f;
}
__noinline int math4(void) {
	int f = 60+444;
	printk(KERN_INFO "MATH4....\n");
	return f;
}
__noinline int math5(void) {
	int f = 60+444;
	printk(KERN_INFO "MATH5....\n");
	return f;
}

void tst_inj_all(void) {
	inject_func(&hk_math1, math1, hook_math1);
	inject_func(&hk_math2, math2, hook_math2);
	inject_func(&hk_math3, math3, hook_math3);
	inject_func(&hk_math4, math4, hook_math4);
	inject_func(&hk_math5, math5, hook_math5);
	return;
}
void tst_math_all(void) {
	math1();
	math2();
	math3();
	math4();
	math5();
	return;
}
void tst_rest_all(void) {
	rest_func(&hk_math1);
	rest_func(&hk_math2);
	rest_func(&hk_math3);
	rest_func(&hk_math4);
	rest_func(&hk_math5);
	return;
}

static void test_hook_syscalltable(void) {
	unsigned long *table = (unsigned long *)sys_hook_close.table;
	table[0] = 0xFFFFFFFF;
	long rip = 0;
       	get_rip(rip);
	printk(KERN_INFO "HI-Hi-hI HO-h0-Oh KH-kh-Kh...!!! I'm Here (%lx) ;)\n AAAAAAAAA!!! KERN PANIC :)\n", rip);

	void(*orig_sys_close)(void) = (void(*)(void)) sys_hook_close.orig;
	orig_sys_close();
	return;
}
static void lkm_test_3(void) {
	printk(KERN_INFO "++++ START_TEST: hook_sys_call_table() ++++\n");

	sys_hook_close.indx = 0;
	sys_hook_close.hook = (unsigned long)test_hook_syscalltable;
	hook_syscall_table(&sys_hook_close);
	
	printk(KERN_INFO "new sys_table[%x] == %lx||orig(%lx)||sys_table(%lx)\n", sys_hook_close.indx, sys_hook_close.hook, sys_hook_close.orig, sys_hook_close.table);
	unsigned long *systable = (unsigned long *)sys_hook_close.table;
	printk(KERN_INFO "0(%lx)|1(%lx)|2(%lx)|3(%lx)\n", systable[0], systable[1], systable[2], systable[3]);
	printk(KERN_INFO "|||||||||||||||||||||||||||||||||||||||\n");
	rest_syscall_table(&sys_hook_close);
	printk(KERN_INFO "0(%lx)|1(%lx)|2(%lx)|3(%lx)\n", systable[0], systable[1], systable[2], systable[3]);

	printk(KERN_INFO "---- END_TEST: hook_sys_call_table() ----\n");
	return;
}
////////////////////////////////////////////////////

static int __init lkm_hook_init(void) {
	printk(KERN_INFO "++++++ LKM_HOOK, ale-alE-aLE-OP ++++++\n");
//	lkm_test_3();
	printk(KERN_INFO "math1(0x%lx) dump:0x%lx, 0x%lx, 0x%lx | hook_math1(0x%lx) dump: 0x%lx, 0x%lx, 0x%lx\n", (unsigned long)math1,*(unsigned long*)math1,*(unsigned long*)math1+8,*(unsigned long*)math1+16,(unsigned long)hook_math1, *(unsigned long*)hook_math1,*(unsigned long*)hook_math1+8,*(unsigned long*)hook_math1+16);

	//start clean functions...
	printk(KERN_INFO ">>>>\n");
	tst_math_all();
	//inject and start functions...
	tst_inj_all();
	tst_math_all();
	//clean and start functions... 
	tst_rest_all();
	tst_math_all();

	return 0;
}
static void __exit lkm_hook_exit(void) {

	printk(KERN_INFO "++++++ LKM_HOOK, HN-Hn-hn ++++++\n");
	return;
}

module_init(lkm_hook_init);
module_exit(lkm_hook_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PARFIK");
MODULE_DESCRIPTION("Hook by address to MY address...");
MODULE_VERSION("0.01");
