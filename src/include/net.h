#ifndef	LKM_NET_H
#define LKM_NET_H

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/time.h>
#include <linux/netpoll.h>

struct lkm_nf_hook_priv {
	char	in_out;
};

#endif
