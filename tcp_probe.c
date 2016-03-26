#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>

#include <net/tcp.h>
#include "lframe.h"


#define  tcp_probe_fun "tcp_transmit_skb"
#define  tcp_set_fun "tcp_set_state"


#define  COMMAND_MAX_LEN 128

unsigned long buffersize = 4096 *1024;
struct dentry *tcpprobe_ctl; 

char command_buf[COMMAND_MAX_LEN]; 
int filevalue; 

struct jprobe connect_probe;
typedef struct tcp_entry {
	struct timeval tv;
	int seq;
	int ack;
	int snd_ssthresh;
	int snd_cwnd;
	int rcv_wnd;
	int srtt_us;
	int packets_out;
	
} tcp_entry_t;

typedef struct tcp_probe_info {
	int connection_state;
	int tsize;
	int usize;
	int hsize;
	int max_idx;
	int idx;
	int saddr;
	int daddr;
	short int sport;
	short int dport;
	struct dentry *dbgfile; 
	struct debugfs_blob_wrapper dbgblob;
	char fields[16][16];
	tcp_entry_t entries[0];
} tcp_info_t;


tcp_info_t *tcpinfo = NULL;

tcp_info_t * alloc_tcp_info(unsigned long size)
{
	if(tcpinfo) {
		return tcpinfo;
	}
	tcpinfo = vmalloc(size);
	return tcpinfo;
}
void free_tcp_info(tcp_info_t *tcpinfo)
{
	if(tcpinfo) {
		vfree(tcpinfo);
	}
}
	
static int init_tcp_info(struct sock *sk, int state, tcp_info_t **tcpinfo)
{
	tcp_info_t *ti = *tcpinfo;
	struct inet_sock *inet = inet_sk(sk);
        unsigned char *dip = (unsigned char *)&inet->inet_daddr;
        unsigned char *sip = (unsigned char *)&inet->inet_saddr;
	char filename[64];
	

	if(ti == NULL) {
		return -1;
	}
	memset(ti, '\0', sizeof(tcp_info_t));
	(ti->dbgblob).data = ti;
	(ti->dbgblob).size = (unsigned long)buffersize;
	
	(*tcpinfo)->tsize = buffersize;
	(*tcpinfo)->usize = sizeof(tcp_entry_t);
	(*tcpinfo)->max_idx = (buffersize - sizeof(tcp_info_t) ) / (*tcpinfo)->usize;
	(*tcpinfo)->saddr = (int) inet->inet_saddr;
	(*tcpinfo)->daddr = (int) inet->inet_daddr;
	(*tcpinfo)->sport = (short int) inet->inet_sport;
	(*tcpinfo)->dport = (short int) inet->inet_dport;

	snprintf(filename, sizeof(filename), "tcp_%d.%d.%d.%d.%d_%d.%d.%d.%d.%d", 
			sip[0], sip[1], sip[2], sip[3], ntohs(inet->inet_sport),
			dip[0], dip[1], dip[2], dip[3], ntohs(inet->inet_dport));
	(ti)->dbgfile = debugfs_create_blob(filename, 0644, basedir, &(ti)->dbgblob);
	if (!(ti)->dbgfile) { 
		printk("unable to create debugfs file %s\n", filename); 
		return -1; 
	}
	return 0;

}
	
static void uninit_tcp_info(tcp_info_t **tcpinfo)
{
	free_tcp_info(*tcpinfo);
	*tcpinfo = NULL;
}

static ssize_t tcp_probe_write(struct file *fp, const char __user *user_buffer, 
                                size_t count, loff_t *position) 
{ 
        if(count > COMMAND_MAX_LEN ) 
                return -EINVAL; 
  
        //simple_write_to_buffer(command_buf, COMMAND_MAX_LEN, position, user_buffer, count); 
	if (strncmp(command_buf, "clear", strlen("clear")) == 0) {
		/*TODO clear logs */
	} else {
		printk("echo \"clear\" > command to clear all data  \n");
	}
	return count;
} 
 
static const struct file_operations tcp_probe_fops = { 
        .write = tcp_probe_write, 
}; 
 
static int  init_debugfs(void) 
{ 
	tcpprobe_ctl = debugfs_create_file("tcpproble_ctl", 0644, basedir, &filevalue, &tcp_probe_fops);
	tcpinfo = alloc_tcp_info(buffersize);
	if (!tcpprobe_ctl) { 
		printk("error creating command debugfs file tcpprobe_ctl"); 
		return (-ENODEV); 
	}
	return 0;
} 

static void  exit_debugfs(void) 
{ 
	uninit_tcp_info(&tcpinfo);
	if (!tcpprobe_ctl) { 
		debugfs_remove(tcpprobe_ctl);
	}
} 

void log_tcp_info(struct sock *sk, struct sk_buff *skb, tcp_info_t *tcpinfo)
{
	struct inet_sock *inet;
        struct tcp_sock *tp;
        struct tcp_skb_cb *tcb;
	struct timeval tv;
	tcp_entry_t *te;

	inet = inet_sk(sk);
	if(tcpinfo->saddr == inet->inet_saddr && tcpinfo->sport == inet->inet_sport
		&& tcpinfo->daddr == inet->inet_daddr && tcpinfo->dport == inet->inet_dport
		&& tcpinfo->max_idx < tcpinfo->idx) {
        	tp = tcp_sk(sk);
        	tcb = TCP_SKB_CB(skb);
		te =  &tcpinfo->entries[tcpinfo->idx];
		do_gettimeofday(&tv);

		te->tv = tv;
		te->seq = tcb->seq;
        	te->ack = tp->rcv_nxt;
        	te->rcv_wnd = tp->rcv_wnd;
        	te->snd_cwnd = tp->snd_cwnd;
        	te->snd_ssthresh = tp->snd_ssthresh;
        	te->srtt_us = tp->srtt_us;
        	te->packets_out = tp->packets_out;
		tcpinfo->idx++;
	}
}
void my_tcp_set_state(struct sock *sk, int state)
{
	struct inet_sock *inet = inet_sk(sk);
	unsigned char *dip = (unsigned char *)&inet->inet_daddr;
	unsigned char *sip = (unsigned char *)&inet->inet_saddr;
	if (state == TCP_ESTABLISHED) {
		printk("tcp connection established(sport=%d,dport=%d, sip=%d.%d.%d.%d dip=%d.%d.%d.%d\n", 
			ntohs(inet->inet_sport), ntohs(inet->inet_dport), sip[0], sip[1], sip[2], sip[3], 
			dip[0], dip[1], dip[2], dip[3]);
		init_tcp_info(sk, TCP_ESTABLISHED, &tcpinfo);
	} else if (state == TCP_CLOSE) {
		printk("tcp connection closed(sport=%d,dport=%d, sip=%d.%d.%d.%d dip=%d.%d.%d.%d\n", 
			ntohs(inet->inet_sport), ntohs(inet->inet_dport), sip[0], sip[1], sip[2], sip[3], 
			dip[0], dip[1], dip[2], dip[3]);
	}
	jprobe_return();
}

static int my_tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask)
{
		
	log_tcp_info(sk, skb, tcpinfo);

	jprobe_return();
	return 0;

}

int tcp_probe_init(void *arg)
{
	lframe_entry_t *en = (lframe_entry_t *)arg;
	int ret;
	ret = install_probe(&en->probe, (kprobe_opcode_t *)my_tcp_transmit_skb, tcp_probe_fun);
	ret = install_probe(&connect_probe, (kprobe_opcode_t *)my_tcp_set_state, tcp_set_fun);
	init_debugfs();
	return ret;
}

void tcp_probe_exit(void *arg)
{
	lframe_entry_t *en = (lframe_entry_t *)arg;
	uninstall_probe(&en->probe, tcp_probe_fun);
	uninstall_probe(&connect_probe, tcp_set_fun);
	exit_debugfs();
}
register_lframe(tcp_probe, tcp_probe_init, tcp_probe_exit);

