#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/inet.h>

#include <net/tcp.h>
#include "lframe.h"


#define  tcp_probe_fun "tcp_transmit_skb"
#define  tcp_set_fun "tcp_set_state"


#define	COMMAND_MAX_LEN	128
#define	BUFFERSIZE		sizeof(tcp_info_t)
#define	TCPENTRIES	80


typedef struct tcp_filter {
	unsigned int	saddr;
	unsigned int	daddr;
	unsigned short int 	sport;
	unsigned short int	dport;
} tcp_filter_t;	
	

struct jprobe 	connect_probe;
typedef struct 	tcp_entry {
	struct 	timeval 	tv;
	int 	seq;
	int 	ack;
	int 	snd_ssthresh;
	int 	snd_cwnd;
	int 	rcv_wnd;
	int 	srtt_us;
	int 	packets_out;
	
} tcp_entry_t;

typedef struct 	tcp_probe_info {
	int 	connection_state;
	int 	tsize;
	int 	usize;
	int 	hsize;
	int 	idx;
	unsigned int 	saddr;
	unsigned int 	daddr;
	unsigned short int 	sport;
	unsigned short int 	dport;
	int 	debugfs_created;
	struct 	dentry *dbgfile; 
	struct 	debugfs_blob_wrapper dbgblob;
	char 	fields[16][16];
} tcp_info_t;



tcp_info_t 	*tcpinfo = NULL;
tcpio_msg_t 	*gtmsg = NULL;
static int 	tecount = 0;
struct 	dentry 	*tcpprobe_ctl; 
char 	command_buf[COMMAND_MAX_LEN + 4]; 
int 	filevalue; 
tcp_filter_t	filter;	

int filter_connection(struct sock *sk);
int check_pkt(struct sock *sk, tcp_info_t *tcpinfo);

tcp_info_t * clear_tcp_info(tcp_info_t *tcpinfo)
{
	if(tcpinfo->debugfs_created == 1) {
		debugfs_remove(tcpinfo->dbgfile);
	}
	memset(tcpinfo, '\0', sizeof(tcp_info_t));
	return tcpinfo;
}
tcp_info_t * alloc_tcp_info(unsigned long size)
{
	if(tcpinfo) {
		return tcpinfo;
	}
	tcpinfo = vmalloc(size);
	memset(tcpinfo, '\0', sizeof(tcp_info_t));
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
	

	/* if(ti == NULL || ti->debugfs_created == 1) { */
	if(ti == NULL) {
		return -1;
	}
	if (!filter_connection(sk)) {
		unsigned char *fdip = (unsigned char *)&filter.daddr;
		unsigned char *fsip = (unsigned char *)&filter.saddr;
		printk("sock_%d.%d.%d.%d.%d_%d.%d.%d.%d.%d and filter_%d.%d.%d.%d.%d_%d.%d.%d.%d.%d do not match\n", 
			sip[0], sip[1], sip[2], sip[3], ntohs(inet->inet_sport),
			dip[0], dip[1], dip[2], dip[3], ntohs(inet->inet_dport),
			fsip[0], fsip[1], fsip[2], fsip[3], ntohs(filter.sport),
			fdip[0], fdip[1], fdip[2], fdip[3], ntohs(filter.dport));

		return -1;
	}

	printk("sock_%d.%d.%d.%d.%d_%d.%d.%d.%d.%d matching with filter\n", 
			sip[0], sip[1], sip[2], sip[3], ntohs(inet->inet_sport),
			dip[0], dip[1], dip[2], dip[3], ntohs(inet->inet_dport));

	clear_tcp_info(ti);
	(ti->dbgblob).data = ti;
	(ti->dbgblob).size = (unsigned long)BUFFERSIZE;
	
	ti->tsize = BUFFERSIZE;
	ti->usize = sizeof(tcp_entry_t);
	ti->hsize = sizeof(tcp_info_t);
	ti->saddr = (int) inet->inet_saddr;
	ti->daddr = (int) inet->inet_daddr;
	ti->sport =  inet->inet_sport;
	ti->dport =  inet->inet_dport;
	ti->connection_state = state;

	snprintf(filename, sizeof(filename), "sock_%d.%d.%d.%d.%d_%d.%d.%d.%d.%d", 
			sip[0], sip[1], sip[2], sip[3], ntohs(inet->inet_sport),
			dip[0], dip[1], dip[2], dip[3], ntohs(inet->inet_dport));
	(ti)->dbgfile = debugfs_create_blob(filename, 0644, basedir, &(ti)->dbgblob);
	if (!(ti)->dbgfile) { 
		printk("unable to create debugfs file %s\n", filename); 
		return -1; 
	}
	(ti)->debugfs_created = 1;
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
	char *s;
	long kint;
	unsigned char *dip = (unsigned char *)&filter.daddr;
	unsigned char *sip = (unsigned char *)&filter.saddr;
	int i=0;
	
	memset(command_buf, '\0', sizeof(command_buf));

        if(count > COMMAND_MAX_LEN ) 
                return -EINVAL; 
	if(*position > COMMAND_MAX_LEN) {
		return 0;
	}
	if(*position + count > COMMAND_MAX_LEN) {
		count = COMMAND_MAX_LEN - *position;
	}
	if(copy_from_user(command_buf, user_buffer, count)) {
		return -EFAULT;
	}
	//*position += count;
	
  
	if (strncmp(command_buf, "clear", strlen("clear")) == 0) {
		clear_tcp_info(tcpinfo);
		return count;
	} 
	if ((s=strstr(command_buf, "sport="))) {
		char aport[20] = {0};
		i = 0;
		s += strlen("sport=");
		while(*s && (s - command_buf) < COMMAND_MAX_LEN && (i < sizeof(aport)-2)) {
			if(*s == ' ' || *s == ',') {
				break;
			}
			aport[i++] = *s++;
		}
		aport[i] = '\0';

		if(kstrtol(aport, 0, &kint)) {
			printk("invalid sport in \"%s\"\n", command_buf);
			return -EINVAL;
		}
		if(kint > 0 && kint < 65535) {
			filter.sport = htons(kint);
		} else {
			printk("invalid sport in \"%s\"\n", command_buf);
			return -EINVAL;
		}
		
	} 
	if ((s=strstr(command_buf, "dport="))) {
		char aport[20] = {0};
		i = 0;
		s += strlen("dport=");
		while(*s && (s - command_buf) < COMMAND_MAX_LEN && (i < sizeof(aport)-2)) {
			if(*s == ' ' || *s == ',') {
				break;
			}
			aport[i++] = *s++;
		}
		aport[i] = '\0';

		if(kstrtol(aport, 0, &kint)) {
			printk("invalid dport in \"%s\"\n", command_buf);
			return -EINVAL;
		}
		if(kint > 0 && kint < 65535) {
			filter.dport = htons(kint);
		} else {
			printk("invalid dport in \"%s\"\n", command_buf);
			return -EINVAL;
		}

	} 
	if ((s=strstr(command_buf, "saddr="))) {
		char ipaddr[20] = {0};

		i = 0;
		s += strlen("saddr=");
		while(*s && (s - command_buf) < COMMAND_MAX_LEN && (i < sizeof(ipaddr)-2)) {
			if(*s == ' ' || *s == ',') {
				break;
			}
			ipaddr[i++] = *s++;
		}
		ipaddr[i] = '\0';
		filter.saddr = in_aton(ipaddr);
	} 
	if ((s=strstr(command_buf, "daddr="))) {
		char ipaddr[20] = {0};

		i = 0;
		s += strlen("daddr=");
		while(*s && (s - command_buf) < COMMAND_MAX_LEN && (i < sizeof(ipaddr)-2)) {
			if(*s == ' ' || *s == ',') {
				break;
			}
			ipaddr[i++] = *s++;
		}
		ipaddr[i] = '\0';
		filter.daddr = in_aton(ipaddr);
	} 
	printk("new filter installed: saddr=%d.%d.%d.%d sport=%d daddr=%d.%d.%d.%d dport=%d\n",
		sip[0], sip[1], sip[2], sip[3], ntohs(filter.sport),
		dip[0], dip[1], dip[2], dip[3], ntohs(filter.dport));
	return count;
} 

static int tcp_probe_show(struct seq_file *s, void *unused)
{
	unsigned char *dip = (unsigned char *)&filter.daddr;
	unsigned char *sip = (unsigned char *)&filter.saddr;
	seq_printf(s, "filter installed: saddr=%d.%d.%d.%d sport=%d daddr=%d.%d.%d.%d dport=%d\n",
			sip[0], sip[1], sip[2], sip[3], ntohs(filter.sport),
			dip[0], dip[1], dip[2], dip[3], ntohs(filter.dport));
        return 0;
}

static int tcp_probe_open(struct inode *inode, struct file *file)
{
        return single_open(file, tcp_probe_show, NULL);
}

static const struct file_operations tcp_probe_fops = { 
	.open           = tcp_probe_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = single_release,
        .write 		= tcp_probe_write, 
}; 
 
static int  init_debugfs(void) 
{ 
	tcpprobe_ctl = debugfs_create_file("tcpprobe_ctl", 0644, basedir, &filevalue, &tcp_probe_fops);
	tcpinfo = alloc_tcp_info(BUFFERSIZE);
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

tcp_entry_t *get_tcp_entry(void)
{
	tcp_entry_t *te = NULL;

	if (tecount >= TCPENTRIES) {
		tcpio_send(gtmsg);
		gtmsg = NULL;
		tecount = 0;
	}
	if(tecount == 0 || gtmsg == NULL) {
		gtmsg = alloc_tcpio_mem(TCPENTRIES * sizeof(tcp_entry_t));
		if(gtmsg == NULL) {
			printk("Unable to allocate tcpio memory\n");
			return NULL;
		}
		tecount = 0;
	}
	te = &((tcp_entry_t *)gtmsg->buffer)[tecount];
	tecount++;
	return te;
}

int flush_tcp_entry(void)
{	
	if(gtmsg != NULL && tecount > 0) {
		gtmsg->len = sizeof(tcp_entry_t) * tecount;
		tcpio_send(gtmsg);
		gtmsg = NULL;
		tecount = 0;
	}
	return 0;
}
int check_pkt(struct sock *sk, tcp_info_t *tcpinfo)
{
	struct inet_sock *inet;

	inet = inet_sk(sk);

	if((tcpinfo->saddr == inet->inet_saddr) && (tcpinfo->sport == inet->inet_sport) && 
	(tcpinfo->daddr == inet->inet_daddr) && (tcpinfo->dport == inet->inet_dport)) {
		return 1;
	}
	return 0;
}

int filter_connection(struct sock *sk)
{

	struct inet_sock *inet;

	inet = inet_sk(sk);

	if(filter.saddr != 0 && !(filter.saddr == inet->inet_saddr)) {
		return 1;
	}
	if(filter.sport != 0 && !(filter.sport == inet->inet_sport)) {
		return 1;
	}
	if(filter.daddr != 0 && !(filter.daddr == inet->inet_daddr)) {
		return 1;
	}
	if(filter.dport != 0 && !(filter.dport == inet->inet_dport)) {
		return 1;
	}
	return 0;
}

void log_tcp_info(struct sock *sk, struct sk_buff *skb, tcp_info_t *tcpinfo)
{
	struct inet_sock *inet;
        struct tcp_sock *tp;
        struct tcp_skb_cb *tcb;
	struct timeval tv;
	tcp_entry_t *te;

	inet = inet_sk(sk);

	te = get_tcp_entry();

	if(te == NULL) {
		if(printk_ratelimit()) 
 			printk("get_tcp_entry returned NULL\n"); 
		return;
	}

	if(check_pkt(sk, tcpinfo)) {
        	tp = tcp_sk(sk);
        	tcb = TCP_SKB_CB(skb);
		do_gettimeofday(&tv);

		te->tv = tv;
		te->seq = tcb->seq;
        	te->ack = tp->rcv_nxt;
        	te->rcv_wnd = tp->rcv_wnd;
        	te->snd_cwnd = tp->snd_cwnd;
        	te->snd_ssthresh = tp->snd_ssthresh;
        	//te->srtt_us = tp->srtt_us;
        	te->srtt_us = 0;
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
		if(filter_connection(sk)) {
			flush_tcp_entry();
		}
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

