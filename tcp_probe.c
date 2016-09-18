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
	lio_hdr_t 		hdr;
	struct 	timeval 	tv;
	int 			seq;
	int 			ack;
	int 			snd_ssthresh;
	int 			snd_cwnd;
	int 			rcv_wnd;
	int 			srtt_us;
	int 			packets_out;
} tcp_entry_t;

typedef struct 	tcp_probe_info {
	struct list_head list;
	int 		connection_state;
	int 		io_state;	/* 0 unknown, 1 connected, -1 failed */
	int 		tsize;
	int 		usize;
	int 		hsize;
	int 		idx;
	tcp_filter_t	filter;
	int 		debugfs_created;
	struct 	dentry 	*dbgfile; 
	lhkey_t		key;
	unsigned int	msgid;
	struct 	debugfs_blob_wrapper dbgblob;
} tcp_info_t;



int tcp_probe_search(void *node, void *data);
void free_tcp_info(tcp_info_t *tcpinfo);
int filter_connection(struct sock *sk);
int check_pkt(struct sock *sk, tcp_info_t *tcpinfo);
tcp_info_t *get_new_tcpinfo(void);
lhkey_t getkey(tcp_filter_t *filter);




tcpio_msg_t 		*gtmsg = NULL;
static int 		tecount = 0;
struct 	dentry 		*tcpprobe_ctl; 
char 			command_buf[COMMAND_MAX_LEN + 4]; 
int 			filevalue; 
tcp_filter_t		gfilter;	
static lh_table_t 	*hashtable;
static unsigned int	gmsgid=1;
lh_func_t ops = {(searchfunp_t)tcp_probe_search, (freefunp_t)free_tcp_info};




tcp_info_t * alloc_tcp_info(gfp_t flags)
{
	tcp_info_t *tcpinfo;
	tcpinfo = kmalloc(sizeof(tcpio_msg_t), flags);
	return tcpinfo;
}

int tcpprobe_io_send(void *msg)
{
	return io_send(msg);
}
	
void free_tcp_info(tcp_info_t *tcpinfo)
{
	if(tcpinfo->debugfs_created == 1) {
		debugfs_remove(tcpinfo->dbgfile);
	}
	if(tcpinfo) {
		kfree(tcpinfo);
	}
}
	
static int init_tcp_info(struct sock *sk, int state)
{
	tcp_info_t *ti = NULL;
	struct inet_sock *inet = inet_sk(sk);
        unsigned char *dip = (unsigned char *)&inet->inet_daddr;
        unsigned char *sip = (unsigned char *)&inet->inet_saddr;
	unsigned char *fdip = (unsigned char *)&gfilter.daddr;
	unsigned char *fsip = (unsigned char *)&gfilter.saddr;
	char filename[64];
	
	if (!filter_connection(sk) == 0) {
		printk("sock_%d.%d.%d.%d.%d_%d.%d.%d.%d.%d and filter_%d.%d.%d.%d.%d_%d.%d.%d.%d.%d do not match\n", 
			sip[0], sip[1], sip[2], sip[3], ntohs(inet->inet_sport),
			dip[0], dip[1], dip[2], dip[3], ntohs(inet->inet_dport),
			fsip[0], fsip[1], fsip[2], fsip[3], ntohs(gfilter.sport),
			fdip[0], fdip[1], fdip[2], fdip[3], ntohs(gfilter.dport));

		return -1;
	}

	ti = get_new_tcpinfo();
	if(ti == NULL) {
		printk("Unable to allocate memory for tcpinfo struct\n");
		return -1;
	}
	printk("sock_%d.%d.%d.%d.%d_%d.%d.%d.%d.%d and filter_%d.%d.%d.%d.%d_%d.%d.%d.%d.%d matching with filter\n", 
		sip[0], sip[1], sip[2], sip[3], ntohs(inet->inet_sport),
		dip[0], dip[1], dip[2], dip[3], ntohs(inet->inet_dport),
		fsip[0], fsip[1], fsip[2], fsip[3], ntohs(gfilter.sport),
		fdip[0], fdip[1], fdip[2], fdip[3], ntohs(gfilter.dport));

	(ti->dbgblob).data = ti;
	(ti->dbgblob).size = (unsigned long)BUFFERSIZE;
	
	ti->tsize = BUFFERSIZE;
	ti->usize = sizeof(tcp_entry_t);
	ti->hsize = sizeof(tcp_info_t);
	ti->filter.saddr = (int) inet->inet_saddr;
	ti->filter.daddr = (int) inet->inet_daddr;
	ti->filter.sport =  inet->inet_sport;
	ti->filter.dport =  inet->inet_dport;
	ti->connection_state = state;
	ti->key = getkey(&ti->filter);
	
	lh_insert(hashtable, (void *)ti, ti->key);

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
	
static ssize_t tcp_probe_write(struct file *fp, const char __user *user_buffer, 
                                size_t count, loff_t *position) 
{ 
	char *s;
	long kint;
	unsigned char *dip = (unsigned char *)&gfilter.daddr;
	unsigned char *sip = (unsigned char *)&gfilter.saddr;
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
		lh_exit(hashtable);
		hashtable = NULL;
		hashtable = lh_init(&ops, 128);
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
			gfilter.sport = htons(kint);
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
			gfilter.dport = htons(kint);
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
		gfilter.saddr = in_aton(ipaddr);
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
		gfilter.daddr = in_aton(ipaddr);
	} 
	printk("new filter installed: saddr=%d.%d.%d.%d sport=%d daddr=%d.%d.%d.%d dport=%d\n",
		sip[0], sip[1], sip[2], sip[3], ntohs(gfilter.sport),
		dip[0], dip[1], dip[2], dip[3], ntohs(gfilter.dport));
	return count;
} 

static int tcp_probe_show(struct seq_file *s, void *unused)
{
	unsigned char *dip = (unsigned char *)&gfilter.daddr;
	unsigned char *sip = (unsigned char *)&gfilter.saddr;
	seq_printf(s, "filter installed: saddr=%d.%d.%d.%d sport=%d daddr=%d.%d.%d.%d dport=%d\n",
			sip[0], sip[1], sip[2], sip[3], ntohs(gfilter.sport),
			dip[0], dip[1], dip[2], dip[3], ntohs(gfilter.dport));
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
tcp_info_t *get_new_tcpinfo(void)
{
	tcp_info_t *node;
	node = alloc_tcp_info(GFP_ATOMIC);
	if(node) {
		memset(node, 0, sizeof(tcp_info_t));
		INIT_LIST_HEAD(&node->list);
		node->msgid=gmsgid;
		gmsgid++;
	}
	return node;
}
 
static int  init_debugfs(void) 
{ 
	tcp_info_t *tcpinfo = NULL;
	tcpprobe_ctl = debugfs_create_file("tcpprobe_ctl", 0644, basedir, &filevalue, &tcp_probe_fops);
	tcpinfo = alloc_tcp_info(GFP_KERNEL);
	if (!tcpprobe_ctl) { 
		printk("error creating command debugfs file tcpprobe_ctl"); 
		return (-ENODEV); 
	}
	if(!tcpinfo) {
		printk("Unable to allocate tcpinfo\n");
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&tcpinfo->list);
	return 0;
} 

static void  exit_debugfs(void) 
{ 
	if (!tcpprobe_ctl) { 
		debugfs_remove(tcpprobe_ctl);
	}
} 

tcp_entry_t *get_tcp_entry(tcp_info_t *tcpinfo)
{
	tcp_entry_t *te = NULL;
	int allocated = 0;

	if (tecount >= TCPENTRIES) {
		if(tcpinfo->io_state == 0 || tcpinfo->io_state == 1) {
			tcpprobe_io_send(gtmsg);
			tcpinfo->io_state = 2;
		} else if (tcpinfo->io_state == 2) {
			if(get_io_status() == 0) {
				printk("logging stopped as io connection is still not ready\n");
				tcpinfo->io_state=-1;
			} else {
				tcpinfo->io_state=1;
			}
		} else {
			return NULL;
		}
		gtmsg = NULL;
		tecount = 0;
	}
	if(tecount == 0 || gtmsg == NULL) {
		tecount = 0;
		gtmsg = alloc_tcpio_mem(TCPENTRIES * sizeof(tcp_entry_t));
		if(gtmsg == NULL) {
			printk("Unable to allocate tcpio memory\n");
			return NULL;
		}
		allocated=1;
	}
	te = &(((tcp_entry_t *)gtmsg->buffer)[tecount]);
	te->hdr.msgtype = TCP_PROBE;
	te->hdr.msgid = tcpinfo->msgid;
	te->hdr.msglen = sizeof(*te)-sizeof(lio_hdr_t);
	tecount++;
	return te;
}

int flush_tcp_entry(void)
{	
	if(gtmsg != NULL && tecount > 0) {
		gtmsg->len = sizeof(tcp_entry_t) * tecount;
		tcpprobe_io_send(gtmsg);
		gtmsg = NULL;
		tecount = 0;
	}
	return 0;
}

int filter_connection(struct sock *sk)
{
	struct inet_sock *inet;

	inet = inet_sk(sk);
	if(gfilter.saddr != 0 && !(gfilter.saddr == inet->inet_saddr)) {
		return 1;
	}
	if(gfilter.sport != 0 && !(gfilter.sport == inet->inet_sport)) {
		return 1;
	}
	if(gfilter.daddr != 0 && !(gfilter.daddr == inet->inet_daddr)) {
		return 1;
	}
	if(gfilter.dport != 0 && !(gfilter.dport == inet->inet_dport)) {
		return 1;
	}
	return 0;
}

lhkey_t getkey(tcp_filter_t *filter)
{
	return (filter->saddr ^ filter->daddr ^ ((filter->sport << (sizeof(short int)))|(filter->dport)));
}

int tcp_probe_search(void *node, void *data)
{
	tcp_info_t *tcpinfo = (tcp_info_t *) node;
	tcp_filter_t *filter = (tcp_filter_t *)data;
	if((tcpinfo->filter.saddr == filter->saddr) && (tcpinfo->filter.sport == filter->sport) && 
	(tcpinfo->filter.daddr == filter->daddr) && (tcpinfo->filter.dport == filter->dport)) {
		return 0;
	}
	return -1;
}


void log_tcp_info(struct sock *sk, struct sk_buff *skb)
{
	struct inet_sock *inet = inet_sk(sk);
        struct 	tcp_sock *tp;
        struct 	tcp_skb_cb *tcb;
	struct 	timeval tv;
	tcp_entry_t *te;
	tcp_info_t *tcpinfo = NULL;
	lhkey_t	key;
	tcp_filter_t	filter = { 	
		.saddr=inet->inet_saddr,
		.sport=inet->inet_sport,
		.daddr=inet->inet_daddr,
		.dport=inet->inet_dport,
	};

	key = getkey(&filter);
	tcpinfo = lh_search(hashtable, key, &filter);

	if(tcpinfo) {
		te = get_tcp_entry(tcpinfo);

		if(te == NULL) {
			return;
		}

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
		init_tcp_info(sk, TCP_ESTABLISHED);
	} else if (state == TCP_CLOSE) {
		printk("tcp connection closed(sport=%d,dport=%d, sip=%d.%d.%d.%d dip=%d.%d.%d.%d\n", 
			ntohs(inet->inet_sport), ntohs(inet->inet_dport), sip[0], sip[1], sip[2], sip[3], 
			dip[0], dip[1], dip[2], dip[3]);
		if(filter_connection(sk) == 0) {
			lhkey_t key;
			tcp_info_t *tcpinfo = NULL;
			tcp_filter_t	filter = { 	
				.saddr=inet->inet_saddr,
				.sport=inet->inet_sport,
				.daddr=inet->inet_daddr,
				.dport=inet->inet_dport,
				};
			key = getkey(&filter);
			tcpinfo = lh_search(hashtable, key, &filter);
			lh_delete(hashtable, tcpinfo, key);
			flush_tcp_entry();
		}
	}
	jprobe_return();
}

static int my_tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask)
{
		
	log_tcp_info(sk, skb);

	jprobe_return();
	return 0;

}
int tcp_probe_init(void *arg)
{
	lframe_entry_t *en = (lframe_entry_t *)arg;
	int ret;
	ret = install_probe(&en->probe, (kprobe_opcode_t *)my_tcp_transmit_skb, tcp_probe_fun);
	ret = install_probe(&connect_probe, (kprobe_opcode_t *)my_tcp_set_state, tcp_set_fun);
	hashtable = lh_init(&ops, 128);
	init_debugfs();
	return ret;
}

void tcp_probe_exit(void *arg)
{
	lframe_entry_t *en = (lframe_entry_t *)arg;
	uninstall_probe(&en->probe, tcp_probe_fun);
	uninstall_probe(&connect_probe, tcp_set_fun);
	if(hashtable) {
		lh_exit(hashtable);
	}
	exit_debugfs();
}
register_lframe(tcp_probe, tcp_probe_init, tcp_probe_exit);

