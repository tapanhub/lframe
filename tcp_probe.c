#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/debugfs.h> 
#include <linux/fs.h>   

#include <net/tcp.h>
#include "lframe.h"


#define  tcp_probe_fun "tcp_transmit_skb"
#define  tcp_connect_fun "tcp_finish_connect"


#define  COMMAND_MAX_LEN 128


struct dentry *dirret,*fileret; 
struct dentry *dynsock; 

char command_buf[COMMAND_MAX_LEN]; 
int filevalue; 

struct jprobe connect_probe;



static ssize_t tcp_probe_write(struct file *fp, const char __user *user_buffer, 
                                size_t count, loff_t *position) 
{ 
        if(count > COMMAND_MAX_LEN ) 
                return -EINVAL; 
  
        simple_write_to_buffer(command_buf, COMMAND_MAX_LEN, position, user_buffer, count); 
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
 
static int  init_debug(void) 
{ 
    /* create a directory by the name dell in /sys/kernel/debugfs */
    dirret = debugfs_create_dir("lframe", NULL); 
      
    /* create a file in the above directory 
 *     This requires read and write file operations */
    fileret = debugfs_create_file("command", 0644, dirret, &filevalue, &tcp_probe_fops);
    if (!fileret) { 
        printk("error creating command file"); 
        return (-ENODEV); 
    } 
 
    return (0); 
} 
 
static void __exit exit_debug(void) 
{ 
    /* removing the directory recursively which 
 *     in turn cleans all the file */
    debugfs_remove_recursive(dirret); 
} 

void my_tcp_finish_connect(struct sock *sk, struct sk_buff *skb)
{
	struct inet_sock *inet = inet_sk(sk);
	unsigned char *dip = (unsigned char *)&inet->inet_daddr;
	unsigned char *sip = (unsigned char *)&inet->inet_saddr;
	printk("tcp connection established(sport=%d,dport=%d, sip=%d.%d.%d.%d dip=%d.%d.%d.%d\n", 
		ntohs(inet->inet_sport), ntohs(inet->inet_dport), sip[0], sip[1], sip[2], sip[3], 
		dip[0], dip[1], dip[2], dip[3]);
	jprobe_return();
}
static int my_tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask)
{
	struct inet_sock *inet;
        struct tcp_sock *tp;
        struct tcp_skb_cb *tcb;

	inet = inet_sk(sk);
        tp = tcp_sk(sk);
        tcb = TCP_SKB_CB(skb);

	printk("tp->rcv_wnd = %d, inet->inet_sport= %d, inet->inet_dport=%d\n", tp->rcv_wnd, ntohs(inet->inet_sport), ntohs(inet->inet_dport));
	jprobe_return();
	return 0;

}

int tcp_probe_init(void *arg)
{
	lframe_entry_t *en = (lframe_entry_t *)arg;
	int ret;
	ret = install_probe(&en->probe, (kprobe_opcode_t *)my_tcp_transmit_skb, tcp_probe_fun);
	ret = install_probe(&connect_probe, (kprobe_opcode_t *)my_tcp_finish_connect, tcp_connect_fun);
	return ret;
}

void tcp_probe_exit(void *arg)
{
	lframe_entry_t *en = (lframe_entry_t *)arg;
	uninstall_probe(&en->probe, tcp_probe_fun);
	uninstall_probe(&connect_probe, tcp_connect_fun);
}
register_lframe(tcp_probe, tcp_probe_init, tcp_probe_exit);


