#include <linux/slab.h>
#include <linux/kthread.h>

#include <linux/errno.h>
#include <linux/types.h>

#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <linux/delay.h>
#include <linux/un.h>
#include <linux/unistd.h>
#include <linux/wait.h>
#include <linux/ctype.h>
#include <asm/unistd.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <net/request_sock.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include "lframe.h"

#define SERVER_PORT 55555
#define SERVER_ADDR 0x7f000001
#define MODULE_NAME "tcp_io"

int tcpio_thread(void);
int tcpio_start(void);

struct tcpio_info {
	int connected;
	int running;
	struct socket *client_socket;
	struct task_struct *thread;
	struct task_struct *accept_worker;
};

struct tcpio_info *tcpio_info;
static struct workqueue_struct *tcpio_wq;


int create_socket(void)
{

	int error;
	struct socket *socket;
	struct sockaddr_in sin;

	if(tcpio_info->connected == 1 && lfconfig.reconfig != 1) {
		return 0;
	}
	if (tcpio_info->client_socket != NULL) {
		printk("[%s]release the client_socket\n", __func__);
		sock_release(tcpio_info->client_socket);
		tcpio_info->client_socket = NULL;
	} 

	error = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &tcpio_info->client_socket);
	printk("sock_create returned %d\n", error);

	if (error < 0) {
		printk(KERN_ERR "CREATE SOCKET ERROR");
		return -1;
	}

	socket = tcpio_info->client_socket;
	tcpio_info->client_socket->sk->sk_reuse = 1;

	if(lfconfig.serverip != 0) {
		sin.sin_addr.s_addr = lfconfig.serverip;
		sin.sin_family = AF_INET;
		if(lfconfig.dport)
			sin.sin_port = htons(lfconfig.dport);
		else
			sin.sin_port = htons(SERVER_PORT);
	} else {
		sin.sin_addr.s_addr = htonl(SERVER_ADDR);
		sin.sin_family = AF_INET;
		sin.sin_port = htons(SERVER_PORT);
	}
	error = socket->ops->connect(socket, (struct sockaddr *)&sin, sizeof(sin), 0);
	printk("connect returned %d\n", error);
	if (error < 0) {
		printk(KERN_ERR "connect failed");
		return -1;
	} else {
		printk("connected\n");
		tcpio_info->connected = 1;
	}
	return 0;

}

int tcpio_send(char *buf, int len)
{
	struct msghdr msg;
        struct kvec iv = { buf, len };
	int ret = 0;
	struct socket *sock = tcpio_info->client_socket;

	if(tcpio_info->connected == 0) {
		create_socket();
	}
	if(tcpio_info->connected == 1) {
		if (sock == NULL) {
			printk("ksend the cscok is NULL\n");
			return -1;
		}
		memset(&msg, 0, sizeof(msg));
		ret = kernel_sendmsg(sock, &msg, &iv, 1, len);
		if (ret < 0) {
			tcpio_info->connected = 0;
		}
	}
	return ret;
}

int tcpio_wq_function()
{
	DECLARE_WAIT_QUEUE_HEAD(wq);

	{
		tcpio_info->running = 1;
		current->flags |= PF_NOFREEZE;
		allow_signal(SIGKILL | SIGSTOP);
	}
	printk("thread started...\n");
	return 0;
}
/* http://www.ibm.com/developerworks/linux/library/l-tasklets/index.html */
int tcpio_start()
{
	int ret;
	tcpio_info->running = 1;
	tcpio_wq = create_workqueue("tcpio_queue");
	if (tcpio_wq) {
		/* Queue some work (item 1) */
		work = (my_work_t *)kmalloc(sizeof(my_work_t), GFP_KERNEL);
		if (work) {
			INIT_WORK( (struct work_struct *)work, tcpio_wq_function );
			work->x = 1;
			ret = queue_work( tcpio_wq, (struct work_struct *)work );
		}

		/* Queue some additional work (item 2) */
		work2 = (my_work_t *)kmalloc(sizeof(my_work_t), GFP_KERNEL);
		if (work2) {
			INIT_WORK( (struct work_struct *)work2, tcpio_wq_function );
			work2->x = 2;
			ret = queue_work( tcpio_wq, (struct work_struct *)work2 );
		}

	}
	return 0;
}


int init_tcpio()
{
	printk("tcpio module init\n");
	tcpio_info = kmalloc(sizeof(struct tcpio_info), GFP_KERNEL);
	tcpio_start();
	return 0;
}

void cleanup_tcpio()
{
	int err;

	printk("module cleanup\n");
	flush_workqueue(tcpio_wq);
	destroy_workqueue(tcpio_wq);
	if (tcpio_info->thread == NULL)
		printk(KERN_INFO MODULE_NAME ": no kernel thread to kill\n");
	else {
		/* free allocated resources before exit */
		if (tcpio_info->client_socket != NULL) {
			printk("release the client_socket\n");
			sock_release(tcpio_info->client_socket);
			tcpio_info->client_socket = NULL;
		}

		kfree(tcpio_info);
		tcpio_info = NULL;

		printk(KERN_INFO MODULE_NAME ": module unloaded\n");
	}
}
