#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/timer.h> 
#include "lframe.h"



spinlock_t	lftimer_lock;
struct  	list_head 	lftimer_head;




int init_lftimer(void)
{
	memset(&lftimer_head, 0, sizeof(lftimer_head));
	INIT_LIST_HEAD(&lftimer_head);
	spin_lock_init(&lftimer_lock);
	return 0;
}

lftimer_t * lftimer_create(lftimerfun handler, unsigned long data, int secs)
{
	lftimer_t *node = kmalloc(sizeof(lftimer_t), GFP_KERNEL);
	if(node) {
		memset(node, 0, sizeof(lftimer_t));
		node->interval = secs;
		node->handler = handler;
		node->data = data;
		init_timer (&node->timer);
		spin_lock(&lftimer_lock);
		list_add(&(node->list), &lftimer_head);
		spin_unlock(&lftimer_lock);
	} else {
		printk("Unable to allocate memory for lftimer\n");
	}
	return node;
}

int lftimer_start(lftimer_t *node)
{
	unsigned long extime = jiffies + (node->interval * HZ); /* HZ gives number of ticks per second */
	node->timer.function = node->handler;
	node->timer.expires = extime;
	node->timer.data = node->data;
	add_timer (&node->timer);
	node->active = 1;
	return 0;
}

int lftimer_stop(lftimer_t *node)
{
	if(node->active == 1) {
		del_timer_sync(&node->timer);
		node->active = 0;
	}
	return 0;
}

int lftimer_delete(lftimer_t *delnode)
{
	lftimer_t *node, *tempnode;
	list_for_each_entry_safe(node, tempnode, &lftimer_head, list) {
		if(node == delnode) {
			if(node->active == 1) {
				del_timer_sync(&node->timer);
			}
			spin_lock(&lftimer_lock);
    			list_del(&node->list);
			spin_unlock(&lftimer_lock);
			kfree(node);
			break;
		}
	}
	return 0;
}
int exit_lftimer(void)
{
	lftimer_t *node, *tempnode;
	list_for_each_entry_safe(node, tempnode, &lftimer_head, list) {
		if(node->active == 1) {
			del_timer_sync(&node->timer);
		}
    		list_del(&node->list);
		kfree(node);
	}
	return 0;
}
