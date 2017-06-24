#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>

#include "lframe.h"

lftimer_t * lftimer = NULL;

void get_meminfo(unsigned long arg)
{
	lftimer_t *t = *((lftimer_t **) arg);
	printk("***[%s] is called at %ld jiffies***\n", __func__, jiffies); 
	lftimer_mod(t);
}

int mem_probe_init(void *arg)
{
	lftimer = lftimer_create(get_meminfo, ( unsigned long)&lftimer, 10);
	lftimer_start(lftimer);	
	return 0;
}

void mem_probe_exit(void *arg)
{
	if(lftimer) {
		lftimer_stop(lftimer);	
		lftimer_delete(lftimer);
	}
}
//register_lframe(mem_probe, mem_probe_init, mem_probe_exit);
