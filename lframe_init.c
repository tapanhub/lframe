#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include "lframe.h"

extern lframe_entry_t __start_LFRAME;
extern lframe_entry_t __stop_LFRAME;

int init_module(void)
{
	lframe_entry_t  *entry = &__start_LFRAME;

    	for ( ; entry < &__stop_LFRAME; ++entry) {
		printk("initializing %s: \n", entry->modname);
		entry->init(entry);
    	}
	return 0;
}

void cleanup_module(void)
{
	lframe_entry_t  *entry = &__start_LFRAME;

    	for ( ; entry < &__stop_LFRAME; ++entry) {
		printk("uninitializing %s: \n", entry->modname);
		entry->exit(entry);
    	}
}

MODULE_LICENSE("GPL");
