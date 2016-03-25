#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/debugfs.h> 
#include <linux/fs.h>   
#include "lframe.h"

extern lframe_entry_t __start_LFRAME;
extern lframe_entry_t __stop_LFRAME;
struct dentry *basedir; 


static int  init_debugfs(void)
{
	basedir = debugfs_create_dir("lframe", NULL);
	return (0);
}

static void exit_debugfs(void) 
{ 
	if(basedir)
		debugfs_remove_recursive(basedir); 
} 
int init_module(void)
{
	lframe_entry_t  *entry = &__start_LFRAME;
	init_debugfs();

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
	exit_debugfs();
}

MODULE_LICENSE("GPL");
