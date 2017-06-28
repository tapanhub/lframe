#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/mmzone.h>
#include <linux/proc_fs.h>
#include <linux/quicklist.h>
#include <linux/seq_file.h>
#include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/atomic.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/pgtable.h>


#include "lframe.h"


lftimer_t * lftimer = NULL;

typedef struct  mem_entry {
        lio_hdr_t               hdr;
        struct  timeval         tv;
	unsigned long		totalmem;
	unsigned long		free;
	unsigned long		active;
	unsigned long		inactive;
	unsigned long		active_anon;
	unsigned long		inactive_anon;
	unsigned long		active_file;
	unsigned long		inactive_file;
	unsigned long		unevictable;
	unsigned long		shmem;
	unsigned long		slab;
	unsigned long		sreclaimable;
	unsigned long		sunreclaim;
	unsigned long		kernelstack;

} mem_entry_t;


tcpio_msg_t *get_mem_entry(void)
{
	mem_entry_t *me = NULL;
	tcpio_msg_t *gtmsg = NULL;

	gtmsg = alloc_tcpio_mem(sizeof(mem_entry_t));
	if(gtmsg == NULL) {
		printk("Unable to allocate tcpio memory\n");
		return NULL;
	}

	
	me = &(((mem_entry_t *)gtmsg->buffer)[0]);
	me->hdr.msgtype = MEM_PROBE;
	me->hdr.msgid = 0;
	me->hdr.msglen = sizeof(*me)-sizeof(lio_hdr_t);
	return gtmsg;
}

/* ref: static int meminfo_proc_show(struct seq_file *m, void *v) */

void get_meminfo(unsigned long arg)
{
	struct sysinfo i;
        unsigned long pages[NR_LRU_LISTS];
        int lru;
	lftimer_t *t = *((lftimer_t **) arg);
	mem_entry_t *me = NULL;
	tcpio_msg_t *gtmsg = NULL;

#define K(x) ((x) << (PAGE_SHIFT - 10))
        si_meminfo(&i);



        for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
                pages[lru] = global_page_state(NR_LRU_BASE + lru);

	
	gtmsg = get_mem_entry();
	if(!gtmsg) {
		goto end;
	}
	me = &(((mem_entry_t *)gtmsg->buffer)[0]);

	do_gettimeofday(&(me->tv));
	me->totalmem = K(i.totalram);
	me->free = K(i.freeram);
	me->active = K(pages[LRU_ACTIVE_ANON]   + pages[LRU_ACTIVE_FILE]);
	me->inactive = K(pages[LRU_INACTIVE_ANON] + pages[LRU_INACTIVE_FILE]);
	me->active_anon = K(pages[LRU_ACTIVE_ANON]);
	me->inactive_anon = K(pages[LRU_INACTIVE_ANON]);
	me->active_file = K(pages[LRU_ACTIVE_FILE]);
	me->inactive_file = K(pages[LRU_INACTIVE_FILE]);
	me->unevictable = K(pages[LRU_UNEVICTABLE]);
	me->shmem = K(i.sharedram);
	me->slab = K(global_page_state(NR_SLAB_RECLAIMABLE) + global_page_state(NR_SLAB_UNRECLAIMABLE));
	me->sreclaimable = K(global_page_state(NR_SLAB_RECLAIMABLE));
	me->sunreclaim = K(global_page_state(NR_SLAB_UNRECLAIMABLE));
	me->kernelstack = global_page_state(NR_KERNEL_STACK) * THREAD_SIZE / 1024;

	io_send(gtmsg);
	
	printk(" %s called \n", __func__);

end:
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
register_lframe(mem_probe, mem_probe_init, mem_probe_exit);
