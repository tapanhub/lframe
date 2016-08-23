#ifndef _LFRAME_H
#define _LFRAME_H
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/debugfs.h> 
#include <linux/fs.h>   
#include <linux/time.h>

typedef void (*lframe_init_t)(void *);
typedef void (*lframe_exit_t)(void *);

typedef struct lframe_entry {
    	lframe_init_t init;
    	lframe_exit_t exit;
	char *modname;
	struct jprobe probe;
	char *data;
	int  tsize;
	int  usize;
	int  idx;
} lframe_entry_t;

struct lframe_config {
	int sock_io_proto;
	int dport;
	int serverip;
	int reconfig;
};

typedef struct {
	struct 	list_head list;
	int  	len;
	char	buffer[];
} tcpio_msg_t;

typedef unsigned int lhkey_t;

typedef struct lh_entry {
	struct 	list_head list;
	lhkey_t	key;
	int	count;
} lh_entry_t;


typedef struct lh_funcs {
	int (*search) (void *, void *);	
	int (*free) (void *);
} lh_func_t;
		

typedef int (*searchfunp_t) (void *);
typedef struct lh_table {
	int 	size;
	lh_entry_t table[];
} lh_table_t;

extern void *alloc_tcpio_mem(int size);
extern void free_tcpio_mem(void *buf);
extern int tcpio_send(tcpio_msg_t *tmsg);

extern struct lframe_config lfconfig;
extern void cleanup_tcpio(void);
extern int init_tcpio(void);


extern lh_table_t * lh_init(lh_func_t *ops, int size);
extern void lh_exit(lh_table_t *lht);
extern void * lh_search(lh_table_t *lht, lhkey_t key, void *data);
extern int lh_insert(lh_table_t *lht, void *entry, lhkey_t key);
extern int lh_delete(lh_table_t *lht, void *entry, lhkey_t key);

#define register_lframe(name, initfun, exitfun)		\
    static lframe_entry_t __lframe_ ## initfun ## exitfun	\
    __attribute__((__section__("LFRAME"))) __used = {			\
	.init = (lframe_init_t)initfun,					\
	.exit = (lframe_exit_t)exitfun,					\
	.modname = #name,					\
    }

static inline int install_probe(struct jprobe *probe, kprobe_opcode_t *cb, char *symbol )
{
	int ret;
	probe->entry = (kprobe_opcode_t *) cb;
        probe->kp.addr = (kprobe_opcode_t *) kallsyms_lookup_name(symbol);
        if (!probe->kp.addr) {
                printk("unable to find %s to plant jprobe\n", symbol);
                return -1;
        }

        if ((ret = register_jprobe(probe)) < 0) {
                printk("register_jprobe failed, returned %d\n", ret);
                return -1;
        }
        printk("planted jprobe at %p, handler addr %p\n", probe->kp.addr, probe->entry);
	return ret;
}

static inline void uninstall_probe(struct jprobe *probe, char *symbol)
{
	unregister_jprobe(probe);
	printk("jprobe %s unregistered\n", symbol?:"");
}
extern struct dentry *basedir; 
int init_lframectl(void);
int exit_lframectl(void);
#endif
