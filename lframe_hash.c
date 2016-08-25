#include "lframe.h"


lh_table_t * lh_init(lh_func_t *ops, int size)
{
	lh_table_t *lht;
	int i=0;
	lht = kmalloc(sizeof(lh_table_t) + size * sizeof(void *), GFP_KERNEL);
	if(lht) {
		memset(lht, 0, sizeof(lh_table_t) + size * sizeof(void *));
		lht->size = size;
		lht->ops.search = ops->search;
		lht->ops.free = ops->free;
		for(i=0; i<size; i++) {
			INIT_LIST_HEAD(&(lht->table[i]).list);	
		}
	}
	return lht;
}

void lh_exit(lh_table_t *lht)
{
	lh_entry_t *node, *tempnode;
	int i=0;
	if(lht) {
		for(i=0; i < lht->size; i++) {
			if(lht->table[i].count > 0) {
				list_for_each_entry_safe(node, tempnode, &lht->table[i].list, list) {
    					list_del(&node->list);
					if(lht->ops.free) {
						lht->ops.free(node);
					}
				}
			}
		}
		kfree(lht);
	}
}

void * lh_search(lh_table_t *lht, lhkey_t key, void *data)
{
	int index = key % lht->size;
	lh_entry_t *node, *tempnode;
	ret = 0;
	
	if(lht) {
		if(lht->table[index].count > 0) {
			list_for_each_entry_safe(node, tempnode, &lht->table[i].list, list) {
				ret = lht->ops.search((void *)node, data);
				if(ret == 0) {
					return node;
				}
			}
		}
	}
	return NULL;
}

int lh_insert(lh_table_t *lht, void *entry, lhkey_t key)
{
	int index = key % lht->size;
	list_add(&(lh_entry_t *)entry->list, &lht->table[index].list);
	lht->table[index].count++;
}

int lh_delete(lh_table_t *lht, void *entry, lhkey_t key)
{
	int index = key % lht->size;
	list_del(&(lh_entry_t *)entry->list, &lht->table[index].list);
	if(lht->ops.free) {
		lht->ops.free(node);
	}
	lht->table[index].count--;
	if(lht->table[index].count < 0) {
		printk("Bug: chain count is negative\n");
	}
	return 0;
}

