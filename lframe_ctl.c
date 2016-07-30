#include <asm/uaccess.h>
#include <linux/inet.h>
#include "lframe.h"

#define  COMMAND_MAX_LEN 128

struct lframe_config lfconfig;
struct dentry *lframe_ctl=NULL; 
int fv;

static int lframectl_show(struct seq_file *s, void *unused)
{
	int serverip = lfconfig.serverip;
	unsigned char *sip = (unsigned char *)&serverip;
	seq_printf(s, "serverip:%d.%d.%d.%d port:%d\n", sip[0], sip[1], sip[2], sip[3], lfconfig.dport);
        return 0;
}

static int lframectl_open(struct inode *inode, struct file *file)
{
        return single_open(file, lframectl_show, NULL);
}

static ssize_t lframe_ctl_write(struct file *fp, const char __user *user_buffer, 
                                size_t count, loff_t *position) 
{ 
	char *s;
	long kint;
	unsigned char *sip = (unsigned char *)&lfconfig.serverip;
	char command_buf[COMMAND_MAX_LEN];
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
	
  
	if ((s=strstr(command_buf, ":"))) {
		char dport[20] = {0};
		i = 0;
		s += 1; 	/* skip ':' char */
		while(*s && (s - command_buf) < COMMAND_MAX_LEN && (i < sizeof(dport)-2)) {
			if(*s == ' ' || *s == ',') {
				break;
			}
			dport[i++] = *s++;
		}
		dport[i] = '\0';

		if(kstrtol(dport, 0, &kint)) {
			printk("invalid sport in \"%s\"\n", command_buf);
			return -EINVAL;
		}
		if(kint > 0 && kint < 65535) {
			if(lfconfig.dport != kint) {
				lfconfig.dport = kint;
				lfconfig.reconfig = 1;
			}
		} else {
			printk("invalid sport in \"%s\"\n", command_buf);
			return -EINVAL;
		}
		
	} 
	if ((s=strstr(command_buf, ":"))) {
		char ipaddr[20] = {0};
		int serverip;
		i = 0;
		s = command_buf;	/* points to begining of buf */

		while(*s && (s - command_buf) < COMMAND_MAX_LEN && (i < sizeof(ipaddr)-2)) {
			if(*s == ' ' || *s == ','||*s == ':') {
				break;
			}
			ipaddr[i++] = *s++;
		}
		ipaddr[i] = '\0';
		
		serverip = in_aton(ipaddr);
		if(serverip != lfconfig.serverip) {
			lfconfig.serverip = serverip;
			lfconfig.reconfig = 1;
		}
	} 
	printk("new config installed: serverip =%d.%d.%d.%d server port=%d \n",
		sip[0], sip[1], sip[2], sip[3], lfconfig.dport);
	return count;
} 
static const struct file_operations lframe_ctl_fops = { 
	.open           = lframectl_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = single_release,
        .write 		= lframe_ctl_write, 
}; 
int init_lframectl(void)
{
	if(basedir)
		lframe_ctl = debugfs_create_file("lframe_ctl", 0644, basedir, &fv, &lframe_ctl_fops);
	return 0;
}

int exit_lframectl(void)
{
	if (!lframe_ctl) { 
		debugfs_remove(lframe_ctl);
	}
	return 0;
}

