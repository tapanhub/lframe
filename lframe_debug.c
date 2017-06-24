#include "lframe.h"


void __hexdump(unsigned char *start, int size, char *funname, int line)
{

	int i=0;
	printk ("[%s:%d] hexdump at %#lx, size=%d:\n", funname, line, (unsigned long)start, size);
	for(i=0; i<size; i+=8) {
		printk("%05d: %02x %02x %02x %02x %02x %02x %02x %02x\n",
			i, start[i], start[i+1], start[i+2], start[i+3], 
			start[i+4], start[i+5], start[i+6], start[i+7]);
	}
}
