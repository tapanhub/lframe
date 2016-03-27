#!/bin/python
from struct import *

"""
typedef struct tcp_probe_info {
	int connection_state;
	int tsize;
	int usize;
	int hsize;
	int max_idx;
	int idx;
	int saddr;
	int daddr;
	short int sport;
	short int dport;
	int debugfs_created;
	struct dentry *dbgfile; 
	struct debugfs_blob_wrapper dbgblob;
	char fields[16][16];
	tcp_entry_t entries[0];
} tcp_info_t;

typedef struct tcp_entry {
        struct timeval tv;
        int seq;
        int ack;
        int snd_ssthresh;
        int snd_cwnd;
        int rcv_wnd;
        int srtt_us;
        int packets_out;

} tcp_entry_t;

"""

f=open("out")
header=f.read(320)
hdr=unpack('iiiiiiIIHHi', header[:40])
print hdr


