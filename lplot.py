#!/bin/python
from struct import *
import socket

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
def int_2_ip(ip, end=0):
	h="%08x" % ip
	hexdata=h.decode("hex")
	out=map(ord, hexdata)
	if(end == 1):
		out= out[::-1]
	return out

header=("conn_state", "tsize", "usize", "hsize", "max_idx", "idx", "saddr", "daddr", "sport", "dport") 
f=open("out")
filebuf=f.read();
f.close()

hdr=unpack('iiiiiiIIHHi', filebuf[:40])
print hdr
d=dict(zip(header, hdr))
sip=int_2_ip(d['saddr'], 1)
dip=int_2_ip(d['daddr'], 1)
sp=socket.ntohs(d['sport'])
dp=socket.ntohs(d['dport'])
count=d['idx']

print sip, dip


hdr=unpack('iiiiiiIIHHi', filebuf[:40])


