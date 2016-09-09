#!/bin/python
from __future__ import division
from struct import *
import socket, os, sys, getopt
import matplotlib.pyplot as plt

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
typedef struct {
	unsigned int msgtype;
	unsigned int msgid;
	unsigned int msglen;
} lio_hdr_t;
typedef struct {
	unsigned int msgtype;
	unsigned int msgid;
	unsigned int msglen;
} lio_hdr_t;

"""
msghdr=("msgtype", "msgid", "msglen")
header=("conn_state", "tsize", "usize", "hsize", "max_idx", "idx", "saddr", "daddr", "sport", "dport") 
uhdr=("sec", "usec", "seq", "ack", "snd_ssthresh", "snd_cwnd", "rcv_wnd", "srtt_us", "packets_out","r")
version="v1.0"
class tcpproble:
	def __init__(self):
		self.data=[]
		self.uhdr=("sec", "usec", "seq", "ack", "snd_ssthresh", "snd_cwnd", "rcv_wnd", "srtt_us", "packets_out","r")
	def adddata(self, data):
		self.data.append(

class ldata:
	def __init__(self, reader):
		self.reader=reader
		self.msghdr=("msgtype", "msgid", "msglen")
		self.hdrsize=12
		self.tcpprobelist=[]
	def process(self):
		tcpprobe_idseen=-1
		while 1:
			hdr=self.reader(12)
			if not hdr || (len(hdr) != 12):
				break
			h=unpack('III', hdr)
			ud=dict(zip(self.msghdr, h))
			if ud['msgtype'] == 0:	#TCPPROBE
				tpdata=self.reader(ud['msglen'])
				if not tpdata || (len(tpdata) != ud['msglen']):
					break
				if ud['msgid'] > tcpprobe_idseen:
					self.tcpprobelist.append(tcpprobe())
					tcpprobe_idseen = tcpprobe_idseen+1
				if ud['msgid'] >= len(self.tcpprobelist):
					print "something wrong.. msgid (%d) is not matching with listlen(%d)\n" % (ud['msgid'], len(self.tcpprobelist))
					continue
				self.tcpprobelist[ud['msgid']].adddata(tpdata)
		for tp in self.tcpprobelist:
			tp.plot()
def int_2_ip(ip, end=0):
	h="%08x" % ip
	hexdata=h.decode("hex")
	out=map(ord, hexdata)
	if(end == 1):
		out= out[::-1]
	return out
def get_header(fl):
	h=unpack('iiiiiiIIHHi', fl[:40])
	d=dict(zip(header, h))
	return d
	
def get_samples(data):
	uarray=[]
	count=int(len(data)/48)
	for i in range(count):
		udata=unpack('QQIIIIIIIi', data[(i*48):((i+1)*48)])
		uarray.append(udata)
		ud=dict(zip(uhdr, udata))
	return uarray
def convert_time(item):
	basetime=item[0] + (item[1]/1000000)
	basevalue=[basetime]
	basevalue.extend(list(item[2:]))
	return tuple(basevalue);
	
def rebase_items(uarray):
	rebase_uarray=[]
	i=0
	item=uarray[0]
	basevalue=convert_time(item)
	for item in uarray[1:]:
		value=convert_time(item)
		value=list(value)
		print "basevalue[1]=%d value[1]=%d\n" % (basevalue[1], value[1])
		if value[1] < basevalue[1]: 
			value[1] = 2^32 + (value[1])
		value[0]=value[0]-basevalue[0]
		value[1]=value[1]-basevalue[1]
		value[2]=value[2]-basevalue[2]
		rebase_uarray.append((value))
		print value
	return rebase_uarray


def main(argv):
	inputopts={'inputfile':''}
	try:
		opts, args = getopt.getopt(argv[1:], "vhi:", ["version", "ifile="])
	except getopt.GetoptError:
		print '%s  -i <input pcap file>' % (argv[0])
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print '%s  -i <input pcap file>' % (argv[0])
			sys.exit(2)
		elif opt in ("-i", "--ifile"):
			inputopts['inputfile'] = arg
		else:
			print "%s %s" % (argv[0], version)
			sys.exit(0)
	if inputopts['inputfile'] == '':
		print '%s  -i <input pcap file>' % (argv[0])
		sys.exit(2)

	f=open(inputopts['inputfile'])
	filebuf=f.read();
	f.close()

	uarray=get_samples(filebuf)
	print 'uarray received:%d' % (len(uarray))
	rebase_uarray=rebase_items(uarray)
	print 'items received:%d' % (len(rebase_uarray))

	plt.plot([x[0] for x in rebase_uarray], [x[1] for x in rebase_uarray])
	plt.xlabel('time (s)')
	plt.ylabel('bytes transmitted from server')
	plt.title('TCP time vs server data')
	plt.grid(True)
	plt.savefig(inputopts['inputfile']+".png")
	plt.show()
	
if __name__ == '__main__':
	try:
		main(sys.argv)
	except KeyboardInterrupt:
		print 'Interrupted'
	try:
		sys.exit(0)
	except SystemExit:
		os._exit(0)
