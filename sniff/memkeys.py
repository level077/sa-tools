#! /usr/bin/env python
"""
Example to sniff all memcached traffic on eth0 interface:
    sudo ./sniff.py eth0 port 11211
"""

import sys
import pcap
import string
import time
import socket
import struct
import threading

workthread = None
glock = threading.Lock()

memstat = {}

protocols={socket.IPPROTO_TCP:'tcp',
            socket.IPPROTO_UDP:'udp',
            socket.IPPROTO_ICMP:'icmp'}

memcache_request={ '\x00':'Get',
		'\x01':'Set',
		'\x02':'Add',
		'\x03':'Replace',
		'\x04':'Delete',
		'\x05':'Increment',
		'\x06':'Decrement',
		'\x07':'Quit',
		'\x08':'Flush',
		'\x09':'GetQ',
		'\x0a':'No-op',
		'\x0b':'version',
		'\x0c':'GetK',
		'\x0d':'GetKQ',
		'\x0e':'Append',
		'\x0f':'Prepend',
		'\x10':'Stat',
		'\x11':'SetQ',
		'\x12':'AddQ',
		'\x13':'ReplaceQ',
		'\x14':'DeleteQ',
		'\x15':'IncrementQ',
		'\x16':'DecrementQ',
		'\x17':'QuitQ',
		'\x18':'FlushQ',
		'\x19':'AppendQ',
		'\x1a':'PrependQ',
		'\x1b':'verbosity',
		'\x1c':'Touch',
		'\x1d':'GAT',
		'\x1e':'GATQ',
		'\x20':'SASL list memchs',
		'\x21':'SASL Auth',
		'\x22':'SASL Step',
		'\x30':'RGet',
		'\x31':'RSet',
		'\x32':'RSetQ',
		'\x33':'RAppend',
		'\x34':'RAppendQ',
		'\x35':'RPrepend',
		'\x36':'RPrependQ',
		'\x37':'RDelete',
		'\x38':'RDeleteQ',
		'\x39':'RIncr',
		'\x3a':'RincrQ',
		'\x3b':'RDecr',
		'\x3c':'RDecrQ',
		'\x3d':'Set VBucket',
		'\x3e':'Get VBucket',
		'\x3f':'Del VBucket',
		'\x40':'TAP Connect',
		'\x41':'TAP Mutation',
		'\x42':'TAP Delete',
		'\x43':'TAP Flush',
		'\x44':'TAP Opaque',
		'\x45':'TAP VBucket Set',
		'\x46':'TAP Checkpoint Start',
		'\x47':'TAP Checkpoint End'
}

memcache_status = { '\x00\00':'No error',
		'\x00\01':'Key not found',
		'\x00\02':'key exists',
		'\x00\03':'Value too large',
		'\x00\04':'Invalid arguments',
		'\x00\05':'Item not stored',
		'\x00\06':'Incr/Decr on non-numeric value',
		'\x00\07':'The vbucket belongs to another server',
		'\x00\08':'Authentication continue',
		'\x00\81':'Unkonw command',
		'\x00\82':'out of memory',
		'\x00\83':'Not support',
		'\x00\84':'Internal error',
		'\x00\85':'Busy',
		'\x00\86':'Temporary failure'
}

def decode_ip_packet(s):
    d={}
    d['version']=(ord(s[0]) & 0xf0) >> 4
    d['header_len']=ord(s[0]) & 0x0f
    d['tos']=ord(s[1])
    d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['flags']=(ord(s[6]) & 0xe0) >> 5
    d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['ttl']=ord(s[8])
    d['protocol']=ord(s[9])
    d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
    d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
    d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
    if d['header_len']>5:
        d['options']=s[20:4*(d['header_len']-5)]
    else:
        d['options']=None
    d['data']=s[4*d['header_len']:]
    return d

def decode_tcp_packet(s):
    d = {}
    d["sport"] = socket.ntohs(struct.unpack('H',s[0:2])[0])
    d["dport"] = socket.ntohs(struct.unpack('H',s[2:4])[0])
    d["seq"] = socket.ntohl(struct.unpack('I',s[4:8])[0])
    d["acknowlege"] = socket.ntohl(struct.unpack('I',s[8:12])[0])
    d["header_len"] = (ord(s[12]) & 0xf0) >> 4
    d["sign"] = ord(s[13])
    d["URG"] = (ord(s[13]) & 0x20) >> 5
    d["ACK"] = (ord(s[13]) & 0x10) >> 4
    d["PSH"] = (ord(s[13]) & 0x08) >> 3
    d["RST"] = (ord(s[13]) & 0x04) >> 2
    d["SYN"] = (ord(s[13]) & 0x02) >> 1
    d["FIN"] = (ord(s[13]) & 0x01)
    d["window"] = socket.ntohs(struct.unpack('H',s[14:16])[0])
    d["checksum"] = socket.ntohs(socket.ntohs(struct.unpack('H',s[16:18])[0]))
    d["URG_POINT"] = socket.ntohs(struct.unpack('H',s[18:20])[0])
    if d['header_len'] > 5:
       d['options']=s[20:4*(d['header_len']-5)]
    else:
       d['options']=None
    d['data'] = s[4*d['header_len']:]
    return d

def decode_memcache_packet(s):
    d = {}
    if s[1:2] in memcache_request:
        d["opcode"] = memcache_request[s[1:2]]
    else:
	d["opcode"] = 'Unknow command'
    d["key_length"] = socket.ntohs(struct.unpack('H',s[2:4])[0])
    d["extra_length"] = ord(s[4:5])
    d["type"] = ord(s[5:6])
    if s[0:1] == '\x81':
	if s[6:8] in memcache_status:
	    d["status"] = memcache_status[s[6:8]]
	else:
	    d["status"] = "Unknow"
    d["totle_length"] = socket.ntohl(struct.unpack('I',s[8:12])[0])
    d["opaque"] = socket.ntohl(struct.unpack('I',s[12:16])[0])
    d["cas"] = socket.ntohl(struct.unpack('I',s[16:20])[0])
    d["extra_data"] = s[24:(24+d["extra_length"])]
    d["key"] = s[(24+d["extra_length"]):(24+d["extra_length"]+d["key_length"])]
    return d

def dumphex(s):
    bytes = map(lambda x: '%.2x' % x, map(ord, s))
    for i in xrange(0,len(bytes)/16):
        print '        %s' % string.join(bytes[i*16:(i+1)*16],' ')
    print '        %s' % string.join(bytes[(i+1)*16:],' ')

              
def print_packet(pktlen, data, timestamp):
    global memstat,glock
    if not data:
        return

    if data[12:14]=='\x08\x00':
        decoded=decode_ip_packet(data[14:])
        if protocols[decoded['protocol']] == 'tcp':
           tcp_decoded = decode_tcp_packet(decoded['data'])
	   if tcp_decoded['data'][0:1] == '\x80':
		memcache_decoded = decode_memcache_packet(tcp_decoded['data'])
		if memcache_decoded["key_length"] > 0:
		    glock.acquire()
		    if memcache_decoded["key"] in memstat:
			memstat[memcache_decoded["key"]] += 1
		    else:
			memstat[memcache_decoded["key"]] = 1
                    glock.release()
		print '\n%s.%f %s:%d > %s:%d    %s    %s' % (time.strftime('%H:%M',
                                time.localtime(timestamp)),
                                timestamp % 60,
                                decoded['source_address'],
                                tcp_decoded["sport"],
                                decoded['destination_address'],
                                tcp_decoded["dport"],
                                memcache_decoded["opcode"],
                                memcache_decoded["key"])
	   if tcp_decoded['data'][0:1] == '\x81':
                memcache_decoded = decode_memcache_packet(tcp_decoded['data'])
                print '\n%s.%f %s:%d > %s:%d    %s    %s    status:%s    length:%d' % (time.strftime('%H:%M',
                                time.localtime(timestamp)),
                                timestamp % 60,
                                decoded['source_address'],
                                tcp_decoded["sport"],
                                decoded['destination_address'],
                                tcp_decoded["dport"],
                                memcache_decoded["opcode"],
                                memcache_decoded["key"],
                                memcache_decoded["status"],
                                (memcache_decoded["totle_length"] - memcache_decoded["extra_length"] - memcache_decoded["key_length"]))

class memThread(threading.Thread):
    def __init__(self):
	threading.Thread.__init__(self)
	self.running = False
	
    def run(self):
	global p,memstat
	self.running = True
	while self.running:
	    p.dispatch(1,print_packet) 
	f  = file('/tmp/memkeys.log','w')
	for item in sorted(memstat.iteritems(), key=lambda pair: pair[1], reverse=True):
		line = "%s	%d\n" % item
		f.write(line)
	f.close

    def shutdown(self):
	self.running = False
	self.join()

if __name__=='__main__':

    if len(sys.argv) < 3:
        print 'usage: python memkeys.py <interface> <expr>'
        sys.exit(0)
    p = pcap.pcapObject()
    dev = sys.argv[1]
    net, mask = pcap.lookupnet(dev)
    p.open_live(dev, 1600, 0, 100)
    p.setfilter(string.join(sys.argv[2:],' '), 0, 0)
    
    workthread = memThread()
    workthread.start()
    try:
        while 1:
		time.sleep(1)	

    except KeyboardInterrupt:
	workthread.shutdown()
	sys.exit(0)
