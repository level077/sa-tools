#! /usr/bin/env python
"""
Example to sniff all HTTP traffic on eth0 interface:
    sudo ./sniff.py eth0 "port 80"
"""

import sys
import pcap
import string
import time
import socket
import struct

rtt = {}

protocols={socket.IPPROTO_TCP:'tcp',
            socket.IPPROTO_UDP:'udp',
            socket.IPPROTO_ICMP:'icmp'}

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

def dumphex(s):
    bytes = map(lambda x: '%.2x' % x, map(ord, s))
    for i in xrange(0,len(bytes)/16):
        print '        %s' % string.join(bytes[i*16:(i+1)*16],' ')
    print '        %s' % string.join(bytes[(i+1)*16:],' ')

def print_rtt(pktlen, data, timestamp):
    if not data:
       return
    
    if data[12:14]=='\x08\x00':
       decoded=decode_ip_packet(data[14:])
       if protocols[decoded['protocol']] == 'tcp':
           tcp_decoded = decode_tcp_packet(decoded['data'])
           if tcp_decoded["sign"] == 18:
	       key = "%s:%d -- %s:%d" % (decoded['destination_address'],tcp_decoded["dport"],decoded['source_address'],tcp_decoded["sport"])
	       rtt[key] = {}
	       rtt[key]["seq"] = tcp_decoded['seq']
 	       rtt[key]["acknowlege"] = tcp_decoded["acknowlege"]
	       rtt[key]["SYN_ACK_TIME"] = timestamp
           if tcp_decoded["sign"] == 16:
	       key = "%s:%d -- %s:%d" % (decoded['source_address'],tcp_decoded["sport"],decoded['destination_address'],tcp_decoded["dport"])
	       if rtt.has_key(key) and rtt[key]["seq"] + 1 == tcp_decoded["acknowlege"]:
		  rtt[key]["EST_TIME"] = timestamp
		  rtt[key]["acknowlege"] = rtt[key]["acknowlege"] + decoded["total_len"] - 4*(tcp_decoded["header_len"] + decoded["header_len"])
 	   if tcp_decoded["sign"] == 24:
	       key_ctos = "%s:%d -- %s:%d" % (decoded['source_address'],tcp_decoded["sport"],decoded['destination_address'],tcp_decoded["dport"])
	       key_stoc = "%s:%d -- %s:%d" % (decoded['destination_address'],tcp_decoded["dport"],decoded['source_address'],tcp_decoded["sport"])
               if rtt.has_key(key_ctos) and rtt[key_ctos]["acknowlege"] == tcp_decoded["seq"]:
		  rtt[key_ctos]["CSEND_TIME"] = timestamp
	       if rtt.has_key(key_stoc) and rtt[key_stoc]["seq"] + 1 == tcp_decoded["seq"]:
		  rtt[key_stoc]["SSEND_TIME"] = timestamp
		  print "%s" % key_stoc
		  print "SYN_ACK_TIME:%f	EST_TIME:%f	CSEND_TIME:%f	SSEND_TIME:%f" % (rtt[key_stoc]["SYN_ACK_TIME"],rtt[key_stoc]["EST_TIME"],rtt[key_stoc]["CSEND_TIME"],rtt[key_stoc]["SSEND_TIME"])
		  print "     rtt:%f" %(rtt[key_stoc]["EST_TIME"] - rtt[key_stoc]["SYN_ACK_TIME"])
		  print "     scriptime:%f" %(rtt[key_stoc]["SSEND_TIME"] - rtt[key_stoc]["CSEND_TIME"])
		  del rtt[key_stoc]
              
def print_packet(pktlen, data, timestamp):
    if not data:
        return

    if data[12:14]=='\x08\x00':
        decoded=decode_ip_packet(data[14:])
        if protocols[decoded['protocol']] == 'tcp':
           tcp_decoded = decode_tcp_packet(decoded['data'])
           print '\n%s.%f %s:%d > %s:%d' % (time.strftime('%H:%M',
                                time.localtime(timestamp)),
                                timestamp % 60,
                                decoded['source_address'],
				tcp_decoded["sport"],
                                decoded['destination_address'],
				tcp_decoded["dport"])
           for key in ['version', 'header_len', 'tos', 'total_len', 'id',
                                'flags', 'fragment_offset', 'ttl']:
            print '    %s: %d' % (key, decoded[key])
           print '    header checksum: %d' % decoded['checksum']
           print '    protocol: %s' % protocols[decoded['protocol']]
        #print '    data:'
        #dumphex(decoded['data'])
           print '         seq: %s' % tcp_decoded['seq']
           print '         acknowledge: %s' % tcp_decoded['acknowlege']
           print '         header len: %d' % tcp_decoded['header_len']
           for key in ['sign','URG','ACK','PSH','RST','SYN','FIN']:
 	       print '         %s: %d' % (key,tcp_decoded[key])
           print '         window size: %d' % tcp_decoded['window']
           print '         checksum: %d' % tcp_decoded['checksum']
           print '         URG POINT: %d' % tcp_decoded['URG_POINT']
	   print repr(tcp_decoded['data'])
            

if __name__=='__main__':

    if len(sys.argv) < 3:
        print 'usage: sniff.py <interface> <expr>'
        sys.exit(0)
    p = pcap.pcapObject()
    #dev = pcap.lookupdev()
    dev = sys.argv[1]
    net, mask = pcap.lookupnet(dev)
    # note:    to_ms does nothing on linux
    p.open_live(dev, 1600, 0, 100)
    #p.dump_open('dumpfile')
    p.setfilter(string.join(sys.argv[2:],' '), 0, 0)

    # try-except block to catch keyboard interrupt.    Failure to shut
    # down cleanly can result in the interface not being taken out of promisc.
    # mode
    #p.setnonblock(1)
    try:
        while 1:
            p.dispatch(1, print_packet)

        # specify 'None' to dump to dumpfile, assuming you have called
        # the dump_open method
        #    p.dispatch(0, None)

        # the loop method is another way of doing things
        #    p.loop(1, print_packet)

        # as is the next() method
        # p.next() returns a (pktlen, data, timestamp) tuple 
        #    apply(print_packet,p.next())
    except KeyboardInterrupt:
        print '%s' % sys.exc_type
        print 'shutting down'
        print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()
    


# vim:set ts=4 sw=4 et:
