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
    d['data'] = s[4*d['header_len']:]
    return d

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
	   print "ip total length: %d" % decoded['total_len']
           print 'payload length: %d' % (decoded['total_len'] - 4*decoded['header_len'] - 4*tcp_decoded['header_len'])
    	   print 'seq:%d' % tcp_decoded["seq"]
           print 'acknowlege:%d' % tcp_decoded["acknowlege"]
           print 'URG:%d  ACK:%d  PSH:%d  RST:%d  SYN:%d  FIN:%d' % (tcp_decoded["URG"],tcp_decoded["ACK"],tcp_decoded["PSH"],tcp_decoded["RST"],tcp_decoded["SYN"],tcp_decoded["FIN"])
           print 'header length:%d' % (tcp_decoded["header_len"] * 4)
           print 'window size:%d' % tcp_decoded["window"]
           print 'checksum:%d' % tcp_decoded["checksum"]
	   if tcp_decoded.has_key("options_mss"):
               print "mss:%s" % tcp_decoded["options_mss"]
           if tcp_decoded.has_key("options_window_factor"):
               print "windos factor:%s" % tcp_decoded["options_window_factor"]
           if tcp_decoded.has_key("options_sack"):
               print "sack:true"
           if tcp_decoded.has_key("options_timestamp"):
               print "timestamp:%s      timestamp_echo:%s" % (tcp_decoded["options_timestamp"],tcp_decoded["options_timestamp_echo"])
           if tcp_decoded['data']:
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

    except KeyboardInterrupt:
        print '%s' % sys.exc_type
        print 'shutting down'
        print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()
