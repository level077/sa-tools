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

mysql_com={'\x00':'COM_SLEEP',
	   '\x01':'COM_QUIT',
	   '\x02':'COM_INIT_DB',
	   '\x03':'COM_QUERY',
	   '\x04':'COM_FILED_LIST',
	   '\x05':'COM_CREATE_DB',
	   '\x06':'COM_DROP_DB',
           '\x07':'COM_REFRESH',
	   '\x08':'COM_SHUTDOWN',
	   '\x09':'COM_STATISTICS',
           '\x0a':'COM_PROCESS_INFO',
	   '\x0b':'COM_CONNECT',
	   '\x0c':'COM_PROCESS_KILL',
           '\x0d':'COM_DEBUG',
           '\x0e':'COM_PING',
	   '\x0f':'COM_TIME',
	   '\x10':'COM_DELAYED_INSERT',
	   '\x11':'COM_CHANGE_USER',
	   '\x12':'COM_BINLOG_DUMP',
	   '\x13':'COM_TABLE_DUMP',
	   '\x14':'COM_CONNECT_OUT',
	   '\x15':'COM_REGISTER_SLAVE',
	   '\x16':'COM_STMT_PREPARE',
	   '\x17':'COM_STMT_EXECUTE',
	   '\x18':'COM_STMT_SEND_LONG_DATA',
	   '\x19':'COM_STMT_CLOSE',
	   '\x1a':'COM_STMT_RESET',
	   '\x1b':'COM_SET_OPTION',
	   '\x1c':'COM_STMT_FETCH',
	   '\x1d':'COM_DAEMON',
	   '\x1e':'COM_BINLOG_DUMP_GTID'}

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
        d['options']=s[20:4*d['header_len']]
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
       #d['options']=s[20:4*(d['header_len']-5)]
       d["options"] = None
       d["options_kind"] = ord(s[20])
       if d["options_kind"] == 2:
           d["options_mss"] = socket.ntohs(struct.unpack('H',s[22:24])[0])
	   d["options"] = "mss:%d" % d["options_mss"]
       elif d["options_kind"] == 3:
           d["options_windows_factor"] = ord(s[22])
           d["options"] = "window factor:%d" % d["options_windows_factor"]
       elif d["options_kind"] == 8:
           d["options_timestamp"] = socket.ntohl(struct.unpack('I',s[22:26])[0]) 
	   d["options_timestamp_ack"] = socket.ntohl(struct.unpack('I',s[26:30])[0])
           d["options"] = "timestamp:%d	timestamp_ack:%d" %(d["options_timestamp"],d["options_timestamp_ack"])
    else:
       d['options']=None
    d['data'] = s[4*d['header_len']:]
    return d

def decode_mysql_packet(s):
    d = {}
    if s[4:5] in mysql_com:
    	d['COM'] = mysql_com[s[4:5]]
    	d['data'] = s[5:] 
    else:
	d['COM'] = "other"
    return d

def dumphex(s):
    bytes = map(lambda x: '%.2x' % x, map(ord, s))
    for i in xrange(0,len(bytes)/16):
        print '        %s' % string.join(bytes[i*16:(i+1)*16],' ')
    print '        %s' % string.join(bytes[(i+1)*16:],' ')

              
def print_packet(pktlen, data, timestamp):
    if not data:
        return

    if data[12:14]=='\x08\x00':
        decoded=decode_ip_packet(data[14:])
        if protocols[decoded['protocol']] == 'tcp':
           tcp_decoded = decode_tcp_packet(decoded['data'])
           mysql_decode = decode_mysql_packet(tcp_decoded["data"])
	   if mysql_decode["COM"] == "COM_QUERY":
	       print '%s.%f %s:%d > %s:%d	%s' % (time.strftime('%H:%M',time.localtime(timestamp)),timestamp % 60,decoded['source_address'],tcp_decoded["sport"],decoded['destination_address'],tcp_decoded["dport"],mysql_decode["data"])
    
if __name__=='__main__':

    if len(sys.argv) < 3:
        print 'usage: mysql_query_sniff.py <interface> <expr>'
	print 'eg:python ./mysql_query_sniff.py em1 dst 3306'
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
