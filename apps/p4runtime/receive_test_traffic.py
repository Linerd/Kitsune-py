#!/usr/bin/env python
import sys
import struct
import os
import binascii

from scapy.all import *

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

i = 0

def handle_pkt(pkt):
    global i 
    if not i % 100: print i
    i += 1

    wrpcap('receiver.pcap', pkt, append=True)

def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
