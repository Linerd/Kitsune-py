#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import binascii

from scapy.all import *

# # Import config from parent directory
# sys.path.append("../")
# from config import *

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():

    if len(sys.argv)<3:
        print 'pass 2 arguments: <destination> "<message>"'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))

    # new.pcap file contains 100000 packets, where 90000 of them are attack packets and 10000 are normal packets,
    # identified by a Kitsune model trained with 55000 training packets
    packets = rdpcap('new.pcap')

    for pkt in packets:
        sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
