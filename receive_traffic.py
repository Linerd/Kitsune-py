#!/usr/bin/python3.7
import sys
import struct
import os
from os.path import abspath, dirname
import binascii
from config import *

from scapy.all import *

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

i = 0

def handle_pkt(pkt):
    global i 
    if not i % 100: 
        print ("Received", i)
        sys.stdout.flush()
    i += 1

    wrpcap(dirname(abspath(__file__)) + '/results/' + RECEIVER_DATA, pkt, append=True)

def main():
    ifaces = list(filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/')))
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    try:
        os.remove(dirname(abspath(__file__)) + '/' + RECEIVER_DATA)
    except:
        pass
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
