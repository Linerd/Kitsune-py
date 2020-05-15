#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import binascii

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP


def get_if():
    ifs = get_if_list()
    iface = None  # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


normal = "34c3d2e0fcc94c09d4c6127b080045c00058eef0000040010532c0a80201c0a8027103003cff000000004500003c58d640004006a215c0a802713ddc3edba6bf0050b4edd2da00000000a002390815180000020405b40402080a00028b3a0000000001030302"
malicious = "01005e7ffffa00166c7f82200800450001c7000040000211c410c0a80273effffffa04bf076c01b342624e4f54494659202a20485454502f312e310d0a484f53543a203233392e3235352e3235352e3235303a313930300d0a43414348452d434f4e54524f4c3a206d61782d6167653d36300d0a6c4f434154494f4e3a20687474703a2f2f3139322e3136382e322e3131353a343038352f6465736372697074696f6e2e786d6c0d0a5345525645523a20736d61727420686f6d652063616d6572612055506e502f312e31204d696e6955506e50642f312e370d0a4e543a2075726e3a736368656d61732d75706e702d6f72673a6465766963653a42617369633a310d0a55534e3a20757569643a34334345353046392d303439412d344245452d424138442d3243424135383242303544373a3a75726e3a736368656d61732d75706e702d6f72673a6465766963653a42617369633a310d0a4e54533a20737364703a616c6976650d0a4f50543a2022687474703a2f2f736368656d61732e75706e702e6f72672f75706e702f312f302f223b206e733d30310d0a30312d4e4c533a20310d0a424f4f5449442e55504e502e4f52473a20310d0a434f4e46494749442e55504e502e4f52473a20313333370d0a0d0a"

def main():

    if len(sys.argv) < 3:
        print 'pass 2 arguments: <destination> <type: 1 (normal) or 2 (malicious)> '
        exit(1)

    addr = sys.argv[1]
    type = int(sys.argv[2])
    assert type in (1, 2)
    if type == 1:
        src_pkt = binascii.unhexlify(normal)
    elif type == 2:
        src_pkt = binascii.unhexlify(malicious)

    iface = get_if()

    print "sending on interface %s" % (iface)
    pkt = Ether(src=get_if_hwaddr(iface), dst=addr)
    pkt = pkt / Ether(src_pkt).getlayer(1)
    # pkt.getlayer(0).type = 0x000
    pkt.show2()
    print(binascii.hexlify(str(pkt)))
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
