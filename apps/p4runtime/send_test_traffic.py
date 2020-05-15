#!/usr/bin/env python
import pickle, binascii
from scapy.all import *


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


def main():
    TEST_TRAFFIC_PATH = '../../testing_dataset.p'
    iface = get_if()

    with open(TEST_TRAFFIC_PATH, 'rb') as f:
        traffic = pickle.load(f)
        for j, hexstr in enumerate(traffic):
            if not j % 100: print j
            # if j == 1000:
            #     break
            pkt = Ether(binascii.unhexlify(hexstr))
            sendp(pkt, iface=iface, verbose=False)
            


if __name__ == '__main__':
    main()
