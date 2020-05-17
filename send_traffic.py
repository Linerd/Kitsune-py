#!/usr/bin/python3.7
import pickle, binascii, argparse
from scapy.all import *
from config import *
from os.path import dirname, abspath

def get_if():
    ifs = get_if_list()
    iface = None  # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


def main():
    NUM_TRAIN = ADgrace + FMgrace
    NUM_TEST = EXECgrace

    iface = get_if()

    print ("Sending training packets (%s)..." % str(NUM_TRAIN))
    with PcapReader(dirname(abspath(__file__)) + '/' + TRAINING_DATA) as pkts:
        i = 0
        for pkt in pkts:
            if not i % 100: 
                print ("Sent", i)
                sys.stdout.flush()
            pkt = Ether(bytes(pkt))
            sendp(pkt, iface=iface, verbose=False)
            i += 1
            if NUM_TRAIN and NUM_TRAIN == i:
                break
    
    print ("Sending testing packets (%s)..." % str(NUM_TEST))
    with PcapReader(dirname(abspath(__file__)) + '/' + TESTING_DATA) as pkts:
        i = 0
        for pkt in pkts:
            if not i % 100: 
                print ("Sent", i)
                sys.stdout.flush()
            pkt = Ether(bytes(pkt))
            sendp(pkt, iface=iface, verbose=False)
            i += 1
            if NUM_TEST and NUM_TEST == i:
                break
    
    print ("Done")



if __name__ == '__main__':
    main()
