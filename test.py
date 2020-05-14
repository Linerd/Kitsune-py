from scapy.all import *

pkts = rdpcap('new.pcap')

print(len(pkts))