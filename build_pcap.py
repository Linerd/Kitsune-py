#!/usr/bin/env python

# This file generates a pcap file from 10000 normal traffic packets and 
# 90000 attack traffic packets

from scapy.all import *

import random

new_packets = []

# Read in normal traffic
packets = rdpcap('normal.pcap')
for pkt in packets:
    new_packets.append(pkt)

# Read in attack traffic
packets = rdpcap('attack.pcap')
for pkt in packets:
    new_packets.append(pkt)

random.shuffle(new_packets)

for pkt in new_packets:
    wrpcap('new.pcap', pkt, append=True)

print(len(new_packets))