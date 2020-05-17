#!/usr/bin/env python3.7

from scapy.all import *
import random, binascii
from config import *
from sdnator_due import *
import pickle, os
import multiprocessing as mp

print("Setting up DUE")
due.set_pubsub({'driver': 'redis', 'host': 'localhost', 'port': 6379})
due.set_db({'driver': 'mongo', 'host': 'localhost',
            'port': 27017, 'opt': BUFFERED, 'db': DB_NAME})
# TODO: Remove COORDINATOR flag when put into production
due.init("kitsune", CONSUMER | PRODUCER | COORDINATOR)

print("Reading historical training data from DUE")
training_packets = due.get(KITSUNE_TRAIN_DATA_KEY)

print("Saving training packets as data dump")
for i, pktdata in enumerate(training_packets):
    if not i % 1000: print (i)
    pkt = Ether(binascii.unhexlify(pktdata['value']))
    pkt.dst = DST_MAC
    wrpcap(TRAINING_DATA, pkt, append=True)

print("Reading testing data from DUE")
testing_packets = due.get(KITSUNE_TEST_DATA_KEY)

print("Saving testing packets as data dump")
for i, pktdata in enumerate(testing_packets):
    if not i % 1000: print (i)
    pkt = Ether(binascii.unhexlify(pktdata['value']))
    pkt.dst = DST_MAC
    wrpcap(TESTING_DATA, pkt, append=True)

due.close()
print("Done")
