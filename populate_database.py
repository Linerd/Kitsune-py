#!/usr/bin/python3.7

"""
Populate training traffic for Kitsune as historical data
"""
from scapy.all import *
from scapy.all import *
import binascii
import pickle
from sdnator_due import *

KITSUNE_TRAINING_PACKET = 'kitsune::train.packet'

# set up drivers
due.set_pubsub({'driver': 'redis', 'host': 'localhost', 'port': 6379, 'opt': BUFFERED})
due.set_db({'driver': 'mongo', 'host': 'localhost', 'port': 27017, 'opt': BUFFERED})
# init due
# TODO: Remove COORDINATOR flag when put into production
due.init("kitsune_producer_%d" % random.randint(0, 100000), PRODUCER | COORDINATOR)

# Write the first 55000 (train data) to DUE
print ("Loading training data")
with open('./training_dataset.p', 'rb') as f:
    packets = pickle.load(f)

print ("Saving training data in Due")
# Write packets into due
curr_count = 0
for pkt in packets:
    if curr_count % 1000 == 0: print(curr_count)
    due.write(KITSUNE_TRAINING_PACKET, pkt)
    curr_count += 1

due.close()
print ("Done")
