#!/usr/bin/python3.7

"""
Populate training traffic for Kitsune as historical data
"""
from scapy.all import *
from scapy.all import *
import binascii
import pickle
import pymongo
from sdnator_due import *
from config import *

# set up drivers
due.set_pubsub({'driver': 'redis', 'host': 'localhost', 'port': 6379, 'opt': BUFFERED})
due.set_db({'driver': 'mongo', 'host': 'localhost', 'port': 27017, 'opt': BUFFERED, 'db': DB_NAME})
# init due
# TODO: Remove COORDINATOR flag when put into production
due.init("Kistune Data Extractor", PRODUCER | COORDINATOR)

# Creating Mongo collections and indexes
print ("Initializing mongo")
mongo = pymongo.MongoClient(host='localhost', port=27017)
db = mongo[DB_NAME]
db.data.drop()
db.data.create_index("dataKey")
db.data.create_index("timestamp")
db.data.create_index("appID")

print ("Saving training and testing data")
NUM_TRAINING = ADgrace + FMgrace
with PcapReader('mirai_due.pcap') as pkts:
    i = 0
    for pkt in pkts:
        pktstr = binascii.hexlify(bytes(pkt))
        if not i % 1000: print (i)
        if i < NUM_TRAINING:
            due.write(KITSUNE_TRAIN_DATA_KEY, pktstr, DB_ONLY | DATA)
        else:
            due.write(KITSUNE_TEST_DATA_KEY, pktstr, DB_ONLY | DATA)
        i += 1

due.close()
print ("Done")
