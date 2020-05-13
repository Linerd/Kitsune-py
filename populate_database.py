"""
A simple app that receives attacker IP address and block them
"""
from sdnator_due import *
from scapy.all import *
from scapy.all import *
import binascii
from pymongo import MongoClient

SONATA_DUE_PKT_CHANNEL = 'kitsune::train.packet'

# set up drivers
due.set_pubsub({'driver': 'redis', 'host': 'localhost', 'port': 6379})
due.set_db({'driver': 'mongo', 'host': 'localhost', 'port': 27017})
# init due
capabilities = [{'dataKey': "sonata::newly_opened_connections.attacker_ip", 'frequency': {'min': 0, 'max': 100}}]
# TODO: Remove COORDINATOR flag when put into production
due.init("sonata_producer_%d" % random.randint(0, 100000), PRODUCER | CONSUMER | COORDINATOR, capabilities=capabilities)

# Write the first 55000 (train data) to DUE
packets = rdpcap('mirai.pcap')
# Write packets into due
curr_count = 0
for pkt in packets:
    if curr_count % 1000 == 0: print(curr_count)
    # Start checking precisely after 54500 packets
    if curr_count >= 54500 and len(due.get({'dataKey': "kitsune::train.packet"})) == 55000:
        break
    due.write(SONATA_DUE_PKT_CHANNEL, binascii.hexlify(bytes(pkt)))
    curr_count += 1

print(len(due.get({'dataKey': "kitsune::train.packet"})))

due.close()