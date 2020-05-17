#!/usr/bin/env python3.7

from matplotlib import pyplot as plt
from matplotlib import cm
from Kitsune import Kitsune
from scipy.stats import norm
import time
import binascii
from scapy.all import *
from config import *
import pickle
import numpy as np
from sdnator_due import *

##############################################################################
# Kitsune a lightweight online network intrusion detection system based on an ensemble of autoencoders (kitNET).
# For more information and citation, please see our NDSS'18 paper: Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection

# This script demonstrates Kitsune's ability to incrementally learn, and detect anomalies in recorded a pcap of the Mirai Malware.
# The demo involves an m-by-n dataset with n=115 dimensions (features), and m=100,000 observations.
# Each observation is a snapshot of the network's state in terms of incremental damped statistics (see the NDSS paper for more details)

#The runtimes presented in the paper, are based on the C++ implimentation (roughly 100x faster than the python implimentation)
###################  Last Tested with Anaconda 3.6.3   #######################

# Set up due
dataKey = "kitsune::attacker_ip"
due.set_pubsub({'driver': 'redis', 'host': 'localhost', 'port': 6379})
due.set_db({'driver': 'mongo', 'host': 'localhost', 'port': 27017, 'opt': BUFFERED, 'db': DB_NAME})
# init due
# TODO: Remove COORDINATOR flag when put into production
due.init("Kitsune Packet Analyzer", CONSUMER | PRODUCER | COORDINATOR)

packet_limit = np.Inf #the number of packets to process

# KitNET params:
maxAE = 10 #maximum size for any autoencoder in the ensemble layer

print("Initiaizing Kitsune")
# Build Kitsune
K = Kitsune(dataKey,packet_limit,maxAE,FMgrace,ADgrace)

print("Running Kitsune with DUE:")

# print('Train Phase')

# i = 0
# while True:
#     if i % 1000 == 0:
#         print(i)
#     rmse = K.proc_next_packet()
#     if rmse == -1:
#         break
#     i += 1

# with open('./model.p', 'rb') as f:
#     K = pickle.load(f)

# print('Train Phase Completed')

# with open('./model.p', 'wb') as f:
#     pickle.dump(K, f)


# process packet
RMSEs = []
def proc_incoming_packet(pkt):
    pkt = Ether(binascii.unhexlify(pkt))
    rmse = K.proc_next_packet_due(pkt)
    # Per the paper, rmse is normalized so that rmse larger than 1 indicates anomaly
    # during training rmse is always 0
    # NOTE: uncomment below to enable blocking
    # if rmse > 1:
    #     due.write('kitsune::attacker_mac', pkt.src, PUB_ONLY)
    RMSEs.append((int(pkt.time * 1000000), rmse))

predictor = due.observe('p4runtime::packet.*')
predictor.subscribe(on_next=lambda d: proc_incoming_packet(d[0]))

# listen for completion
GLOBAL = {'done': False}
def dumping_pkts():
    print("Dumping results")
    with open('./results/kitsune_processed_pkts.p', 'wb') as f:
        pickle.dump(RMSEs, f)
    GLOBAL['done'] = True

completion = due.observe('p4runtime.mininent_command.done')
completion.subscribe(on_next=lambda d: dumping_pkts())

# run sender and listener
print("Start receiving traffic on h2")
due.write('p4runtime::mininet_command', 'h2::./receive_traffic.py &> ./receive_traffic.out', PUB_ONLY)

time.sleep(1.0)

print("Start sending traffic on h1")
due.write('p4runtime::mininet_command', 'h1::./send_traffic.py &> ./send_traffic.out', PUB_ONLY)

print("=========== Due Listener started. Ctrl/Cmd + C to exit ============")
def until_done():
    ret = GLOBAL['done']
    if ret:
        due.close()
    return ret
due.wait(until_done)
