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
due.set_db({'driver': 'mongo', 'host': 'localhost',
            'port': 27017, 'opt': BUFFERED, 'db': DB_NAME})
# init due
# TODO: Remove COORDINATOR flag when put into production
due.init("Kitsune Packet Analyzer", CONSUMER | PRODUCER | COORDINATOR)

packet_limit = np.Inf  # the number of packets to process

# KitNET params:
maxAE = 10  # maximum size for any autoencoder in the ensemble layer

print("Initiaizing Kitsune")
# Build Kitsune
K = Kitsune(dataKey, packet_limit, maxAE, FMgrace, ADgrace)

print("Running Kitsune with DUE:")
RMSEs = []
with PcapReader('./results/receiver_noblocking.pcap') as pkts:
    i = 0
    for pkt in pkts:
        if not i % 1000: print (i)
        rmse = K.proc_next_packet_due(pkt)
        RMSEs.append((int(pkt.time * 1000000), rmse))
        i += 1

print("Dumping data")
with open('./results/kitsune_processed_pkts_noblocking_original.p', 'wb') as f:
    pickle.dump(RMSEs, f)

due.close()
