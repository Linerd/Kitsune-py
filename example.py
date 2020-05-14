from Kitsune import Kitsune
import numpy as np
import time
from sdnator_due import *
import binascii
from scapy.all import *
from config import *

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
due.set_db({'driver': 'mongo', 'host': 'localhost', 'port': 27017})
# init due
interest = 'kitsune::train.packet'
# TODO: Remove COORDINATOR flag when put into production
due.init("kitsune", CONSUMER | PRODUCER | COORDINATOR, interests = [interest], capabilities = [dataKey])


# Load Mirai pcap (a recording of the Mirai botnet malware being activated)
# The first 70,000 observations are clean...
print("Unzipping Sample Capture...")
import zipfile
with zipfile.ZipFile("mirai.zip","r") as zip_ref:
    zip_ref.extractall()

packet_limit = np.Inf #the number of packets to process

# KitNET params:
maxAE = 10 #maximum size for any autoencoder in the ensemble layer

# Build Kitsune
K = Kitsune(dataKey,packet_limit,maxAE,FMgrace,ADgrace)

print("Running Kitsune with DUE:")

print('Train Phase')
i = 0
# normal_count = 0
# attack_count = 0
while True:
    if i % 1000 == 0:
        print(i)
    rmse = K.proc_next_packet()
    if rmse == -1:
        break

    # Used for generating new pcap containing both normal and attack packets
    # # Starting at the 100000th packet to get rid of the training data
    # if i > 100000:
    #     if rmse != 0.0:
    #         if rmse < 1:
    #             # Normal traffic
    #             if normal_count < NUMBER_OF_NORMAL_PACKETS:
    #                 wrpcap('normal.pcap', pkt, append=True)
    #                 normal_count += 1
    #         else:
    #             # Attack traffic
    #             if attack_count < NUMBER_OF_ATTACK_PACKETS:
    #                 wrpcap('attack.pcap', pkt, append=True)
    #                 attack_count += 1
    # i += 1
    i+=1

print('Train Phase Completed')

def proc_incoming_packet(pkt):
    pkt = Ether(binascii.unhexlify(pkt))
    rmse = K.proc_next_packet_due(pkt)
    # Per the paper, rmse is normalized so that rmse larger than 1 indicates anomaly
    if rmse > 1:
        due.write('kitsune::attacker_ip', pkt['IP'].src)
    
    print(rmse, pkt)


def handle_error(e):
    print e

predicter = due.observe('p4runtime::packet.*')
predicter.subscribe(on_next=lambda d: proc_incoming_packet(d[0]), 
                    on_error=lambda e: handle_error(e))

print("=========== Due Listener started. Ctrl/Cmd + C to exit ============") 
due.wait()

due.close()
