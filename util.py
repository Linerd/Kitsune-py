from scapy.all import *
import binascii
import pickle
import random


# Convert the first 55000 packets as training dataset from mirai.pcap into a pickle file
def process_training_dataset():
    pkts = rdpcap('mirai.pcap')
    count = 0
    output = []
    for pkt in pkts:
        if count < 55000:
            output.append(binascii.hexlify(bytes(pkt)))
        else:
            break
        count += 1
    if len(output) != 55000:
        print(len(output))
        exit()
    with open('training_dataset.p', 'wb') as f:
        pickle.dump(output, f)

# Convert new.pcap into a pickle file
def process_testing_dataset():
    dst_mac = "08:00:00:00:02:22"
    attack_src_mac = "08:00:00:00:01:11"
    new_packets = []

    # Read in normal traffic
    packets = rdpcap('normal.pcap')
    for pkt in packets:
        new_pkt = pkt
        new_pkt.dst = dst_mac
        new_packets.append(binascii.hexlify(bytes(new_pkt)))

    # Read in attack traffic
    packets = rdpcap('attack.pcap')
    for pkt in packets:
        new_pkt = pkt
        new_pkt.dst = dst_mac
        new_pkt.src = attack_src_mac
        new_packets.append(binascii.hexlify(bytes(new_pkt)))

    random.shuffle(new_packets)

    with open('testing_dataset.p', 'wb') as f:
        pickle.dump(new_packets, f)
    
if __name__ == "__main__":
    # process_testing_dataset()
    # process_training_dataset()