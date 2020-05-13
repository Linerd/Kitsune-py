from scapy.all import *
from sdnator_due import *
import binascii

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap('mirai.pcap')

# Set up DUE
capabilities = [{'dataKey': 'sonata::runtime.packet', 'frequency': {'min': 0, 'max': 100}}]
# set drivers
due.set_pubsub({'driver': 'redis', 'host': 'localhost', 'port': 6379})
due.set_db({'driver': 'mongo', 'host': 'localhost', 'port': 27017})
# init due
due.init("mock_producer", PRODUCER | COORDINATOR, capabilities=capabilities)

curr_count = 0
for pkt in packets:
    # We're only interested packets with a DNS Round Robin layer
    print(pkt)

    curr_count += 1
    if curr_count % 1000 == 0: print(curr_count)
    if curr_count >= 50000 + 5000:
        # wrpcap('test.pcap', pkt, append=True)  #appends packet to output file
        due.write('sonata::runtime.packet', binascii.hexlify(bytes(pkt)))