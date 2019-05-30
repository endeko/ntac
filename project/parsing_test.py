from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP

pkts = sniff(offline="/home/davide/Documents/ntac/datasets/network_traffic.pcap")
print(pkts)

