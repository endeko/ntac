from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP



#udp_pkts = sniff(offline="/home/davide/Documents/ntac/datasets/network_traffic.pcap", filter="udp", prn=lambda x:x.summary(), count = 1000)
#tcp_pkts = sniff(offline="/home/davide/Documents/ntac/datasets/network_traffic.pcap", filter="tcp", prn=lambda x:x.summary(), count = 1000)
#icmp_pkts = sniff(offline="/home/davide/Documents/ntac/datasets/network_traffic.pcap", filter="icmp", prn=lambda x:x.summary(), count = 1000)
#other_pkts = sniff(offline="/home/davide/Documents/ntac/datasets/network_traffic.pcap", filter=" ", prn=lambda x:x.summary())

pkts = sniff(offiline="/home/davide/Documents/ntac/datasets/network_traffic.pcap", count = 1000)
std_ports = ['1','2','3','7','8','9','13','17','19','20','21','22','23','25','53','67','68','69','70','79','80','88','104','110','113','119','123','137','138','139','143','161','162','389','411','443','445','445','465','502','514','554','563','587','591','631','636','666','993','995', '1002', '1023']

#accessing the port field of each packet and comparing it with the port numbers in std_ports
#for each match for an x port, a counter is going to increase > organize it in a dictionary

#print('a')
