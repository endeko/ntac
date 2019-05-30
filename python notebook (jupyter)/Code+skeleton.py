#!/usr/bin/env python
# coding: utf-8

# # Analyze Network Packet with Python
# > created by __Bin Xiang__ (bin.xiang@polimi.it)

# ## 1. Introduction
# ### Network packet - PCAP
# 
# > PCAP (packet capture) is a type of file containing packet data of a network.
# 
# > _Check this link:_ [PCAP Next Generation Dump File Format - PCAP-DumpFileFormat2](https://www.tcpdump.org/pcap/pcap.html)
# 
# ### Analyzing tool
# - [__Scapy__](https://scapy.net/)
# > is a powerful interactive packet manipulation program. It is able to forge or decode packets of a wide number of protocols, send them on the wire, capture them, match requests and replies, and much more. Scapy can easily handle most classical tasks like scanning, tracerouting, probing, unit tests, attacks or network discovery. It can replace hping, arpspoof, arp-sk, arping, p0f and even some parts of Nmap, tcpdump, and tshark).
# - [__Wireshark__](https://www.wireshark.org/docs/wsug_html_chunked/)
# > is the world’s foremost and widely-used network protocol analyzer. It lets you see what’s happening on your network at a microscopic level and is the de facto (and often de jure) standard across many commercial and non-profit enterprises, government agencies, and educational institutions. Wireshark development thrives thanks to the volunteer contributions of networking experts around the globe and is the continuation of a project started by Gerald Combs in 1998.

# ## 2. Obtain network packets
# 
# There are many ways to obtain packets. Here are several nice options:
# 
# - [__Wireshark__](https://www.wireshark.org/)
# - [__Tcpdump__](https://www.tcpdump.org/)
# - [__Scapy__](https://scapy.net/)
# 
# where __wireshark__ has GUI support. In the following, since we adopt __Scapy__ to parse pcap file, we also use it to capture network packets.
# 
# ### Capture packets
# > - To sniff packets, you need __<font color=red>root privileges</font>__, otherwise, you will get the "_Operation not permitted_" errors.
# > - To skip this problem, you can uncomment the following commands and run them in a __<font color=blue>scapy's interactive shell</font>__ with root privileges.

from scapy.all import * # Packet manipulation

#pkts = sniff(count=10)       # sniff 10 packets
#if pkts:                     # if pkts exist
#    wrpcap("temp.pcap",pkts) # save captured packets to a pcap file

# ### Read packets

#pkts = rdpcap("temp.pcap") # read and parse packets into memory
pkts = sniff(offline="temp.pcap", count=10) # sniff in a offline way from a pcap file 

# > Notice that, this can be very useful when you try to load a large size pcap file.

# ### Filter packets
# 
# > sniff() uses __Berkeley Packet Filter (BPF)__ syntax (the same one as tcpdump).
# 
# > [Check this link for more details about the syntax.](https://www.wireshark.org/docs/man-pages/pcap-filter.html)


# > __prn__: function to apply to each packet. If something is returned, it is displayed.
pkts_filtered = sniff(offline="temp.pcap", filter="tcp", prn=lambda x:x.summary()) # filter all TCP packets


print(pkts) # print a overview of pkts
print(pkts_filtered)

# ### Show packets details

print(pkts[0].summary()) # summary of the first packet

pkts[0].payload.show() # show the payload details of the first packet


# ## 3. Transform pcap to DataFrame
# 
# ### Retrieve layers in a single packet

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP

print(pkts[IP]) # a overview of all IP packets

# Store the pre-defined fields name in IP, TCP layers
f_ip = [field.name for field in IP().fields_desc]
f_tcp = [field.name for field in TCP().fields_desc]
print(f_ip)  # field name of IP Layer
print(f_tcp) # field name of TCP Layer

f_all = f_ip + ['time'] + f_tcp + ['payload']

# Data structures and data analysis
import pandas as pd

# Blank DataFrame
df = pd.DataFrame(columns=f_all)
for packet in pkts[IP]:
     # store data for each row of DataFrame
    field_values = []
    
    # Read values of IP fields
    for field in f_ip:
        if field == 'options':
            # we only store the number of options defined in IP Header
            field_values.append(len(packet[IP].fields[field]))
        else:
            field_values.append(packet[IP].fields[field])
    
    # Read values of Time
    field_values.append(packet.time)
    
    # Read values of TCP fields
    layer_type = type(packet[IP].payload)
    for field in f_tcp:
        try:
            if field == 'options':
                field_values.append(len(packet[layer_type].fields[field]))
            else:
                field_values.append(packet[layer_type].fields[field])
        except:
            # the field value may not exist
            field_values.append(None)
    
    # Read values of Payload
    field_values.append(len(packet[layer_type].payload))
    
    # Fill the data of one row
    df_append = pd.DataFrame([field_values], columns=f_all)
    # Append row in df
    df = pd.concat([df, df_append], axis=0)

# Reset index
df = df.reset_index()
df = df.drop(columns="index")

# shape
print("Shape: ", df.shape, '\n')
# first row
print(df.iloc[0], '\n')
# table with specified fields
df[['time', 'src', 'dst', 'sport', 'dport']]


# ## 4. Statistics

print(df['src'].describe(), '\n')  # show description of the source addresses
print(df['src'].describe()['top']) # top ip address
print(df['src'].unique())          # unique address

src_addr = df.groupby("src")['payload'].sum() # show the sum of payload for each src ip
src_addr.plot(kind='barh', figsize=(8,2))     # plot figure

