#LT Rouben Azad
#Lab 4 CS4558 
#This is a programs that extracts various data from a pcap file
##########################################################################################################
##########################################################################################################
import time
import dpkt
import socket
import random
import matplotlib.mlab as mlab
import matplotlib.pyplot as plt
##########################################################################################################
##########################################################################################################
fd = open("peering.pcap", "rb")
pcap = dpkt.pcap.Reader(fd)
start_time = time.time()
#Initializers
IPV4 = 0
num_pkts = 0
bad_pkts = 0
prt_2323 = 0
data_length = 0
flow_count = 0
ip_len = 0
#Probability L/NumPackets
Prob = 0.00025
tuple_dict = {}


FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80
##########################################################################################################
##########################################################################################################
#Main for loop to extract data
for ts, data in pcap:
	#--------------------------------------
    try:
        num_pkts+=1 #total number of packets
        ip = dpkt.ip.IP(data)
        rand = random.random()
        if rand <= Prob:
            flow_count +=1
            tcp = ip.data
            #print(len(data), len(ip.data), ip.len, len(ip))
            packet = (socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ip.p, tcp.sport, tcp.dport)
            if packet in tuple_dict.keys():
                ip_len += ip.len
                tuple_dict[packet].add(num_pkts, ip_len)
                print('same')
            else:
                tuple_dict[packet] = (num_pkts, ip.len)
    except:
        bad_pkts+=1

    if num_pkts >= 30000:
       break

print(tuple_dict)
# x = []
# for key, values in tuple_dict.items():
#     for i in values:
        
x = sorted(tuple_dict.items(), key =lambda kv:(kv[1], kv[0])) 
print(x)