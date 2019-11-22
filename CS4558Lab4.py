#LT Rouben Azad
#Lab 4 CS4558 
#This is a programs that extracts various data from a pcap file
##########################################################################################################
##########################################################################################################
import time
import dpkt
import socket
import random
import operator
import numpy as np 
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
tcp_pkt = []
num_byt = []

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
            num_byt.append(ip.len)
            #print(len(data), len(ip.data), ip.len, len(ip))
            packet = (socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ip.p, tcp.sport, tcp.dport)
            if packet in tuple_dict.keys():
                ip_len += ip.len
                tuple_dict[packet].add(num_pkts, ip_len)
                print('same')
            else:
                tuple_dict[packet] = (num_pkts, ip.len)
            if ip.p == 6:
                tcp_pkt.append(ip.len)
    except:
        bad_pkts+=1

    if num_pkts >= 10000:
       break

##########################################################################################################
##########################################################################################################
#Number of flows
print()
print('Number of flows without probability: \n', num_pkts, '\n'
    'Number of flows with probability: \n', flow_count)
print('------------------')
#top 5 heavy hitters
top5_HH = dict(sorted(tuple_dict.items(), key =lambda x:x[1][1], reverse = True)[:5]) 
print('Top 5 Heavy hitter: \n', top5_HH)
print('------------------')
##########################################################################################################
##########################################################################################################
def min_max_avg(x, r):
    return ['Minimun', r ,'per flow:', min(x),
    'Maximum byte per flow:', max(x),
    'Average byte per flow:', (sum(x)/len(x))]

uniq_src = []
uniq_dst = []
num_pkt_PF = []
for a, b in tuple_dict.items():
    uniq_src.append(a[0])
    uniq_dst.append(a[1])
    num_pkt_PF.append(b[0])

#Unique IP sourc and IP destination
print('Number of Unique IP source:\n', 
    len(np.unique(uniq_src)),'\n'
    'Number of Unique IP destination:\n',
    len(np.unique(uniq_dst)))
print('------------------')
##########################################################################################################
##########################################################################################################
print(min_max_avg(num_byt, byte))
print('------------------')
print(min_max_avg(num_pkt_PF))

