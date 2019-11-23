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
#from countminsketch import CountMinSketch
##########################################################################################################
##########################################################################################################
fd = open("peering.pcap", "rb")
pcap = dpkt.pcap.Reader(fd)
start_time = time.time()
#Initializers
ip_len = 0
bad_pkts = 0
num_pkts = 0
flow_count = 0
#Probability L/NumPackets
Prob = 0.00025
tuple_dict = {}
tcp_pkt = []

#Count-min sketch
#sketch = CountMinSketch(width=1000, depth=10)
##########################################################################################################
##########################################################################################################
#Main for loop to extract data
for ts, data in pcap:
	#--------------------------------------
    try:
        num_pkts += 1
        ip = dpkt.ip.IP(data)
        rand = random.random()
        if rand <= Prob:
            flow_count +=1
            tcp = ip.data
            packet = (socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), 
                ip.p, tcp.sport, tcp.dport)
            if packet in tuple_dict.keys():
                ip_len += ip.len
                tuple_dict[packet].add(flow_count, ip_len)
            else:
                tuple_dict[packet] = (flow_count, ip.len)
            if ip.p == 6:
                tcp_pkt.append(ip.len)
    except:
        bad_pkts+=1

    if num_pkts >= 30000:
       break

##########################################################################################################
##########################################################################################################
#Number of flows
print()
print('Number of packets: \n', num_pkts, '\n'
    'Number of flows: \n', flow_count)
print('------------------')
#top 5 heavy hitters
top5_HH = dict(sorted(tuple_dict.items(), 
    key =lambda x:x[1][1], reverse = True)[:5]) 
print('Top 5 Heavy hitter: \n', top5_HH)
print('------------------')
##########################################################################################################
##########################################################################################################
uniq_src = []
uniq_dst = []
num_pkt_PF = []
num_byt_PF = []
for a, b in tuple_dict.items():
    uniq_src.append(a[0])
    uniq_dst.append(a[1])
    num_pkt_PF.append(b[0])
    num_byt_PF.append(b[1])
    print(a, type(a))
    # sketch.add(a[0:4])
    # print(sketch.check(a[0:4]))

#Unique IP sourc and IP destination
print('Number of Unique IP source:\n', 
    len(np.unique(uniq_src)),'\n'
    'Number of Unique IP destination:\n',
    len(np.unique(uniq_dst)))
print('------------------')
##########################################################################################################
##########################################################################################################
def min_max_avg(x, r):
    return ['Minimun ' + r +' per flow:', min(x),
    'Maximum '+r+ ' per flow:', max(x),
    'Average '+r+' per flow:', round(sum(x)/len(x), 2)]
    
print(min_max_avg(num_byt_PF, 'bytes'))
print('------------------')
print(min_max_avg(num_pkt_PF, 'packets'))
print('------------------')
print('Fraction of TCP traffic vs tatal byte count: \n',
    round((sum(tcp_pkt)/sum(num_byt_PF))*100, 2), 'percent')
##########################################################################################################
##########################################################################################################
#Extra credit 
print('----------------------')
print(sketch.check('a'))
##########################################################################################################
##########################################################################################################
print('----------------------')
print('This program took:')
if (time.time() - start_time) > 60:
    print(round((time.time() - start_time)/60, 3), 'minutes to run')
else:
    print(round((time.time() - start_time), 3), 'seconds to run')
