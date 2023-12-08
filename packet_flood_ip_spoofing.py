#!/usr/bin/env python
"""
Written by Sebastien Marleau and Prianna Rahman
for Carleton University's SYSC4701 "Communications System Lab" course
"""

from time import sleep
from scapy.all import IP, ICMP, sendp, RandIP, Ether, conf
import sys

src_ip = sys.argv[1]
dst_ip = sys.argv[2]

if src_ip == "spoof":
    src_ip = RandIP()

socket = conf.L2socket()
packet = (
    Ether(src="ff:ff:ff:ff:ff:ff", dst="ff:ff:ff:ff:ff:ff") #Ethernet doesn't matter with this topology
    / IP(src=src_ip, dst=dst_ip)
    / ICMP()
)
size_bits = len(bytes(packet)) * 8
target_mbps = 0.1
every_x_seconds = size_bits / (target_mbps * 1e6)
print(size_bits, target_mbps, every_x_seconds)

while True:
    sendp(packet, socket=socket, verbose=0)
    sleep(every_x_seconds)
