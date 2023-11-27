#!/usr/bin/env python
from scapy.all import IP, ICMP, send
import sys

if len(sys.argv) < 3:
    print("usage: python3 packet_flood_ip_spoofing.py <srcip> <dstip>")
    sys.exit()

src_ip = sys.argv[1]
dst_ip = sys.argv[2]

icmp = IP(src=src_ip, dst=dst_ip) / ICMP()
send(icmp)

