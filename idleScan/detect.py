""" Program to attempt to detect globally-incrementing IP-ID hosts """
import sys
import json
import concurrent.futures
from scapy.all import *

def SendSynAck(host, prt=80):
    """ Send and receive a syn/ack pkt (requires root) """
    pkt = IP(dst=host)/TCP(dport=prt, flags="SA")
    
    ans, unans = sr(pkt, timeout=5)

    ans.summary()

if __name__ == "__main__":
    #get target file
    if (len(sys.argv) >= 2):
        path = sys.argv[1]
    else: sys.exit("Error: requires json file path")

    hosts = []
    with open(path, "r") as f:
        for l in f:
            hosts.append(json.loads(l))

    for item in hosts:
        ip = hosts[0]["http"]["host"]
        SendSynAck(ip, 80)
