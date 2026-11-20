""" Program to attempt to detect globally-incrementing IP-ID hosts """
import sys
import json
import concurrent.futures
from scapy.all import *

def SendSynAck(host, prt=80):
    """ Send and receive a syn/ack pkt (requires root) """
    print(f"Scanning {host}...")
    pkt = IP(dst=host)/TCP(dport=prt, flags="A")
    
    t = AsyncSniffer(filter=f"src host {host}")
    t.start()

    send(pkt, count=3, verbose=False)

    time.sleep(3)
    pkts = t.stop()

    for p in pkts:
        print(p.id)
    #ans, unans = sr(pkt, timeout=5, verbose=False)

    #ans.summary()

if __name__ == "__main__":
    #get target file
    if (len(sys.argv) >= 2):
        path = sys.argv[1]
    else: sys.exit("Error: requires json file path")

    hosts = []
    with open(path, "r") as f:
        for l in f:
            hosts.append(json.loads(l))

    processes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers = 12) as e:
        for item in hosts:
            ip = item["http"]["host"]
            processes.append(e.submit(SendSynAck, ip, (20,443)))
