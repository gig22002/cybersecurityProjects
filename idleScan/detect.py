""" Program to attempt to detect globally-incrementing IP-ID hosts """
import sys
from scapy.all import *

def SendSynAck(host, prt=80):
    """ Send and receive a syn/ack pkt (requires root) """
    pkt = IP(dst=host)/TCP(dport=prt, flags="SA")
    
    t = AsyncSniffer(filter=f"src host {host}")
    t.start()

    send(pkt, count=3, verbose=True)

    time.sleep(3)
    pkts = t.stop()

    for p in pkts:
        print(p.id)

if __name__ == "__main__":
    #get target host (placeholder)
    if (len(sys.argv) >= 2):
        host = sys.argv[1]
    else: host = "8.8.8.8"

    SendSynAck(host, 3389)
