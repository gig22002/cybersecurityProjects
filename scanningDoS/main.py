""" Program to scan IPs and detect what IP ID they use """
import sys
from scapy.all import *

def ICMPScan(target):
    """ Method to fingerprint IP ID based on an ICMP ping """
    #craft packet
    pkt = IP(dst=target)/ICMP()

    #create sniffer
    t = AsyncSniffer(filter=f"src host {target}")
    t.start()

    #send ping
    send(pkt, count=2)

    #wait and stop sniffer
    time.sleep(.4)
    pkts = t.stop()

    #review ans
    for p in pkts:
        print(p.id)

if __name__ == "__main__":
    #get target from user input
    target = "google.com"
    if (len(sys.argv) >= 2):
        target = sys.argv[1]

    ICMPScan(target)
