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

    #analyze ids
    inc = True #incremental? diff b/w ids is never more than 10
    const = False #constant? diff b/w ids is 0
    rand = False #random? diff b/w ids is greater than 20000
    for i in range(len(pkts)-1):
        if (pkts[i+1].id - pkts[i].id > 10):
            inc = False
        if (pkts[i+1].id == pkts[i].id):
            inc = False
            const = True
            break
        if (pkts[i+1].id - pkts[i].id > 20000):
            inc = False
            rand = True
            break

    if const:
        print("IP ID is constant",pkts[0].id)
    elif rand:
        print("IP ID is random")
    elif inc:
        print("Incrementing IP ID")
    else:
        print("IP ID sequence is indeterminate")

if __name__ == "__main__":
    #get target from user input
    target = "google.com"
    if (len(sys.argv) >= 2):
        target = sys.argv[1]

    ICMPScan(target)
