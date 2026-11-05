""" Program to scan IPs and detect what IP ID they use """
from scapy.all import *

def Test():
    pkt = IP(dst="statlocker.gg")/TCP(dport=[53,80,443], flags="S")
    ans, unans = sr(pkt, timeout=3)

    for s,r in ans:
        if s[TCP].dport == r[TCP].sport:
            print("%d is unfiltered" % s[TCP].dport)

    for s in unans:
        print("%d is filtered" % s[TCP].dport)

if __name__ == "__main__":
    Test()
