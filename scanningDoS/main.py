""" Program to scan IPs and detect what IP ID they use """
from scapy.all import *

def TestSR():
    pkt = IP(dst="statlocker.gg")/TCP(dport=[53,80,443], flags="S")
    ans, unans = sr(pkt, timeout=3)

    for s,r in ans:
        if s[TCP].dport == r[TCP].sport:
            print("%d is unfiltered" % s[TCP].dport)

    for s in unans:
        print("%d is filtered" % s[TCP].dport)

def Test(target="statlocker.gg"):
    pkt = IP(dst=target)/TCP(dport=[53,80,443], flags="S")/Raw(RandString(size=42))

    t = AsyncSniffer(filter=f"host {target}")
    t.start()

    frags = fragment(pkt, fragsize=8)
    for f in frags:
        send(f)
    time.sleep(2)
    
    pkts = t.stop()
    for p in pkts:
        print(p.summary())

if __name__ == "__main__":
    Test()
