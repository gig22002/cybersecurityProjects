""" Program to scan IPs and detect what IP ID they use """
from scapy.all import *

def TestSR():
    """ Test sending and receiving Syn packet """
    #craft packet
    pkt = IP(dst="statlocker.gg")/TCP(dport=[53,80,443], flags="S")
    ans, unans = sr(pkt, timeout=3) #timeout after 3 sec

    #view results
    for s,r in ans:
        if s[TCP].dport == r[TCP].sport:
            print("%d is unfiltered" % s[TCP].dport)

    for s in unans:
        print("%d is filtered" % s[TCP].dport)

def Test(target="statlocker.gg"):
    """ Test sending fragmented packets """
    #craft packet
    pkt = IP(dst=target)/TCP(dport=[53,80,443], flags="S")/Raw(RandString(size=42))

    #create async sniffer
    t = AsyncSniffer(filter=f"host {target}")
    t.start()

    #fragment and send packet
    frags = fragment(pkt, fragsize=8)
    for f in frags:
        send(f)
    time.sleep(2) #wait for responses
    
    #stop sniffing and read packets
    pkts = t.stop()
    for p in pkts:
        print(p.flags)

if __name__ == "__main__":
    Test()
