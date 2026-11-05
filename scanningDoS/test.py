""" Program to scan IPs and detect what IP ID they use """
import sys
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

def TestFrag(target="statlocker.gg"):
    """ Test sending fragmented packets """
    #craft packet
    pkt = IP(dst=target)/TCP(dport=[80,443], flags="FPU")#/Raw(RandString(size=42))
    #pkt = IP(dst=target)/ICMP()/Raw(RandString(size=67))

    #create async sniffer
    t = AsyncSniffer(filter=f"src host {target}")
    t.start()

    #fragment and send packet
    frags = fragment(pkt, fragsize=8)
    for f in frags:
        send(f)
    time.sleep(3) #wait for responses
    
    #stop sniffing and read packets
    pkts = t.stop()
    for p in pkts:
        print(p.show())

def TestIPIDTCP(target="statlocker.gg"):
    #craft packet
    pkt = IP(dst=target)/TCP(dport=[22,80,443], flags="S")

    #create async sniffer
    t = AsyncSniffer(filter=f"src host {target}")
    t.start()

    #send packets x times
    send(pkt, count=3)
    time.sleep(1)

    pkts = t.stop()
    for p in pkts:
        print(p.id)

def TestClosedTCP(target="statlocker.gg"):
    pkt = IP(dst=target)/TCP(dport=[2], flags="S")

    a,unans = sr(pkt, timeout=3)

def TestIPIDICMP(target="statlocker.gg"):
    """ Test probing IP ID """
    #craft packet
    pkt = IP(dst=target)/ICMP()

    #create async sniffer
    t = AsyncSniffer(filter=f"src host {target}")
    t.start()

    #send packets x times
    send(pkt, count=3)
    time.sleep(0.67) #wait for responses

    #stop sniffing and read pkts
    pkts = t.stop()
    for p in pkts:
        print(p.id)

if __name__ == "__main__":
    if(len(sys.argv) >= 2):
        target = str(sys.argv[1])
    else: target="statlocker.gg"
    #TestFrag(target)
    #TestIPIDTCP(target)
    #TestIPIDICMP(target)
    TestClosedTCP(target)
