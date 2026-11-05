""" Program to scan IPs and detect what IP ID they use """
from scapy.all import *

def Test():
    pkt = IP(dst="statlocker.gg")/ICMP()/"XXXXXXXXXXX"
    a = sr1(pkt)

    a.show()

if __name__ == "__main__":
    Test()
