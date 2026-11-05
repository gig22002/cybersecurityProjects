""" Program to scan IPs and detect what IP ID they use """
import sys
import concurrent.futures
from scapy.all import *

def ICMPScan(target, count=2, debug=False):
    """ Method to fingerprint IP ID based on an ICMP ping """
    #craft packet
    pkt = IP(dst=target)/ICMP()
    
    try:
        #create sniffer
        t = AsyncSniffer(filter=f"src host {target}")
        t.start()

        #send ping
        send(pkt, count=count, verbose=False)

        #wait and stop sniffer
        time.sleep(.2*count)
        pkts = t.stop()

        #analyze ids
        inc = True #incremental? diff b/w ids is never more than 10
        const = False #constant? diff b/w ids is 0
        rand = False #random? diff b/w ids is greater than 20000
        randPos = False #random positive increments? diff b/w ids is <20000, >1000
        for i in range(len(pkts)-1):
            if debug: print(pkts[i].id)
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
            elif (pkts[i+1].id - pkts[i].id > 1000):
                inc = False
                randPos = True

        #print out results
        print(f"{target} IP ID", end="")
        if const:
            print(f" is constant {pkts[0].id}")
        elif rand:
            print(" is random")
        elif randPos:
            print(f" is random positive increments")
        elif inc:
            print(f" is incrementing")
        else:
            print(f" sequence is indeterminate")
    except:
        print(f"Target {target} failed")

if __name__ == "__main__":
    #get list from txt file
    if (len(sys.argv) >= 2):
        path = sys.argv[1]
    else: sys.exit("ERROR: Requires text file of addresses to enumerate.")

    #multithreaded enumeration from txt file
    with open(path, "r") as f:
        processes = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as e:
            for l in f:
                processes.append(e.submit(ICMPScan, l.strip(), 5))
