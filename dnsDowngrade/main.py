""" Gio Girasoli CSE4402 """
""" DNSSEC testing tool  """

import sys
import dns.resolver
import dns.message
import dns.dnssec

def CheckFlags(domain):
    #make basic query
    resp = dns.message.make_query(domain, "A")
    
    #check AD flag
    ad = resp.flags & dns.flags.AD

    print(resp.rcode())

def CheckDNSSEC(domain):
    #initialize query
    resolver = dns.resolver.Resolver()
    name = dns.name.from_text(domain, origin=dns.name.root)

    #try dnskey
    try:
        ans = resolver.resolve(name, "DNSKEY", tcp=True)
    except Exception as x:
        print("Failed with exception",x)
        return False
    
    #resolution succeed:
    print(f"Found DNSKEY\n{ans[0]}")
    
    return True

def IterateResolvers():
    #fixed resolver path
    path = "./resolvers.txt"
    with open(path, "r") as f:
        for x in f:
            CheckDNSSEC(x.strip())

if __name__ == "__main__":
    #get domain from input, default: uconn.edu
    if len(sys.argv) >= 2:
        domain = sys.argv[1]
    else: domain = "cookiebot.com."

    CheckFlags(domain)
    CheckDNSSEC(domain)
    #IterateResolvers()
