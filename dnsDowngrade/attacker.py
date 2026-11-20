""" Program to perform DNS downgrade attacks """
import sys
import dns.resolver, dns.message, dns.dnssec

def CreateResolverObj(resolverAddr):
    #initialize resolver
    resolver = dns.resolver.Resolver(configure=False)
    #add specified addr
    resolver.nameservers = [resolverAddr]

    return resolver

def RRSIGDowngrade(addr, target="cloudflare.com"):
    #create resolver for addr
    r = CreateResolverObj(addr)

    #create query
    zone = dns.name.from_text(target) #target origin
    qname = dns.name.from_text("", origin=zone)
    q = dns.message.make_query(qname, "A")
    q.flags |= dns.flags.AD #dnssec
    #submit query
    query = dns.query.udp(q, where=addr, timeout=2)

    print(query)

if __name__ == "__main__":
    """ Testing functions """
    if (len(sys.argv) >= 2):
        serv = sys.argv[1]
    else: serv = "1.1.1.1"
    if (len(sys.argv) >= 3):
        target = sys.argv[2]
    else: target = "cloudflare.com"
    RRSIGDowngrade(serv, target)
