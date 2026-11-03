""" Program to familiarize with creating DNS requests in python """
import dns.resolver
import dns.message
import dns.dnssec
import sys

def PrintRecords(domain):
    """ Print basic records """
    Ares = dns.resolver.resolve(domain, "A")
    for val in Ares:
        print("A Record: ", val.to_text())
    print("")

    NSres = dns.resolver.resolve(domain, "NS")
    for val in NSres:
        print("NS Record: ", val.to_text())
    print("")

    TXTres = dns.resolver.resolve(domain, "TXT")
    for val in TXTres:
        print("TXT Record: ", val.to_text())

def PrintDNSKEY(key):
    """ Print DNSKEY from array """
    #ZSK or KSK
    if(key[0] == 256): print("ZSK", end=" ")
    else: print("KSK", end=" ")

    #skip protocol (always 3)

    #alg
    print("using alg ", end="")
    if(key[2] == 8): print("RSA/SHA-256", end="; ")
    elif(key[2] == 13): print("ECDSA/SHA-256", end="; ")
    else: print(key[2], end="; ")

    #pk
    print("public key: ", end="")
    for x in key[3:]:
        print(x, end=" ")

def DNSSEC(domain):
    resolver = dns.resolver.Resolver()
    name = dns.name.from_text(domain, origin=dns.name.root)

    ans = resolver.resolve(name, "DNSKEY", tcp=True)
    print(ans[0])
    PrintDNSKEY(ans[0].to_text().split(" "))

if __name__ == "__main__":
    #obtain domain from args
    if len(sys.argv) >= 2:
        domain = str(sys.argv[1])
    else: domain = "uconn.edu"

    #print basic records
    #PrintRecords(domain)
    print("")

    #dnssec query
    DNSSEC(domain)
