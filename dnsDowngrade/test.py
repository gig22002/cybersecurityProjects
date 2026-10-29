""" Program to familiarize with creating DNS requests in python """
import dns.resolver
import sys

if len(sys.argv) >= 2:
    domain = str(sys.argv[1])
else: domain = "uconn.edu"

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
