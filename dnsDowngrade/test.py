""" Program to familiarize with creating DNS requests in python """
import dns.resolver

res = dns.resolver.resolve("uconn.edu", "A")

for val in res:
    print("A Record: ", val.to_text())
