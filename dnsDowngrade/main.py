""" Program using dig to detect DNSSEC use of resolvers """
import sys
import re
import subprocess

def Dig(resolver):
    #dig with +dnssec flag on known dnssec domain (cloudflare) w/ specified resolver
    out = subprocess.check_output(["dig", "A", "cloudflare.com", "+dnssec", f"@{resolver}"]).decode("utf-8")
    #grab flags and check if "ad" flag is present
    flags = re.search("\\bflags:\\s(.*);", out).group()
    ad = "ad" in str(flags)

    print(flags)
    print(ad)

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        res = sys.argv[1]
    else: res = "1.1.1.1"

    Dig(res)
