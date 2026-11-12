""" Program using dig to detect DNSSEC use of resolvers """
import sys
import re
import subprocess

def Dig(resolver):
    out = subprocess.check_output(["dig", "A", "cloudflare.com", "+dnssec", f"@{resolver}"]).decode("utf-8")
    x = re.search("\\bflags:\\s(.*);", out).group()

    print(x)

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        res = sys.argv[1]
    else: res = "1.1.1.1"

    Dig(res)
