""" Program using dig to detect DNSSEC use of resolvers """
import re
import argparse
import subprocess

def Dig(resolver):
    #dig with +dnssec flag on known dnssec domain (cloudflare) w/ specified resolver
    try:
        out = subprocess.check_output(["dig", "A", "cloudflare.com", "+dnssec", f"@{resolver}"]).decode("utf-8")
    except:
        #failed to dig
        return 0
    #grab flags and check if "ad" flag is present
    flags = re.search("\\bflags:\\s(.*);", out).group()
    ad = "ad" in str(flags)

    print(flags)
    print(ad)

def CreateArgs():
    """ Helper function to create argument parser """
    #create parser
    parser = argparse.ArgumentParser(description = "A tool for testing DNSSEC validation of resolvers.")

    #input
    parser.add_argument("input", help="A text file of resolvers or a single resolver (IP format)")

    #single target? (i.e. not text file)
    parser.add_argument("-s", "--single", action="store_true", help="If the input is a single resolver")

    return parser

if __name__ == "__main__":
    #parse arguments
    parser = CreateArgs()
    args = parser.parse_args()
    
    #get input
    inp = str(args.input)

    #if single
    if (args.single):
        Dig(inp)
        sys.exit()

    #if file
    with open(inp, "r") as f:
        for ip in f:
            Dig(ip.strip())
