""" Program using dig to detect DNSSEC use of resolvers """
import re
import sys, csv
import argparse
import subprocess
import concurrent.futures

def Dig(resolver):
    #dig with +dnssec flag on known dnssec domain (cloudflare) w/ specified resolver
    try:
        out = subprocess.check_output(["dig", "A", "cloudflare.com", "+dnssec", f"@{resolver}"]).decode("utf-8")
    except:
        #failed to dig
        return resolver, False
    #grab flags and check if "ad" flag is present
    flags = re.search("\\bflags:\\s(.*);", out).group()
    ad = "ad" in str(flags)

    #format result
    if (ad):
        print(f"Resolver {resolver} supports DNSSEC")

    return resolver, ad

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
    resolvers = dict() #initialize dict
    #multithread from file
    processes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as e:
        with open(inp, "r") as f:
            #submit thread for each ip in txt
            for ip in f:
                processes.append(e.submit(Dig, ip.strip()))

        #collect results
        for thread in concurrent.futures.as_completed(processes):
            try:
                res, ans = thread.result()
                resolvers[res] = ans
            except Exception as ex:
                print(f"Encountered exception {ex}")

    with open("out.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerows(resolvers.items())
