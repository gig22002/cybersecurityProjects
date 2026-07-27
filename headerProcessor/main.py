# tool to process email headers

import os, sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Requires file path")

    headersDict = {
            "To:": "",
            "From:": "",
            "ARC-Authentication-Results:": "",
            "Received-SPF:": "",
            "DKIM-Signature:": ""
        }
    i=0
    with open (sys.argv[1], "r") as f:
        #iterate through lines
        for line in f:
            #iterate through desired headers
            for x in headersDict.keys():
                #store header info
                if line.startswith(x):
                    headersDict[x] = line.strip()
                    i+=1
            if i==len(headersDict.keys()):
                break

