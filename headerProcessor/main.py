# tool to process email headers

import os, sys

def ProcessDict(h):
    ''' Function to parse the header contents '''
    print(f"Email to {h['To:']} from {h['From:']} on {h['Date:']}")

    #parse arc
    arc = h["ARC-Authentication-Results:"].split(' ')
    try: dkimRes = [x for x in arc if x.startswith("dkim")][0][5:]
    except: dkimRes="ERROR"
    try: spfRes = [x for x in arc if x.startswith("spf")][0][4:]
    except: spfRes="ERROR"
    try: dmarcRes = [x for x in arc if x.startswith("dmarc")][0][6:]
    except: dmarcRes="ERROR"
    print(f"dkim:{dkimRes} spf:{spfRes} dmarc:{dmarcRes}", end=' ')
    
    #parse spf
    spf = h["Received-SPF:"].split(' ')
    try: ip = [x for x in spf if x.startswith("client-ip")][0]
    except: ip="ERROR"
    print(f"client-ip:{ip[10:-1]}", end=' ')
    
    #parse dkim
    dkim = h["DKIM-Signature:"].split(' ')

    print("\n==DMARC==")
    try: policy = [x for x in arc if x.startswith("(p=")][0][3:]
    except: policy="ERROR"
    try: subdp = [x for x in arc if x.startswith("sp=")][0][3:]
    except: subdp="ERROR"
    try: disposition = [x for x in arc if x.startswith("dis=")][0][4:-1]
    except: disposition="ERROR"
    print(f"policy:{policy} sub-domain-policy:{subdp} disposition:{disposition}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Requires file path")

    headersDict = {
            "To:": "",
            "From:": "",
            "Date:": "",
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
                    headersDict[x] = line.strip()[len(x)+1:]
                    i+=1
                    break
            #break out when done
            if i==len(headersDict.keys()):
                break

    ProcessDict(headersDict)

