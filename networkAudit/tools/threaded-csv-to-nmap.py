#!/bin/python3

'''
Take a 3-column csv file and start nmap scans from it

Format:
Col 1   Col 2   Col 3
CIDR    Name    bool if scanned
'''

import sys, os
import subprocess
import numpy as np
import pandas as pd
import concurrent.futures
from threading import current_thread
import argparse

def ScanHosts(index, ip, fname, fastFlag=0):
    '''
    Helper function for multithreaded nmap scanning

    parameters:
        - name: index
          type: integer
          example: 1
          description: The index of the numpy array

        - name: ip
          type: string
          example: 137.99.0.0/24
          description: The IP in CIDR format to scan

        - name: fname
          type: string
          example: 001-FWScan-%T-%D.xml
          description: The file name to output to

        - name: fast
          type: integer
          example: 0, 1, 2, 3
          description: Integer flag on what level of speed to use for nmap (at the cost of accuracy)
    '''
    #get thread number
    workerid = int(current_thread().name.replace("ThreadPoolExecutor-0_", ""))
    workerName = str(workerid+1)

    #populate flags
    fastFlag = "-sT" #default is default scan type
    ping = "-Pn" #default is skip host discovery
    if fast >= 2:
        fastFlag = "-F"
    if fast >= 3:
        ping = "--reason"

    #run nmap in shell
    print(f"=== Thread {workerName} scanning {(index+1):03}: {ip} ===")
    if fast == 0:
        process = subprocess.run(["nmap", fastFlag, "-T4", "-sV", ping, "--open", "-oX", fname, ip])
    else:
        #no stdout if fast
        process = subprocess.run(["nmap", fastFlag, "-T4", "-sV", ping, "--open", "-oX", fname, ip], stdout = subprocess.DEVNULL)

    #return index of scan and if it was successful
    if process.returncode == 0:
        #successfully scanned
        print(f"[!] Thread {workerName} scan of index {index+1} on {ip} completed successfully")
        return index, True
    else:
        print(f"[!] Thread {workerName} failed to scan index {index+1} on {ip}")
        return index, False

def ExecuteNmap(arr, path, fast=0):
    '''
    Function to execute nmap on each entry of the inputted csv

    parameters:
        - name: arr
          type: numpy array
          description: The read csv file converted to a 2d array
            Col 1: IP to scan (str)
            Col 2: Name for file (str)
            Col 3: Already scanned or not? (bool)

        - name: path
          type: string
          example: /path/to/csv
          description: The path of the csv passed in by args

        - name: fast
          type: integer
          example: 0, 1, 2
          description: The speed at which nmap will scan, at the cost of accuracy. Each level includes the last.
            0: default settings
            1: skips subnets of size 256 or greater
            2: only scans top 100 ports
            3: uses ping discovery
    '''
    #backup csv
    dfbak = pd.DataFrame(arr, columns=None)

    #create and collect threads for scans
    processes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e:
        #loop through each ip in first col
        for i in range(len(arr[:, 0])):
            #check if scanned
            if str(arr[:, 2][i]).lower() == "true" or str(arr[:, 2][i]) == "1":
                isScanned = True
            else: isScanned = False

            #skip if fast scan
            skip = fast >= 1 and (int(arr[:, 0][i][-2:]) <= 24)
            if isScanned or skip: continue

            #get values
            ip = str(arr[:, 0][i])
            name = str(arr[:, 1][i])

            #construct output filename
            #   format: count-col2name-timestamp.xml
            fname = f"{(i+1):03}-{name.replace("/","")}-%T-%D.xml"

            #run worker
            processes.append(e.submit(ScanHosts, i, ip, fname, fast))

        #collect results
        for thread in concurrent.futures.as_completed(processes):
            #update numpy array
            try:
                #get output
                _index = thread.result()[0]
                _scanned = thread.result()[1]

                #set array
                arr[:, 2][_index] = _scanned
            except Exception as x:
                print(f"Encountered exception cleaning up thread for scan: {x}")

            #write to csv
            df = pd.DataFrame(arr, columns=None)
            try:
                df.to_csv(path)
            except:
                print(f"Failed to write to csv at {i+1}: {ip}")
                dfbak.to_csv(path)
                sys.exit("Aborting...")

def CreateArgs():
    ''' Helper function that creates an argparser object '''
    #create parser object
    parser = argparse.ArgumentParser(description = "A tool to scan a list of subnets from a csv file.")

    #input file
    parser.add_argument("input", help="Input csv to scan from.")

    #fast argument
    parser.add_argument("-F", "--fast", action="count", help="Increase fastness level.")

    #quiet nmap output
    parser.add_argument("-q", "--quiet", action="store_true", help="Disables Nmap stdout.")

    #num threads
    parser.add_argument("--max-workers", action="store", default=4, help="Number of worker threads. Default=4")

    return parser

if __name__ == "__main__":
    #parse args
    parser = CreateArgs()
    args = parser.parse_args()
    print(args.input)
    print(args.fast)

    #require path arg
    if len(sys.argv) < 2:
        sys.exit("Usage: python3 csv-to-nmap.py path/to/iplist.csv")
    path = sys.argv[1]
    
    fast = 0
    if len(sys.argv) >= 3:
        #fast lvl 1
        if str(sys.argv[2]) == "-F":
            fast = 1
        #fast lvl 2
        elif str(sys.argv[2]) == "-FF":
            fast = 2
        #fast lvl 3
        elif str(sys.argv[2]) == "-FFF":
            fast = 3

    #convert csv -> pandas dataframe -> numpy array
    try:
        data = pd.read_csv(path, header=None) #header=None needed to not skip first row
        arr = data.to_numpy()
        
        #check if there is header
        if str(arr[0][0]) == "nan":
            arr = np.delete(arr, (0), axis=1) #drop index column
            if "/" not in str(arr[0][0]): 
                arr = np.delete(arr, (0), axis=0) #drop header row

    except Exception as x:
        sys.exit(f"Failed to load file {path} with exception {x}")

    ExecuteNmap(arr, path, fast)
