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

def ExecuteNmap(arr, path, fast=False):
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
          type: bool
          example: False, True
          description: Whether or not to skip subnets of size 256 or greater.
    '''
    #backup csv
    dfbak = pd.DataFrame(arr, columns=None)

    #loop through each ip in first col
    for i in range(len(arr[:, 0])):
        #check if scanned
        if str(arr[:, 2][i]).lower() == "true" or str(arr[:, 2][i]) == "1":
            isScanned = True
        else: isScanned = False

        #skip if fast scan
        skip = fast and (int(arr[:, 0][i][-2:]) <= 24)
        if isScanned or skip: continue

        #get values
        ip = str(arr[:, 0][i])
        name = str(arr[:, 1][i])

        #construct output filename
        #   format: count-col2name-timestamp.xml
        fname = f"{(i+1):03}-{name.replace("/","")}-%T-%D.xml"
        #if fast, use -F and not -Pn
        fastFlag = "-sT" #default is default scan type
        ping = "-Pn" #default is skip host discovery
        if fast:
#            fastFlag = "-F" 
            ping = "--reason"
        
        #run nmap in shell
        print(f"=== Scanning {ip} ===")
        process = subprocess.run(["nmap", "-v", fastFlag, "-T4", "-sV", ping, "--open", "-oX", fname, ip])

        if process.returncode == 0:
            #successfully scanned
            arr[:, 2][i] = True
        else:
            print(f"Failed to scan {ip}")

        #write to csv
        df = pd.DataFrame(arr, columns=None)
        try:
            df.to_csv(path)
        except:
            print(f"Failed to write to csv at {i+1}: {ip}")
            dfbak.to_csv(path)
            sys.exit("Aborting...")

if __name__ == "__main__":
    #require path arg
    if len(sys.argv) < 2:
        sys.exit("Usage: python3 csv-to-nmap.py path/to/iplist.csv")
    path = sys.argv[1]
    
    fast = False
    if len(sys.argv) >= 3 and str(sys.argv[2]) == "-F":
        fast = True

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
