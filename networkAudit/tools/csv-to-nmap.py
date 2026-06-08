#!/bin/python3

'''
Take a 3-column csv file and start nmap scans from it

Format:
Col 1   Col 2   Col 3
CIDR    Name    bool if scanned
'''

import sys, os
import numpy as np
import pandas as pd



if __name__ == "__main__":

    if len(sys.argv) < 2:
        sys.exit("Usage: python3 csv-to-nmap.py path/to/iplist.csv")
    path = sys.argv[1]

    try:
        data = pd.read_csv(path)
        arr = data.to_numpy()

    except Exception as x:
        sys.exit(f"Failed to load file {path} with exception {x}")
