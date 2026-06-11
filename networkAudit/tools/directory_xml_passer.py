#!/bin/python3

'''
Scan the current (or specified) directory to pass to threaded_nmap_shodan_scan.py
'''

import sys, os
import subprocess
import concurrent.futures

def ExecuteScan(fname):
    '''
    Helper function for multithreaded execution

    parameters:
        - name: fname
          type: string
          example: 001-FWNmap.xml
          description: The file name to pass into threaded_nmap_shodan_scan.py
    '''
    #run process
    process = subprocess.run(["python3", "threaded_nmap_shodan_scan.py", "-f", fname])

if __name__ == "__main__":
    #set path if specified
    path = "."
    if (len(sys.argv) >= 2):
        path = str(sys.argv[1])
    
    #create threads
    processes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e:
        #traverse directory
        for f in os.scandir(path):
            if not f.is_file(): continue #skip if not file
            #obtain file name
            fname = os.path.basename(f.name)
            fname = f"{path}/{fname}"
        
            if fname[-3:] != "xml": continue #skip if not xml
            processes.append(e.submit(ExecuteScan, fname))
