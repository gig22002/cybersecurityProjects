#!/bin/python3

import getopt, sys, os
from dotenv import load_dotenv
from shodan import Shodan
import xml.etree.ElementTree as et
import numpy as np
import pandas as pd

class IPObj:
    '''
    Class to store IP scan information
    
    ip:
        type: integer
        example: 137.99.1.1
        description: The IP address of the host
    ports:
        type: array of PortObjs
        example: [(80, tcp, http), (443, tcp, https)]
        description: An array of ports the host has exposed wrapped by the PortObj class
    hostname:
        type: string
        example: its.uconn.edu
        description: The relative domain name of the host
    '''
    def __init__(self, ip, ports, hostname=None):
        self.ip = ip
        self.ports = ports
        self.hostname = hostname

    def __str__(self):
        ''' Return string of all attributes '''
        outStr = f"{self.ip}, ["
        for port in self.ports:
            outStr += f"{port}; "
        outStr += f"], {self.hostname}"

        return outStr

    def arr(self):
        '''
        Output as numpy-compatible array
        
        Format:
        [ip, hostname, portid, protocol, service]
        for each port
        '''
        outer = []

        #separate ip entry for each port
        for port in self.ports:
            inner = [self.ip]
            inner.append(self.hostname)
            inner.append(port.portid)
            inner.append(port.service)

            outer.append(inner)

        return outer

class PortObj:
    '''
    Class to store port information

    portid:
        type: integer
        example: 80, 22
        description: The port number
    protocol:
        type: string
        example: tcp, udp
        description: The transport-layer protocol
    service:
        type: string
        example: http, ssh
        description: The service nmap guesses the port to be
    '''

    def __init__(self, portid, protocol, service):
        self.portid = portid
        self.protocol = protocol
        self.service = service

    def __str__(self):
        ''' Return string of all attributes '''
        return f"{self.portid}, {self.protocol}, {self.service}"

    def arr(self):
        ''' Return array of all attributes '''
        return [self.portid, self.protocol, self.service]

def XMLParse(path, verbose=False):
    '''
    Parses nmap scan xml based on the path provided by args.

    Assumes at least
    nmap --open -oX: i.e. only open ports are stored

    parameters:
        - name: path
          type: string
          example: /path/to/scan.xml
          description: The file path to the desired .xml nmap scan
          
        - name: verbose
          type: bool
          example: False
          description: Option to enable verbose stdout
    '''
    try:
        #create xml tree object
        tree = et.parse(path)
        root = tree.getroot()
        
        print(f"=== Parsing {root.get("args")} ===")

        #iterate through each scanned host
        ips = [] #scanned IP objects
        ipList = [] #list of contained IPs for Shodan
        for host in root.findall("host"):
            #parse ip addr
            ip = host.find("address").get("addr")

            #parse hostname
            try:
                hostname = host.find("hostnames").find("hostname").get("name")
            except:
                hostname = ""
                if (verbose): print(f"Failed to find hostname for {ip}.")

            #parse port info
            portList = []
            ports = host.find("ports")
            for port in ports.findall("port"):
                portid = port.get("portid")
                protocol = port.get("protocol")
                serviceField = port.find("service")
                if serviceField is not None:
                    service = serviceField.get("name")
                
                #create port object and append to array
                _PortObj = PortObj(portid, protocol, service)
                portList.append(_PortObj)

            #create ip object and append to array
            _IPObj = IPObj(ip, portList, hostname)
            ips.append(_IPObj)
            ipList.append(ip)

        print("[!] Nmap results parsed.")
        return ips, ipList

    except Exception as x:
        sys.exit("Encountered fatal exception in Nmap parse: " + str(x))

def ShodanScan(ipList, verbose=False):
    '''
    Use Shodan.io API to find externally exposed IPs

    parameters:
        - name: ipList
          type: array of strings
          description: Nmap's list of IPs to enumerate via Shodan

        - name: verbose
          type: bool
          example: False
          description: Option to enable verbose stdout
    '''
    #load and use Shodan api key from .env
    load_dotenv()
    key = os.getenv("SHODAN_KEY")
    api = Shodan(key)

    #get results from search
    #note: this scans only the ips returned from the nmap search.
    #      thus, I am making the (logical) assumption the externally exposed ips
    #      are a subset of the internally exposed ips.
    ips = dict()
    for _ip in ipList:
        if(verbose): print(f"Querying {_ip}...")
        try:
            host = api.host(_ip) #search hosts by IP
            ip = host["ip_str"]
            if(verbose): print(f"IP {ip} found externally.")
            hostname = host['hostnames'][0]
            
            #get ports from host data
            ports = []
            for item in host["data"]:
                #generate port object
                _PortObj = PortObj(item["port"], None, None)
                ports.append(_PortObj)

            #generate ip object
            _IPObj = IPObj(ip, ports, hostname)
            ips[ip] = _IPObj

        except Exception as x:
            if(verbose): print("Encountered exception in Shodan search: " + str(x))

    print("[!] Shodan results parsed.")
    return ips

def Export(path, nmapResults, shodanResults):
    '''
    Coalesces and exports scan results to a .csv file using numpy.

    parameters:
        - name: path
          type: string
          example: /path/to/output.csv
          description: The file path to output results into

        - name: nmapResults
          type: array of IPObjs
          description: The IPObjs returned from parsing the nmap scan .xml

        - name: shodanResults
          type: array of IPObjs
          description: The IPObjs returned from the Shodan scan of the nmap IPs
    '''
    
    #create initial array
    #entry format:
    #   [ip, hostname, port, protocol, service, externalPort]
    array = []
    for _obj in nmapResults:
        #make two dimensional per port per IPObj
        for ip in _obj.arr():
            l = ip
            l.append("")
            #detect if port is external
            if (ip[0] in shodanResults):
                for _port in shodanResults[ip[0]].ports:
                    if (str(ip[2]) == str(_port.portid)):
                        l[-1] = ip[2]

            array.append(l)

    #convert to dataframe and export
    npObj = np.array(array)
    df = pd.DataFrame(npObj, columns=[
        "IP",
        "Hostname",
        "Internal Port",
        "Service",
        "External (Internet) Port"])
    try:
        df.to_csv(path)
        print(f"[!] Data successfully exported to {path}")
    except:
        print(f"Failed to export data to {path}")

def GetOutputHelper(path):
    '''
    Helper function to get the filename to output to

    parameters:
        - name: path
          type: string
          example: path/to/nmapscan.xml
          description: The path to the nmap scan obtained by arguments
    '''

    #split by slash
    arr = path.split('/')

    fname = arr[-1]
    fname = "out-"+fname[:-3]+"csv"

    return fname

if __name__ == "__main__":
    args = sys.argv[1:]
    options = "vf:"
    longOpts = ["verbose", "file="]
    verbose = False
    path = None

    try:
        arguments, vals = getopt.getopt(args, options, longOpts)
        for _arg, _val in arguments:
            if _arg in ("-v", "--verbose"):
                verbose = True
            elif _arg in ("-f", "--file"):
                path = _val
                outPath = GetOutputHelper(path)

    except:
        sys.exit("Usage: python3 nmap_shodan_scan.py -f path/to/nmapscan.xml")
    if path == None:
        sys.exit("Usage: python3 nmap_shodan_scan.py -f path/to/nmapscan.xml")

    nmapResults = XMLParse(str(path), verbose)

    shodanResults = ShodanScan(nmapResults[1], verbose)

    Export(outPath, nmapResults[0], shodanResults)
