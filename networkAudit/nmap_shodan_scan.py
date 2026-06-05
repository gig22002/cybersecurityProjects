#!/bin/python3

import sys, os
import ipaddress
from dotenv import load_dotenv
from shodan import Shodan
import requests
import xml.etree.ElementTree as et

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

    def info(self):
        '''
        Returns dictionary of held attributes

        Format:
        {
            str(ip):
            [[PortObj, PortObj, ...],
            str(hostname)]
        }
        '''
        infoDict = {
            self.ip: [self.ports, self.hostname]
        }

        return infoDict

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

def XMLParse(path):
    '''
    Parses nmap scan xml based on the path provided by args.

    Assumes at least
    nmap --open: i.e. only open ports are stored 

    parameters:
        - name: path
          type: string
          example: /path/to/scan.xml
          description: The file path to the desired .xml nmap scan
    '''
    #hostdict = 

    try:
        #create xml tree object
        tree = et.parse(path)
        root = tree.getroot()

        #iterate through each scanned host
        ips = []
        for host in root.findall('host'):
            #parse ip addr
            ip = host.find('address').get('addr')

            #parse hostname
            hostname = host.find('hostnames').find('hostname').get('name')

            #parse port info
            portList = []
            ports = host.find('ports')
            for port in ports.findall('port'):
                portid = port.get('portid')
                protocol = port.get('protocol')
                serviceField = port.find('service')
                if serviceField is not None:
                    service = serviceField.get('name')
                
                #create port object and append to array
                _PortObj = PortObj(portid, protocol, service)
                portList.append(_PortObj)

            #create ip object and append to array
            _IPObj = IPObj(ip, portList, hostname)
            ips.append(_IPObj)

        return ips

    except Exception as x:
        sys.exit("Encountered exception in nmap parse " + str(x))

def shodanScan(CIDR):
    '''
    Use Shodan.io API to find externally exposed IPs

    parameters:
        - name: CIDR
          type: string 
          example: 137.99.0.0/16
          description: IP addr in CIDR notation where subnet is 0
    '''
    #load and use Shodan api key from .env
    load_dotenv()
    key = os.getenv("SHODAN_KEY")
    api = Shodan(key)

    #parse IPs from CIDR input
    ips = [str(ip) for ip in ipaddress.IPv4Network(CIDR)]

    try:
        #get results from search

    except Exception as x:
        sys.exit("Encountered exception in Shodan search " + str(x))

if __name__ == "__main__":
    if (len(sys.argv) < 3 or sys.argv[1][-3:] != "xml"): #require nmap scan in xml format
        sys.exit("Usage: python3 nmap_shodan_scan.py path/to/nmapscan.xml ip.in.CIDR.0/notation")

    nmapResults = XMLParse(str(sys.argv[1]))
    shodanScan("137.99.146.0/24")
