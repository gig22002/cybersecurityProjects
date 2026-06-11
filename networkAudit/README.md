# Nmap and Shodan.io Auditing Tool

## Overview

This is a command line tool intended to enumerate a list of subnets from a csv file ia Nmap, then transform the xml output of the Nmap scan in conjunction with paired data from Shodan.io to discover internal and external port exposures on a network.

## Usage

Create a `.env` file in the `tools/` directory containing your Shodan API key in the format of `SHODAN_KEY=yourKeyHere`.

Install the required libraries with `pip install -r requirements.txt`.

Run `python3 orchestrator.py path/to/toscan.csv`.

This uses multiple threads (default: 4) to scan the subnets tabled in the csv file, outputting the xmls to `rawScans/`. Then, these scans are passed into `tools/threaded_nmap_shodan_scan.py` where these IPs and ports are coalesced with Shodan results and outputted to the current directory as csv files.

The csv should be in the following format:  
Three columns with no header row.  
Column 1: IPs in CIDR format  
Column 2: name of the subnet for file output  
Column 3: all zeros (used to record if a subnet has already been scanned)

Optionally, the `-F` or `--fast` option may be passed at the end of the command: `python3 csv-to-nmap.py path/to/csv -F`.   
Increasing the amount of Fs increases the speed:   
`-F`: skips subnets of size 256 or larger   
`-FF`: also uses nmap `-F` flag (i.e. only scans top 100 ports)   
`-FFF`: also uses ping host discovery (i.e. does NOT use `-Pn`)   

The `-q` or `--quiet` option may be passed to disable Nmap output to the console.

The `-sS` or `--stealthy` option may be passed to use "stealthy" Nmap options.

The `--max_workers INT` option may be passed to specify the max number of worker threads, with the default being 4.

## Nmap

For my scans, I used the following command:

`nmap -T4 -Pn -sV --open -oX output.xml ip.in.CIDR.0/format`

`-T4` to speed up the scan, `-Pn` to treat all hosts as online (circumvents blocked discovery probes), `-sV` enables version/service detection, `--open` to only output open ports (required for this program), `-oX output.xml` to output to xml (required for this program), and finally the IP range to scan.

###### Created by Gio Girasoli for UConn ITS 06/05/26   
###### No AI was used in the making of this program.
