# Nmap and Shodan.io Auditing Tool

## Overview

These are several tools for performing a network/firewall audit and enumeration.

`threaded_nmap_shodan_scan.py`: Takes an Nmap xml output file and queries Shodan.io and outputs a csv detailing the ports exposed to Nmap and Shodan. A sequential (slower) version is also included.

`threaded_csv_to_nmap.py`: Takes a csv of subnets to scan and runs Nmap on those IP sequences, outputting to xml for use with the former program. A sequential (slower) version is also included.

`directory_xml_passer.py`: Traverses the current or specified directory for xml files to pass to `threaded_nmap_shodan_scan.py`.

The main program file is `../orchestrator.py`, which is essentially `threaded_csv_to_nmap.py` but also automatically passes results to `threaded_nmap_shodan_scan.py`.

Note the sequential versions are missing useful QoL features, e.g. preventing certain errors for edge cases.

## Usage

Create a `.env` file in THIS directory containing your Shodan API key in the format of `SHODAN_KEY=yourKeyHere`.

Install the required libraries with `pip install -r ../requirements.txt`.

Run `python3 threaded_nmap_shodan_scan.py -f path/to/nmapscan.xml`.

This program iterates through each IP detected by Nmap, collecting hostnames, exposed ports, and their respective services.
Then, using the IPs returned by Nmap, queries Shodan.io's API to attempt to find posts exposed externally to the internet.
This data is outputted as a .csv file with the columns of IP, Hostname, Internal Port (detected by nmap), Service, and External Port (detected by Shodan), with an entry for each individual port.

Optionally, you can include the `-v` flag before the `-f` flag for verbose output.

In the event Shodan discovers a port that Nmap did not, an alert with that IP will be printed. This is most likely due to the internet-exposed ports being outside of the top 1000 ports Nmap typically scans; to remedy this, simply rerun the scan separately with the `-p-` flag to scan all ports.

The multithreaded version is over 500% faster than the sequential version.

If you have a bunch of xml files you'd like to process automatically, run `python3 directory_xml_passer.py optional/path/to/dir`. This traverses the specified directory (default: current working dir), passing the xml files to `threaded_nmap_shodan_scan.py`.

## Nmap

For my scans, I used the following command:

`nmap -T4 -Pn -sV --open -oX output.xml ip.in.CIDR.0/format`

`-T4` to speed up the scan, `-Pn` to treat all hosts as online (circumvents blocked discovery probes), `-sV` enables version/service detection, `--open` to only output open ports (required for this program), `-oX output.xml` to output to xml (required for this program), and finally the IP range to scan.

To automatically scan IPs from a csv table, included is `tools/csv-to-nmap.py`.

Create a table with three columns and no header row. Column 1 should be IPs in CIDR format, Column 2 should be the name of the range, and Column 3 should be all zeros (used to detect if an ip has already been scanned for continuity).

Then, run `python3 threaded-csv-to-nmap.py path/to/csv`. This will then automatically scan (with, by default, 4 worker threads) and output to xml the chosen IPs, which can then be fed into `threaded_nmap_shodan_scan.py`.

Optionally, the `-F` or `--fast` option may be passed at the end of the command: `python3 csv-to-nmap.py path/to/csv -F`.   
Increasing the amount of Fs increases the speed:   
`-F`: skips subnets of size 256 or larger   
`-FF`: also uses nmap `-F` flag (i.e. only scans top 100 ports)   
`-FFF`: also uses ping host discovery (i.e. does NOT use `-Pn`)   

The `-q` or `--quiet` option may be passed to disable Nmap output to the console.

The `-sS` or `--stealthy` option may be passed to use "stealthy" Nmap options.

The `--max_workers INT` option may be passed to specify the max number of worker threads, with the default being 4.

###### Created by Gio Girasoli for UConn ITS 06/05/26   
###### No AI was used in the making of these programs.
