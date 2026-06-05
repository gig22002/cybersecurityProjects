# Nmap and Shodan.io Auditing Tool

## Overview

This is a command line tool intended to transform an .xml output of an Nmap scan in conjunction with paired data from Shodan.io to discover internal and external port exposures on a network.

## Usage

Create a `.env` file in this directory containing your Shodan API key in the format of `SHODAN_KEY=[yourKeyHere]`.

Run `python3 nmap_shodan_scan.py -f path/to/nmapscan.xml`.

This program iterates through each IP detected by Nmap, collecting hostnames, exposed ports, and their respective services.
Then, using the IPs returned by Nmap, queries Shodan.io's API to attempt to find posts exposed externally to the internet.
This data is outputted as a .csv file with the columns of IP, Hostname, Internal Port (detected by nmap), Service, and External Port (detected by Shodan), with an entry for each individual port.

Optionally, you can include the `-v` flag before the `-f` flag for verbose output.

## Nmap

For my scans, I used the following command:

`nmap -T4 -Pn --open -oX output.xml ip.in.CIDR.0/format`

`-T4` to speed up the scan, `-Pn` to treat all hosts as online (circumvents blocked discovery probes), `--open` to only output open ports (required for this program), `-oX output.xml` to output to xml (required for this program), and finally the IP range to scan.

###### Created by Gio Girasoli for UConn ITS 06/05/25
