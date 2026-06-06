# Nmap and Shodan.io Auditing Tool

## Overview

This is a command line tool intended to transform an xml output of an Nmap scan in conjunction with paired data from Shodan.io to discover internal and external port exposures on a network.

## Usage

Create a `.env` file in this directory containing your Shodan API key in the format of `SHODAN_KEY=yourKeyHere`.

Install the required libraries with `pip install -r requirements.txt`.

Run `python3 threaded_nmap_shodan_scan.py -f path/to/nmapscan.xml`.

This program iterates through each IP detected by Nmap, collecting hostnames, exposed ports, and their respective services.
Then, using the IPs returned by Nmap, queries Shodan.io's API to attempt to find posts exposed externally to the internet.
This data is outputted as a .csv file with the columns of IP, Hostname, Internal Port (detected by nmap), Service, and External Port (detected by Shodan), with an entry for each individual port.

Optionally, you can include the `-v` flag before the `-f` flag for verbose output.

The multithreaded version is over 500% faster than the sequential version.

## Nmap

For my scans, I used the following command:

`nmap -T4 -Pn -sV --open -oX output.xml ip.in.CIDR.0/format`

`-T4` to speed up the scan, `-Pn` to treat all hosts as online (circumvents blocked discovery probes), `-sV` enables version/service detection, `--open` to only output open ports (required for this program), `-oX output.xml` to output to xml (required for this program), and finally the IP range to scan.

###### Created by Gio Girasoli for UConn ITS 06/05/26

###### No AI was used in the making of this program.
