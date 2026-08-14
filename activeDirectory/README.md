# Active Directory Emails to CSV

## Overview

This is a simple PowerShell script meant for obtaining student worker email addresses for phishing simulations.

## Usage

Create a `groupNames.txt` file (in the same directory as the script) with the desired group names to query AD for. The script will then output a timestamped csv file.

Note that the script creates the temporary `raw.txt` and `out.txt` files, containing the raw output of the script's `Get-ADGroupMember` pipeline and the results filtered to only contain student worker emails respectively. If these files are desired, simply comment out the `Remove-Item` commands for them.

###### Created by Gio Girasoli 8/14/26 for ITS
