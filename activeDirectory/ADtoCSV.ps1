#This script takes a txt file of AD group names and exports the work email addresses to csv

#define variables
$ADServer = "grove.ad.uconn.edu"
$ADGroupNames = @()

#get groupnames from txt file (groupNames.txt in same working dir)
foreach ($line in Get-Content .\groupNames.txt){
    $ADGroupNames += $line
}

"" > raw.txt #empty file
#traverse groups and get mail address
foreach ($ADGroup in $ADGroupNames){
    Get-ADGroupMember -Identity $ADGroup -Server $ADServer | Get-ADUser -Properties Mail | Select-Object Mail >> raw.txt
}

Write-Output $null > out.txt #empty file
#traverse raw output and get only students
foreach ($line in Get-Content .\raw.txt){
    if ($line -match "work"){ #regex for line containing "work"
        $line.Replace("work", "").Trim() >> out.txt
    }
}

#create csv data and export
$csvData = Get-Content .\out.txt | ForEach-Object {
    [PSCustomObject]@{
        mail = $_
    }
}
$date = Get-Date -Format "yy-MM-ddTHH-mm-ss"
$path = ".\studentEmails_"+$date+".csv"
$csvData | Export-Csv -Path $path -NoTypeInformation

#clean up temp
Remove-Item .\raw.txt
Remove-Item .\out.txt

#created by Gio Girasoli 8/14/26 for UITS/ISO
