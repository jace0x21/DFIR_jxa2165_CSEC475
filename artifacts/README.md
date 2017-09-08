# Get-Artifacts.ps1

This is a tool for collecting system information from one machine or multiple machines remotely. It can then print the collected data to stdout or export it to a single CSV file. It is written in Powershell.

## Prerequisites

- Powershell 3.0
- PS Remoting must be enabled on target hosts in order for this script to run successfully. To do so just run the following command on a target host.
```
Enable-PSRemoting -Force
```

## Usage

There are multiple parameters that you can utilize when running this script.

To specify a list of target hosts to collect data from you would use the -TargetList parameter and supply a list of hosts in a text file.
```
.\Get-Artifacts.ps1 -TargetList targets.txt
```
If you only want to probe one remote target you can use the -Target parameter.
```
.\Get-Artifacts.ps1 -Target 192.168.1.24
.\Get-Artifacts.ps1 -Target "SRV1-W16R2"
```
If you want the data to be exported to a CSV file you must specify the path of your CSV file using the -CSVPath parameter.
```
.\Get-Artifacts.ps1 -CSVPath C:\Users\Hercules\Documents\evidence.csv
```
If you want the data to be printed to stdout all you have to do is set the -Print flag.
```
.\Get-Artifacts.ps1 -Print
```
If you run the script with no specified targets it will collect data from the system it is running on. You can export to csv or print to stdout or do both. When connecting to a remote machine you will be prompted to enter credentials for that machine. 

## What artifacts are collected?

That's a good question. Below is a list of the data collected from target hosts.
##### Time
Current PC time, PC time zone, PC uptime
##### Windows Version 
Canonical name, numerical version, build number, build type
##### Hardware Specifications
CPU brand and type, list of local drives on the system including free space and total size, mounted file systems
##### User and Domain Information
System hostname and domain name, local users, domain users, system users, service users
Each user's SID and domain were also grabbed if they had one.
##### Startup Services and Programs
Startup services and programs as well as the user each program runs as, the command they are run with and the relavent registry key location
##### Network Configuration
IP address, MAC address, DHCP server, DNS servers, default gateway for each network interface
the system's ARP table, routing table, and DNS cache are also grabbed
##### Running Processes
process name, ID, parent ID, executable location, process owner
##### Installed Programs
program name, install date
##### Network Shares and Printers
a list of shares including their name and file path, a list of installed printers 
##### Scheduled Tasks
a list of scheduled tasks and the state they are currently in
##### TCP Connections
listening services and established connections
##### Documents and Downloads
a list of files in these folders as well as their creation time, last access time, and last modifcation time
##### Drivers
a list of installed drivers on the system

## Improvements to be made

I see this as the first draft of an ongoing project so I intend to make several improvements to remedy flaws I noticed in development.

- Grab more information from target systems such as WIFI access profiles, a user creation dates, user login history and domain controller information
- Switch to using only CIM-Sessions for running commands remotely
- Research methods to improve the speed of the program and have it running as quickly as possible
- Add titles to the top of each table of information in the outputted CSV file 

### Author

Joncarlo Alvarado
