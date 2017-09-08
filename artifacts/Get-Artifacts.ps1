# Get-Artifacts.ps1

# Enable-PSRemoting -Force must be run on target hosts
# Only tested on Windows 10. Requires Powershell 3.0 or above

## There are four parameters this script

## TargetList specifies the filepath to a file contatining
## a lists of hosts to probe.
## The Target is used to specify a single remote target on the command line
## The CSVPath paramter is used to specify the path of a CSV file to export to.
## The Print parameter is set when you want information to be printed to stdout

param (
    [string]$TargetList = $null,
    [string]$Target = $null,
    [string]$CSVPath = $null,
    [switch]$Print = $false 
)

# Initialize objects and arraylists for each table of information to be gathered

$timeInfo = New-Object System.Object
$OSInfo = New-Object System.Object
$CPUInfo = [System.Collections.ArrayList]@()
$HDDlist = [System.Collections.ArrayList]@()
$MountPoints = [System.Collections.ArrayList]@()
$DomainInfo = New-Object System.Object
$LocalUsers = [System.Collections.ArrayList]@()
$DomainUsers = [System.Collections.ArrayList]@()
$SystemUsers = [System.Collections.ArrayList]@()
$ServiceUsers = [System.Collections.ArrayList]@()
$StartupServices = [System.Collections.ArrayList]@()
$StartupPrograms = [System.Collections.ArrayList]@()
$NetworkConfiguration = [System.Collections.ArrayList]@()
$ProcessList = [System.Collections.ArrayList]@()
$ProgramList = [System.Collections.ArrayList]@()
$NetworkShares = [System.Collections.ArrayList]@()
$PrinterList = [System.Collections.ArrayList]@()
$TaskList = [System.Collections.ArrayList]@()
$ARPTable = [System.Collections.ArrayList]@()
$RoutingTable = [System.Collections.ArrayList]@()
$ListeningServices = [System.Collections.ArrayList]@()
$EstablishedServices = [System.Collections.ArrayList]@()
$DNSCache = [System.Collections.ArrayList]@()
$Downloads = [System.Collections.ArrayList]@()
$Documents = [System.Collections.ArrayList]@()


## The function collectData is used to collect information from a single 
## target system. It tries to utilize Get-CimInstance wherever possible.
## The intent was to use CimSessions to remotely gather information from
## hosts but it seemed that certain data such as a host's arp table could
## not be gathered using Get-CimInstance. For that reason PS remote sessions
## are used instead.

## Initially CIM cmdlets were used over WMI cmdlets because CIM cmdlets
## use WSMAN to connect to remote machines. WMI uses DCOM which is insecure
## and often blocked by networking devices. 


function collectData {

    ## The Win32_OperatingSystem class specifies information about the OS running on
    ## the target system. 
    ## We use this class to grab the current time, time zone, last boot up time, and uptime
    ## on the target system.

    Get-CimInstance -ClassName Win32_OperatingSystem | ForEach {
        $timeInfo | Add-Member -MemberType NoteProperty -Name "Current Time" -Value $_.LocalDateTime
        $timeInfo | Add-Member -MemberType NoteProperty -Name "Current Time Zone" -Value $_.CurrentTimeZone
        $timeInfo | Add-Member -MemberType NoteProperty -Name "Last Boot Up Time" -Value $_.LastBootUpTime
        $timeInfo | Add-Member -MemberType NoteProperty -Name "Uptime" -Value ($_.LocalDateTime - $_.LastBootUpTime)
    }

    ## We can also utilize this class to grab information about the operating system version.
    ## Namely, the canonical name, version, build number and build type.

    Get-CimInstance -ClassName Win32_OperatingSystem | ForEach {
        $OSInfo | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Caption
        $OSInfo | Add-Member -MemberType NoteProperty -Name "Version" -Value $_.Version
        $OSInfo | Add-Member -MemberType NoteProperty -Name "Build Number" -Value $_.BuildNumber
        $OSInfo | Add-Member -MemberType NoteProperty -Name "Build Type" -Value $_.BuildType
    }

    ## The Win32_Processor class specifies information about the processors on the targer system.
    ## We elect to grab just the name and brand of each processor on the system.

    Get-CimInstance -ClassName Win32_Processor | ForEach {
        $CPU = New-Object System.Object
        $CPU | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
        $CPU | Add-Member -MemberType NoteProperty -Name "Brand" -Value $_.Manufacturer
        $CPUInfo.Add($CPU) | Out-Null
    }

    ## The Win32_LogicalDisk class specifies information that pertains to a local storage
    ## device running on the target system. Drive Type 3 restricts the query to 
    ## just local disks rather than including removeable media or network drives.

    Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType='3'" | ForEach {
        $disk = New-Object System.Object
        $disk | Add-Member -MemberType NoteProperty -Name "Label" -Value $_.DeviceID
        $disk | Add-Member -MemberType NoteProperty -Name "Size" -Value $_.Size
        $disk | Add-Member -MemberType NoteProperty -Name "FreeSpace" -Value $_.FreeSpace
        $HDDlist.Add($disk) | Out-Null
    }

    Get-CimInstance -ClassName Win32_Volume -Filter "DriveType='3'" | ForEach {
        $mp = New-Object System.Object
        $mp | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
        $mp | Add-Member -MemberType NoteProperty -Name "FreeSpace" -Value $_.FreeSpace
        $MountPoints.Add($mp) | Out-Null
    }

    ## The Win32_ComputerSystem class provides plenty of information regarding
    ## a computer system running Windows. Here we just need the hostname and domain name. 

    Get-CimInstance -ClassName Win32_ComputerSystem | ForEach {
        $DomainInfo | Add-Member -MemberType NoteProperty -Name "Hostname" -Value $_.Name
        $DomainInfo | Add-Member -MemberType NoteProperty -Name "Domain" -Value $_.Domain
    }

    ## The class Win32_UserAccount specifies objects for all user accounts 
    ## on the system. 
    ## Grab local user accounts. Account type 512 specifies that it is a local account.

    Get-CimInstance -ClassName Win32_UserAccount -Filter "AccountType='512'" | ForEach {
        $local = New-Object System.Object
        $local | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
        $local | Add-Member -MemberType NoteProperty -Name "SID" -Value $_.SID
        $LocalUsers.add($local) | Out-Null
    }

    ## Grab domain accounts. Account type 4096 specifies domain accounts.

    Get-CimInstance -ClassName Win32_UserAccount -Filter "AccountType='4096'" | ForEach {
        $user = New-Object System.Object
        $user | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
        $user | Add-Member -MemberType NoteProperty -Name "SID" -Value $_.SID
        $user | Add-Member -MemberType NoteProperty -Name "Domain" -Value $_.Domain
        $DomainUsers.add($user) | Out-Null
    }

    ## Grab system accounts. The Win32_SystemAccount class specifies objects for each
    ## system account found on the system.

    Get-CimInstance -ClassName Win32_SystemAccount | ForEach {
        $sys_user = New-Object System.Object
        $sys_user | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
        $sys_user | Add-Member -MemberType NoteProperty -Name "SID" -Value $_.SID
        $SystemUsers.add($sys_user) | Out-Null
    }

    ## The Win32_Service specifies information about the services running on a target system.
    ## One of the attributes it specifies is StartName. This refers to the service account that
    ## the starts the service. 
    ## $ServiceUsernames is used to aggregate all service accounts listed for each service
    ## Then duplicates are purged and unique values are placed in the $ServiceUsers arraylist.

    $ServiceUsernames = [System.Collections.ArrayList]@() 

    Get-CimInstance -ClassName Win32_Service | ForEach {
        $ServiceUsernames.add($_.StartName) | Out-Null
    }

    $ServiceUsernames | Sort-Object -Property @{Expression={$_.Trim()}} -Unique | ForEach {
        $serv_user = New-Object System.Object
        $serv_user | Add-Member -MemberType NoteProperty -Name "Name" -Value $_
        $serv_user | Add-Member -MemberType NoteProperty -Name "Type" -Value "ServiceUser"
        $ServiceUsers.add($serv_user) | Out-Null
    }

    ## The Win32_Service class also has an attribute that specifies if a service
    ## starts automatically at boot. This type is used to filter for all the services
    ## that start at boot and add them to $StartupServices

    Get-CimInstance -ClassName Win32_Service -Filter "StartMode='Auto'" | ForEach {
        $serv = New-Object System.Object
        $serv | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.DisplayName
        $StartupServices.Add($serv) | Out-Null
    }

    ## The Win32_StartupCommand class specifies a command that runs when a user logs onto
    ## the target system. This class is used to gather information about the programs
    ## that startup at boot.

    Get-CimInstance -ClassName Win32_StartupCommand | ForEach {
        $program = New-Object System.Object
        $program | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
        $program | Add-Member -MemberType NoteProperty -Name "Runs As" -Value $_.User
        $program | Add-Member -MemberType NoteProperty -Name "Command" -Value $_.Command
        $program | Add-Member -MemberType NoteProperty -Name "Registry Key" -Value $_.Location
        $StartupPrograms.Add($program) | Out-Null
    }

    ## The Win32_NetworkAdaptorConfiguration class specifies information about the network 
    ## interfaces on a target system. It is used here to gather information about the
    ## network configuration of each interface on the target system. The "MACAddress!=NULL"
    ## filter is used to exclude any network adapters that do not have a MAC Address.

    Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "MACAddress!=NULL" | ForEach {
        $interface = New-Object System.Object
        $interface | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Description
        $interface | Add-Member -MemberType NoteProperty -Name "MAC Address" -Value $_.MACAddress
        $interface | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $_.IPAddress
        $interface | Add-Member -MemberType NoteProperty -Name "DHCP Server" -Value $_.DHCPServer
        $interface | Add-Member -MemberType NoteProperty -Name "DNS Server" -Value $_.DNSServerSearchOrder
        $interface | Add-Member -MemberType NoteProperty -Name "Default Gateway" -Value $_.DefaultIPGateway
        $NetworkConfiguration.Add($interface) | Out-Null
    }

    ## The Win32_Process class specifies information about all running processes on
    ## the target machine. It is used here to gather information about each running
    ## process. To grab the name of the user running the process we invoke a method
    ## named GetOwner.

    Get-CimInstance -ClassName Win32_Process | ForEach {
        $process = New-Object System.Object
        $process | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
        $process | Add-Member -MemberType NoteProperty -Name "Process ID" -Value $_.ProcessId
        $process | Add-Member -MemberType NoteProperty -Name "Parent Process ID" -Value $_.ParentProcessId
        $process | Add-Member -MemberType NoteProperty -Name "Location" -Value $_.ExecutablePath
        $name = (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User  # Grabs the name of the user running the process.
        $process | Add-Member -MemberType NoteProperty -Name "Owner" -Value $name
        $ProcessList.Add($process) | Out-Null
    }

    ## The Win32_Product class specifies the installed programs on the target system.
    ## It is used to list all the programs that were installed on the target system as well
    ## as the date they were installed.

    Get-CimInstance -ClassName Win32_Product | ForEach {
        $program = New-Object System.Object
        $program | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
        $program | Add-Member -MemberType NoteProperty -Name "Install Date" -Value $_.InstallDate
        $ProgramList.Add($program) | Out-Null
    }

    ## The Win32_Share class is used here to gather information about each network share
    ## mounted on the target system. 

    Get-CimInstance -ClassName Win32_Share | ForEach {
        $share = New-Object System.Object
        $share | Add-Member -MemberType NoteProperty -Name "Share Name" -Value $_.Name
        $share | Add-Member -MemberType NoteProperty -Name "Path" -Value $_.Path
        $share | Add-Member -MemberType NoteProperty -Name "Caption" -Value $_.Description
        $NetworkShares.Add($share) | Out-Null
    }

    ## The Win32_Printer class is used here to gather information about each printer installed
    ## on the target system.

    Get-CimInstance -ClassName Win32_Printer | ForEach {
        $printer = New-Object System.Object
        $printer | Add-Member -MemberType NoteProperty -Name "Printer" -Value $_.Name
        $printer | Add-Member -MemberType NoteProperty -Name "Share Name" -Value $_.ShareName
        $printer | Add-Member -MemberType NoteProperty -Name "System Name" -Value $_.SystemName
        $PrinterList.Add($printer) | Out-Null
    }

    ## From here on out, I use normal Powershell cmdlets to query for relavent information
    ## on the target system. I create objects from the information in the same way I did using
    ## the Get-CimInstance cmdlets.

    ## Get-Scheduled Task returns information about every scheduled task ont he target system.
    ## I choose to record the TaskN

    Get-ScheduledTask | ForEach {
        $task = New-Object System.Object
        $task | Add-Member -MemberType NoteProperty -Name "Task" -Value $_.TaskName
        $task | Add-Member -MemberType NoteProperty -Name "State" -Value $_.State
        $TaskList.Add($task) | Out-Null
    }

    ## Get-NetNeighbor returns information regarding a host's ARP table. It is used
    ## used here to grab the target system's ARP table.

    Get-NetNeighbor | ForEach {
        $entry = New-Object System.Object
        $entry | Add-Member -MemberType NoteProperty -Name "Interface" -Value $_.ifIndex
        $entry | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $_.IPAddress
        $entry | Add-Member -MemberType NoteProperty -Name "MAC Address" -Value $_.LinkLayerAddress
        $entry | Add-Member -MemberType NoteProperty -Name "State" -Value $_.State
        $ARPTable.Add($entry) | Out-Null
    }

    ## Get-NetRoute can be used to return information regarding the host's routing table. It is used
    ## here to grab the target system's Routing Table.

    Get-NetRoute | ForEach {
        $entry = New-Object System.Object
        $entry | Add-Member -MemberType NoteProperty -Name "Interface" -Value $_.ifIndex
        $entry | Add-Member -MemberType NoteProperty -Name "Destination" -Value $_.DestinationPrefix
        $entry | Add-Member -MemberType NoteProperty -Name "Next Hop" -Value $_.NextHop
        $entry | Add-Member -MemberType NoteProperty -Name "Route Metric" -Value $_.RouteMetric
        $entry | Add-Member -MemberType NoteProperty -Name "Interface Metric" -Value $_.Interface
        $RoutingTable.Add($entry) | Out-Null
    }    

    ## Get-NetTCPConnection can be used as an alternative to netstat to gather information about
    ## TCP connections on a target system. Here it is used with the -State Listen flag to gather information
    ## about all listening sockets.

    Get-NetTCPConnection -State Listen | ForEach {
        $service = New-Object System.Object
        $service | Add-Member -MemberType NoteProperty -Name "Local Address" -Value $_.LocalAddress
        $service | Add-Member -MemberType NoteProperty -Name "Local Port" -Value $_.LocalPort
        $service | Add-Member -MemberType NoteProperty -Name "Remote Address" -Value $_.RemoteAddress
        $service | Add-Member -MemberType NoteProperty -Name "Remote Port" -Value $_.RemotePort
        $ListeningServices.Add($service) | Out-Null
    }

    ## Here Get-NetTCPConnection -State Established is used to gather information about all
    ## established connections on the target system.

    Get-NetTCPConnection -State Established | ForEach {
        $service = New-Object System.Object
        $service | Add-Member -MemberType NoteProperty -Name "Local Address" -Value $_.LocalAddress
        $service | Add-Member -MemberType NoteProperty -Name "Local Port" -Value $_.LocalPort
        $service | Add-Member -MemberType NoteProperty -Name "Remote Address" -Value $_.RemoteAddress
        $service | Add-Member -MemberType NoteProperty -Name "Remote Port" -Value $_.RemotePort
        $EstablishedServices.Add($service) | Out-Null
    }

    ## Get-DnsClientCache can be used to return all the DNS records cached on the target system.

    Get-DnsClientCache | ForEach {
        $record = New-Object System.Object
        $record | Add-Member -MemberType NoteProperty -Name "Entry" -Value $_.Entry
        $record | Add-Member -MemberType NoteProperty -Name "Record Type" -Value $_.Type
        $record | Add-Member -MemberType NoteProperty -Name "Data" -Value $_.Data
        $record | Add-Member -MemberType NoteProperty -Name "TTL" -Value $_.TimeToLive
        $DNSCache.Add($record) | Out-Null
    }

    ## Get-ChildItem can be used to return every file in a specified directory.
    ## The -Recurse flag makes it so it also returns every file in every sub-folder in that
    ## directory.

    ## In the two loops below it is used to return 

    $docPath = $env:USERPROFILE + "\Documents"
    $dlPath = $env:USERPROFILE + "\Downloads"

    Get-ChildItem $docPath -Recurse | ForEach {
        $file = New-Object System.Object
        $file | Add-Member -MemberType NoteProperty -Name "File" -Value $_.Name
        $file | Add-Member -MemberType NoteProperty -Name "Creation Time" -Value $_.CreationTime
        $file | Add-Member -MemberType NoteProperty -Name "Last Access Time" -Value $_.LastAccessTime
        $file | Add-Member -MemberType NoteProperty -Name "Last Write Time" -Value $_.LastWriteTime
        $Documents.Add($file) | Out-Null
    }

    Get-ChildItem $dlPath -Recurse | ForEach {
        $file = New-Object System.Object
        $file | Add-Member -MemberType NoteProperty -Name "File" -Value $_.Name
        $file | Add-Member -MemberType NoteProperty -Name "Creation Time" -Value $_.CreationTime
        $file | Add-Member -MemberType NoteProperty -Name "Last Access Time" -Value $_.LastAccessTime
        $file | Add-Member -MemberType NoteProperty -Name "Last Write Time" -Value $_.LastWriteTime
        $Downloads.Add($file) | Out-Null
    }

    ## Get-WindowsDriver is used here to gather information about every driver installed
    ## on the target system.

    Get-WindowsDriver -All -Online | ForEach {
        $driver = New-Object System.Object
        $driver | Add-Member -MemberType NoteProperty -Name "Driver" -Value $_.OriginalFileName
        $driver | Add-Member -MemberType NoteProperty -Name "Provider" -Value $_.ProviderName
        $DriverList.Add($driver) | Out-Null
    }

}

## The writeData function prints all the gathered information to 
## stdout in formatted tables. writeData has to be called for
## every computer being probed

function writeData {

    ## Format-Table makes sure the information is formatted in table form
    ## Out-String converts the information into a string to be written by Write-Host

    Write-Host ($timeInfo | Format-Table | Out-String) 
    Write-Host ($OSInfo | Format-Table | Out-String)
    Write-Host ($CPUInfo | Format-Table | Out-String)
    Write-Host ($HDDlist | Format-Table | Out-String)
    Write-Host ($MountPoints | Format-Table | Out-String)
    Write-Host ($DomainInfo | Format-Table | Out-String)
    Write-Host ($LocalUsers | Format-Table | Out-String)
    Write-Host ($DomainUsers | Format-Table | Out-String)
    Write-Host ($SystemUsers | Format-Table | Out-String)
    Write-Host ($ServiceUsers | Format-Table | Out-String)
    Write-Host ($StartupServices | Format-Table | Out-String)
    Write-Host ($StartupPrograms | Format-Table | Out-String)
    Write-Host ($NetworkConfiguration | Format-Table | Out-String)
    Write-Host ($ProcessList | Format-Table | Out-String)
    Write-Host ($ProgramList | Format-Table | Out-String)
    Write-Host ($NetworkShares | Format-Table | Out-String)
    Write-Host ($PrinterList | Format-Table | Out-String)
    Write-Host ($TaskList | Format-Table | Out-String)
    Write-Host ($ARPTable | Format-Table | Out-String)
    Write-Host ($RoutingTable | Format-Table | Out-String)
    Write-Host ($ListeningServices | Format-Table | Out-String)
    Write-Host ($EstablishedServices | Format-Table | Out-String)
    Write-Host ($DNSCache | Format-Table | Out-String)
    Write-Host ($Downloads | Format-Table | Out-String)
    Write-Host ($Documents | Format-Table | Out-String)

    ## I originally tried using Write-Output but as it turns out
    ## when you call Write-Output on objects with different properties
    ## only the first object will be printed to stdout. Write-Output
    ## will only work on objects with matching properties.

}

## The writeCSV function will send individual tables to its 
## own csv file and then append all the individual files
## together. This creates a single csv file for every computer probed.

function writeCSV {

    $path = $CSVPath + "\Evidence"
    New-Item -ItemType directory -Path $path | Out-Null

    $timeInfo | Export-CSV -Path $path\time.csv -NoTypeInformation  ## -NoTypeInformation removes type headers
    $OSInfo | Export-CSV -Path $path\os.csv -NoTypeInformation
    $CPUInfo | Export-CSV -Path $path\cpu.csv -NoTypeInformation
    $HDDlist | Export-CSV -Path $path\hdd.csv -NoTypeInformation 
    $MountPoints | Export-CSV -Path $path\mp.csv -NoTypeInformation
    $DomainInfo | Export-CSV -Path $path\domain.csv -NoTypeInformation
    $LocalUsers | Export-CSV -Path $path\localusers.csv -NoTypeInformation
    $DomainUsers | Export-CSV -Path $path\domainusers.csv -NoTypeInformation
    $SystemUsers | Export-CSV -Path $path\systemusers.csv -NoTypeInformation
    $ServiceUsers | Export-CSV -Path $path\serviceusers.csv -NoTypeInformation
    $StartupServices | Export-CSV -Path $path\startupservices.csv -NoTypeInformation
    $StartupPrograms | Export-CSV -Path $path\startupprograms.csv -NoTypeInformation
    $NetworkConfiguration | Export-CSV -Path $path\netconfig.csv -NoTypeInformation
    $ProcessList | Export-CSV -Path $path\processes.csv -NoTypeInformation
    $ProgramList | Export-CSV -Path $path\programs.csv -NoTypeInformation
    $NetworkShares | Export-CSV -Path $path\netshares.csv -NoTypeInformation
    $PrinterList | Export-CSV -Path $path\print.csv -NoTypeInformation
    $TaskList | Export-CSV -Path $path\scheduledtasks.csv -NoTypeInformation
    $ARPTable | Export-CSV -Path $path\arp.csv -NoTypeInformation
    $RoutingTable | Export-CSV -Path $path\routes.csv -NoTypeInformation
    $ListeningServices | Export-CSV -Path $path\listen.csv -NoTypeInformation
    $EstablishedServices | Export-CSV -Path $path\established.csv -NoTypeInformation
    $DNSCache | Export-CSV -Path $path\dnscache.csv -NoTypeInformation
    $Downloads | Export-CSV -Path $path\downloads.csv -NoTypeInformation
    $Documents | Export-CSV -Path $path\documents.csv -NoTypeInformation

    $finalpath = $path + "\" + $DomainInfo.Hostname + ".csv"

    ## This loop appends all the CSV files to one master file and adds a newline 
    ## in between tables.

    Get-ChildItem $path | ForEach {
        [System.IO.File]::AppendAllText($finalpath, [System.IO.File]::ReadAllText($_.FullName) + [System.Environment]::NewLine)
        Remove-Item $path\$_
    }

}

## The following if-blocks control how the script executes in accordance
## with what the specified parameters are.
## In short, if a $TargetList exists then remote into each Target 
## and collect/write/export data. If a single $Target is specified then
## remote into that one target and collect/write/export data.
## Otherwise, just collect data on the local machine and write/export it.
## Data is written only if specified and exported only if specified.

if ($TargetList) {

    $computers = Get-Content $TargetList

    $computers | ForEach {

        $computer = $_
        Enter-PSSession -ComputerName $_ ## -Credential (Get-Credential)
        collectData
        Exit-PSSession
        if ($Print -eq $true) {
            writeData
        }
        if ($CSVPath) {
            writeCSV
        }
    }

} elseif ($Target) {

    Enter-PSSession -ComputerName $Target ## -Credential (Get-Credential)
    collectData
    Exit-PSSession
    if ($Print -eq $true) {
        writeData
    }
    if ($CSVPath) {
        writeCSV
    } else {
        $CSVPath = $MyInvocation.MyCommand.Path
        writeCSV
    }

} else {

    collectData
    if ($Print -eq $true) {
        writeData
    }
    if ($CSVPath) {
        writeCSV
    } else {
        $CSVPath = $PSScriptRoot
        writeCSV
    }

}




