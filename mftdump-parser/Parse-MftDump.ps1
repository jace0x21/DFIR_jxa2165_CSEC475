## Author: JC

## Parses the output of MFTDump.exe in a more read-able format
## Prints out a table or prints out a single file entry.


## Parameters are path and file
## path is necessary to specify the location of the csv file to parse
## file is optional and specifies the file entry to print


param (

[Parameter(Mandatory=$true)]
[string] $path,

[string] $file = $null

)

$data = Import-CSV -path $path -Delimiter "|"

if($file -eq $null) {

    $data | Write-Output

} else {

    $data | Where-Object {$_.filename -eq $file} | Write-Output

}
