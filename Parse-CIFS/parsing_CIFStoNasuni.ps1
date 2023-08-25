#
<#
.SYNOPSIS
  This script will parse a CIFS share txt file exported from NetApp filer and create a
  CSV file to be used as input on NASUNI system, according to specifications.

.DESCRIPTION
  This script will parse CIFS txt files of a specific format to translate the shares configuration
  into a CSV input to be used/imported on a NASUNI system.
  The script depends on input files: listofUsersAD.csv and exporte cifs hsare txt file.

.PARAMETER Path
    the prefix of the share path local to Nasuni server. Provided by Nasuni SA.
.PARAMETER Volume_GUID
    provided by Nasuni SA
.PARAMETER Filer_Serial_Number
    provided by Nasuni SA
.PARAMETER Cifs_File_Path
    the name and path of the CIFS txt file - example: ".\BRSPLNDOWD009_Cifs Shares_Details.txt

.INPUTS
  CIFS share export from NetAPP - txt file
  List of Domain Users - csv file

.OUTPUTS
  CSV file with list of parsed shares: .\ShareInfoPArsed-$d$m$y-$h$min$sec.csv
  CSV file formatted accordingly to NASUNI input requirements: .\InputCSV-$d$m$y-$h$min$sec.csv
  name of the file is formatted as following:
  $d=day(XX);$m=month(XX);$y=year(XXXX);$h=hour(XX);$min=minute;$sec=second(XX)

.NOTES
  Version:        1.0
  Author:         emurari@kyndryl.com
  Creation Date:  July 26 2023
  Purpose/Change: Initial script development

.EXAMPLE
  parsing_CIFStoNasuni.ps1 -Path "<prefix_path>" -Volume_GUID "<volumeguid>" -Filer_Serial_Number "<serial_number>" -Cifs_File_Path "<filepath>"
.EXAMPLE
  parsing_CIFStoNasuni.ps1 -Path "\brsplndown001_d\" -Volume_GUID "583f1a3e-02f6-481b-8515-0240839ee3fd_3" -Filer_Serial_Number "0e8b51d4-7d74-403f-90c2-7cf58e21561e" -Cifs_File_Path ".\export_cifs_shares.txt"
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------
Param (
	[parameter(Mandatory=$true)]
        [string] $Path,
	[parameter(Mandatory=$true)]
        [string] $Volume_GUID,
	[parameter(Mandatory=$true)]
        [string] $Filer_Serial_Number,
	[parameter(Mandatory=$true)]
        [string] $Cifs_File_Path
)

#----------------------------------------------------------[Declarations]----------------------------------------------------------
$dates = get-date
$d = $dates.Day
$m = $dates.month
$y = $dates.year
$h = $dates.hour
$min = $dates.minute
$sec = $dates.second
$resultcsv = ".\ShareInfoPArsed-$d$m$y-$h$min$sec.csv"
$inputNICSV = ".\InputCSV-$d$m$y-$h$min$sec.csv"
$Shareobj = @()
$dataUser = @()
$firstLinepattern = '----         -----------                       -----------'
$sharepattern = '(?<shareName>\S+)\s+(?<path>\S+)\s+(?<comments>.+)'
$shareNoCpattern = '(?<shareName>\S+)\s+(?<path>\S+)'
$userpattern = '(?<user>.+)\/(?<permission>.+)'
$i=0
$checkShare = $false

#-----------------------------------------------------------[Execution]------------------------------------------------------------
if(Test-Path $Cifs_File_Path){
    $file = $Cifs_File_Path
}
else{
    write-output "File $Cifs_File_Path not found. Aborting..."
    break
}

foreach($line in get-content $file){
	if($checkShare){
		if(-not($line -match '^\s')){
			if ($line -match $sharepattern) {
				$sharename = $Matches.shareName
                $i = 0
                $fullpath = ""
                foreach($part in $Matches.path.split('/')){
                    if($i -gt 2){
                        $fullPath = -join($fullpath,'\',$part)
                    }
                    $i++
                }
                if($fullpath){$fullpath = $fullpath.substring(1)}
				$Shareobj += [PSCustomObject]@{
					ShareName = $sharename
					Path = $Matches.path
                    FullPath = $fullpath
					Comments = $Matches.comments
				}
			}
			elseif($line -match $shareNoCpattern) {
				$sharename = $Matches.shareName
				$i = 0
                $fullpath = ""
                foreach($part in $Matches.path.split('/')){
                    if($i -gt 2){
                        $fullPath = -join($fullpath,'\',$part)
                    }
                    $i++
                }
                if($fullpath){$fullpath = $fullpath.substring(1)}
				$Shareobj += [PSCustomObject]@{
					ShareName = $sharename
					Path = $Matches.path
                    FullPath = $fullpath
					Comments = "blank"
				}
			}
			else{
				$Shareobj += [PSCustomObject]@{
					ShareName = $line
					Path = "not found"
                    FullPath = "not found"
					Comments = "blank"
				}
			}
		}
		else{
			if($line -match $userpattern){
				$dataUser += [PSCustomObject]@{
					Sharename = $shareName
					Username = $Matches.user.Trim()
					Permission = $Matches.permission.Trim()
				}
			}
		}
		$i++
	}
	else{
		if($line -match $firstLinepattern){
			$checkShare = $true
		}
	}
}


#authRo_users	authRw_users	authDeny_users	authRo_groups	authRw_groups	authDeny_groups
#Full control = read & write, Change, Read & Write
#Read only = read
#Deny = no access

$inputResult = @()

$adList = Import-Csv .\listofUsersAD.csv
foreach($share in $Shareobj){
    $permURW = ""
    $permURO = ""
    $permUDN = ""
    $permGRW = ""
    $permGRO = ""
    $permGDN = ""
    $browseable = "TRUE"
    $curUsers = $dataUser | Where-Object{$_.Sharename -eq $share.Sharename}
    foreach($user in $curUsers){
        $isUser = $false
        if($user.Username.split("\")[1]){
            $curuser = $user.Username.split("\")[1]
        }
        else{
            $curuser = $user.Username
        }

        if($curuser -match "S-1-5-21"){
            continue
        }

        if(($curuser -eq "everyone") -or ($curuser -eq "Authenticated Users")){
            #is group
            $translatedUser = "DOW\Domain Users"
        }
        else{
            if($adlist | Where-Object{$_.SAMAccountName -eq $curuser}){ #check if user
                $isUser = $true
            }
            $translatedUser =  $user.Username
        }

        if(($user.Permission -match "Full") -or ($user.Permission -match "Change")){
            if($isUser){
                $permURW = -join($permURW,";",$translatedUser)
            }
            else{
                $permGRW = -join($permGRW,";",$translatedUser)
            }
        }
        elseif($user.Permission -match "Read"){
            if($isUser){
                $permURO = -join($permURO,";",$translatedUser)
            }
            else{
                $permGRO = -join($permGRO,";",$translatedUser)
            }
        }
        elseif($user.Permission -match "No"){
            if($isUser){
                $permUDN = -join($permUDN,";",$translatedUser)
            }
            else{
                $permGDN = -join($permGDN,";",$translatedUser)
            }
        }
    }
    if($share.Sharename -match '\$'){
        $browseable = "FALSE"
    }
    if($permURW){ $permURW = $permURW.Substring(1)}
    if($permURO){ $permURO = $permURO.Substring(1)}
    if($permUDN){ $permUDN = $permUDN.Substring(1)}
    if($permGRW){ $permGRW = $permGRW.Substring(1)}
    if($permGRO){ $permGRO = $permGRO.Substring(1)}
    if($permGDN){ $permGDN = $permGDN.Substring(1)}
    $inputResult += [PSCustomObject]@{
        shareid = ""
        Volume_GUID = $Volume_GUID
        filer_serial_number = $filer_serial_number
        share_name = $share.Sharename
        path = -join($path,$share.Fullpath)
        comment = $share.Comments
        readonly = "FALSE"
        browseable = $browseable
        authAuthall = "FALSE"
        authRo_users = $permURO
        authRw_users = $permURW
        authDeny_users = $permUDN
        authRo_groups = $permGRO
        authRw_groups = $permGRW
        authDeny_groups = $permGDN
        hosts_allow = ""
        hide_unreadable = "FALSE"
        enable_previous_vers = "TRUE"
        case_sensitive = "FALSE"
        enable_snapshot_dirs = "FALSE"
        homedir_support = "0"
        mobile = "FALSE"
        browser_access = "FALSE"
        aio_enabled = "TRUE"
        veto_files = ""
        fruit_enabled = "FALSE"
        smb_encrypt = "required"
        shared_links_enabled = ""
        link_force_password = ""
        link_allow_rw = ""
        external_share_url = ""
        link_expire_limit = ""
        link_authAuthall = ""
        link_authAllow_groups_ro = ""
        link_authAllow_groups_rw = ""
        link_authDeny_groups = ""
        link_authAllow_users_ro = ""
        link_authAllow_users_rw = ""
        link_authDeny_users = ""
    }
}

$Shareobj | Sort-Object -Property ShareName | Export-Csv -Path $resultcsv -NoTypeInformation -ErrorAction Stop
$inputResult | Export-Csv -Path $inputNICSV -NoTypeInformation -ErrorAction Stop

Write-Output "NASUNI CSV Import file created: $inputNICSV"
Write-Output "Parsed CIFS Shares: $resultcsv"