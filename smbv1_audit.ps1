function Resolve-IPAddresses {
    param (
        [Parameter(Mandatory=$true,Position=1)]
        [string[]]$IPs
    )
    begin{
        $resolutions = @()
    }
    process{
        foreach($ip in $Ips){
            try{
                $name = [System.Net.DNS]::GetHostByAddress($ip).HostName
            }
            catch{
                $name = "Not found"
            }
            $resolutions += @{"IP"=$ip; "Hostname"=$name}
        }
    }
    end{
        return $resolutions
    }
}

function parseLogMessages {
    param (
        [Parameter(Mandatory=$true,Position=1)]
        [string[]]$Messages
    )
    begin{
        $regex = "(?:(?:(?:Client)|(?:Server))\sAddress:\s)([\d\.]+)"
        $Ips = @()
    }
    process{
        foreach($message in $Messages){
            $matches = [regex]::Match($message,$regex); 
            if($matches -ne $null -and $matches.groups.count -gt 1){
                $Ips += $matches.groups[1].value
            }
        }
    }
    end{
        return $Ips
    }
}

function resolutionsToString {
    param (
        [Parameter(Mandatory=$true,Position=1)]
        [Hashtable[]]$Resolutions
    )
    begin{
        $output = ""
    }
    process{
        foreach($resolution in $Resolutions){
            $output += "{0} - {1}`r`n" -f $resolution.IP, $resolution.Hostname
        }
    }
    end{
        return $output
    }
}

$serverIps = @()
$clientIps = @()
$serverOutput = ""
$clientOutput = ""
$serverLogs = Get-WinEvent -FilterHashtable @{LogName = "Microsoft-Windows-SMBServer/Audit"; Level=4; Id=3000} -ea SilentlyContinue
if($null -ne $serverLogs){
    $serverIps = parseLogMessages -Messages $serverLogs.message
    $serverIps = $serverIps | Select-Object -unique
    $serverIps = Resolve-IPAddresses -IPs $serverIps
    $serverOutput = resolutionsToString -Resolutions $serverIps
}

$clientLogs = Get-WinEvent -FilterHashtable @{LogName = "Microsoft-Windows-SMBClient/Audit"; Level=4; Id=3000} -ea SilentlyContinue
if($null -ne $clientLogs){
    $clientIps = parseLogMessages -Messages $clientLogs.message
    $clientIps = $clientIps | Select-Object -unique
    $clientIps = Resolve-IPAddresses -Ips $clientIps
    $clientOutput = resolutionsToString -Resolutions $clientIps
}

Write-Output ("SMBv1 server connected to by the following clients:`r`n{0}`r`n`r`nSMBv1 client connected to the following servers:`r`n{1}" -f $serverOutput, $clientOutput)