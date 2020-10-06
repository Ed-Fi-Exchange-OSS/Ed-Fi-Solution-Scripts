# SPDX-License-Identifier: Apache-2.0
# Licensed to the Ed-Fi Alliance under one or more agreements.
# The Ed-Fi Alliance licenses this file to you under the Apache License, Version 2.0.
# See the LICENSE and NOTICES files in the project root for more information.
function Get-ExternalIP {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param ()
    try {
        $ExtIP = Invoke-WebRequest -Uri "https://showextip.azurewebsites.net/" -Method Get -TimeoutSec 10 -UseBasicParsing
    }
    catch { 
        Write-Error "Failed to discover public IP address.  Error: $_ "
        return $null
    } 
    $IPregex='(?<Address>(\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b))'
    if ($ExtIP.Content -Match $IPregex) {
        return $Matches.Address
    }
    else {
        Write-Error "Failed to parse IP address from showextip.  Error: $_ "
        return $null
    }
}
function Get-InternalIP {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param ()
    try {
        # Grabs the list of system IP addresses which are either manually assigned or assigned via DHCP, then sorts them in index order
        # Index order may not be route order but that is usually the case
        # $locRoutes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object -Property ifMetric
        # $IntIPs = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $locRoutes[0].ifIndex |Sort-Object -Property ifIndex
        $IntIP = (Get-NetIPAddress -AddressState Preferred -AddressFamily IPv4 -InterfaceIndex (Get-NetRoute -DestinationPrefix "0.0.0.0/0" |Sort-Object -Property ifIndex)[0].ifIndex).IPAddress
    }
    catch { 
        Write-Error "Failed to collect system IP addresses.`n  Error: $_ "
        return $null
    } 
    return $IntIP
}
function Add-NameToHostsFile {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DnsName
    )
    # Setting a hosts entry for the given name on local IP address to attempt to bypass DNS
    $hostsFilePath = "$($Env:WinDir)\system32\Drivers\etc\hosts"
    $hostsFile = Get-Content $hostsFilePath
    $escapedHostname = [Regex]::Escape($DnsName)
    $loopbackIP="127.0.0.1"
    $localIP=Get-InternalIP -Verbose:$VerbosePreference
    if ($null -eq $localIP -or $localIP -like $loopbackIP) {
        Write-Warning "Unable to determine local ip address.  Skipping update of hosts file."
        return
    }
    if (!(($hostsFile) -match ".*$localIP\s+$escapedHostname.*")) {
        Add-Content -Encoding UTF8  $hostsFilePath ("$localIP".PadRight(20, " ") + "$DnsName") -Verbose:$VerbosePreference
    }
    Write-Verbose "Local address mapping to $DnsName added to Hosts file"
}
function Update-DynDNS {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $HostDNS,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $IP,
        [string] $ProviderUrl="https://members.dyndns.org/nic/update?hostname={DnsName}&myip={IP}",
        [pscredential]$Credentials
    )
    # Uses the REST interface for Dyn.com.
    if (!$IP) {
        $IP=Get-ExternalIP
    }
    try {
        $ProviderUrl = $ProviderUrl -replace "{DnsName}",$HostDNS -replace "{IP}",$IP
        Write-Verbose " Calling: Invoke-RestMethod -Uri $ProviderUrl -Credential $Credentials -UserAgent `"EdFiAlliance SolutionBuilder`" "
        $Result = Invoke-RestMethod -Uri $ProviderUrl -Credential $Credentials -UserAgent "EdFiAlliance SolutionBuilder" -Verbose:$VerbosePreference
        Write-Verbose "DDNS update result: $Result"
    }
    catch {
        Write-Error "Secure update of Dynamic DNS failed.`n Attempting less secure update.`n  Error: $_ "
    }
    try {
        [string]$authparams="https://$($Credentials.GetNetworkCredential().UserName):$($Credentials.GetNetworkCredential().Password)@"
        $ProviderUrl = $ProviderUrl -replace "^https://",$authparams
        Write-Verbose " Calling: Invoke-RestMethod -Uri $ProviderUrl -Credential $Credentials -UserAgent `"EdFiAlliance SolutionBuilder`" "
        $Result = Invoke-RestMethod -Uri $ProviderUrl -Credential $Credentials -UserAgent "EdFiAlliance SolutionBuilder" -Verbose:$VerbosePreference
        Write-Verbose "DDNS update result: $Result"
    }
    catch {
        Write-Error "Failed to update Dynamic DNS entry.  Error: $_ "
        return $false 
    }
    return $true
}
