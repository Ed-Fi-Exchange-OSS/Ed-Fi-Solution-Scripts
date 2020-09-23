# SPDX-License-Identifier: Apache-2.0
# Licensed to the Ed-Fi Alliance under one or more agreements.
# The Ed-Fi Alliance licenses this file to you under the Apache License, Version 2.0.
# See the LICENSE and NOTICES files in the project root for more information.
function Get-ConfigParam {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [string]$param,
        [string]$configParam,
        [string]$default=$null
    )
    if ([string]::IsNullOrEmpty($param)) {
        if (!([string]::IsNullOrEmpty($configParam))) {
            $configParam.trim()
        } else {
            If($null -ne $default) {
                $default.trim()
            } else { 
                $null
            }
        }
    } else {
        $param.trim()
    }
}
function Enable-RequiredWindowsFeatures {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param ()
    $tooVerbose=Add-WindowsCapability -Online -Name OpenSSH.Client
    Write-Verbose "$tooVerbose"
    $tooVerbose=Install-WindowsFeature -name NET-Framework-45-Core,NET-Framework-45-ASPNET
    Write-Verbose "$tooVerbose"
    $tooVerbose=Install-WindowsFeature -name Web-Server,Web-Common-Http,Web-Windows-Auth,Web-Basic-Auth,Web-App-Dev,Web-Net-Ext45,Web-Asp-Net45,Web-ISAPI-Ext,Web-ISAPI-Filter -IncludeManagementTools
    Write-Verbose "$tooVerbose"
#    Install-WindowsFeature -name RSAT-AD-PowerShell
}
function Install-ChocolateyPackages {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()] $Packages,
        [string] $InstallPath = "C:\Ed-Fi",
        [string] $LogPath = "C:\Ed-Fi\Logs"
    )
    if ($Packages -isnot [array]) {
        Install-Choco -Packages $Packages -InstallPath $InstallPath -LogPath $LogPath
    }
    else {
        $versionedPackages = $Packages | Where-Object {$null -ne $_.version}
        $arglistPackages = $Packages | Where-Object {($null -eq $_.version) -and ($null -ne $_.installargs)}
        $otherPackages = $Packages | Where-Object {($null -eq $_.version) -and ($null -eq $_.installargs)}
        $packageList = ""
        foreach ($pkgItem in $otherPackages) {
            $packageList+="$($pkgItem.package) "
        }
        foreach ($pkgItem in $versionedPackages) {
            if ([string]::IsNullOrEmpty($pkgItem.installargs)) {
                Install-Choco -Packages $pkgItem.package -Version $pkgItem.version -InstallPath $InstallPath -LogPath $LogPath
            }
            else {
                Install-Choco -Packages $pkgItem.package -Version $pkgItem.version -InstallArguments $pkgItem.installargs -InstallPath $InstallPath -LogPath $LogPath
            }
        }
        foreach ($pkgItem in $arglistPackages) {
            Install-Choco -Packages $pkgItem.package -Version $pkgItem.version -InstallArguments $pkgItem.installargs -InstallPath $InstallPath -LogPath $LogPath
        }
        Install-Choco -Packages $packageList -InstallPath $InstallPath -LogPath $LogPath
    }
}
function Install-Choco {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $Packages,
        [string] $Version,
        [string] $InstallArguments,
        [string] $Source,
        [string] $InstallPath = "C:\Ed-Fi",
        [string] $LogPath = "C:\Ed-Fi\Logs"
    )
    # Uses the Chocolatey package manager to install a list of packages
    # $packages is a space separated string of packages to install simultaneously with chocolatey
    #
    # Check/Install Chocolatey Package Manager 
    # 
    if (!(Get-Command "choco.exe" -ErrorAction SilentlyContinue)) {
        Write-Verbose "Installing Chocolatey package manager"
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        # Start-Sleep -Seconds 2  # Yes..sigh..a 2 second pause
    }
    if (!(Get-Command "Update-SessionEnvironment" -ErrorAction SilentlyContinue)) {
        $env:ChocolateyInstall = Convert-Path "$((Get-Command choco).path)\..\.."
        Import-Module "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
        refreshenv
    }
    $ChocoPath=(Get-Command "choco.exe" -ErrorAction SilentlyContinue).Source
    #
    # Attempt choco installs with versions or installargs and upgrades for the rest
    # 
    $logFile="$LogPath\"
    $chocArgs=[System.Collections.Generic.List[string]]::new()
    # These special cases will only work with one package at a time
    if ([string]::IsNullOrEmpty($InstallArguments) -and [string]::IsNullOrEmpty($Version)) {
        $chocArgs.Add("upgrade")
        $chocArgs.Add($Packages)
        $logFile+="choco-upgrade-"
        $errFile+="choco-upgrade-"
    }
    else {
        $chocArgs.Add("install")
        $chocArgs.Add($Packages)
        $logFile+="choco-install-"
        $errFile+="choco-install-"
        if ($InstallArguments) {
            $chocArgs.Add("--installarguments `"'$InstallArguments'`"")
        }
        if ($Version) {
            $chocArgs.Add("--version=$Version")
        }
        if ($Source) {
            $chocArgs.Add("--source=$Source")
        }
    }
    $chocArgs.Add('-y')
    $chocArgs.Add('--noprogress')
    if ($Packages.Length -gt 20) {
        $logFile+=$Packages.Substring(0,19)
    }
    else {
        $logFile+=$Packages
    }
    $errFile=$logFile
    $logFile+="-log.txt"
    $errFile+="-err.txt"
    # Could use $chocArgs.ToArray()
    Write-Verbose "Start-Process -Wait -NoNewWindow -RedirectStandardOutput $logFile -RedirectStandardError $errFile -FilePath $ChocoPath -ArgumentList $chocArgs"
    Start-Process -Wait -NoNewWindow -RedirectStandardOutput $logFile -RedirectStandardError $errFile -FilePath $ChocoPath -ArgumentList $chocArgs
    Update-SessionEnvironment
}
function Copy-GitRepo {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $repoURL,
        [string] $InstallPath,
        [string] $keyPath
    )
    Write-Verbose "Cloning repo: $repoURL to $InstallPath"
    if (!(Get-Command "git.exe" -ErrorAction SilentlyContinue)) {
        Install-Choco "git"
        if(!(Test-Path -ErrorAction SilentlyContinue "C:\Program Files\Git\cmd\git.exe")) {
            Write-Error "Error: Git not found on default installation path! Failed to clone repository!"
            return
        }
        else {
            $Env:Path += ";C:\Program Files\Git\cmd"
            if ($null -eq (Get-Command "git.exe" -ErrorAction SilentlyContinue)) {
                Write-Error "Error: Failed to find Git on path! Failed to clone repository!"
                return
            }
        }
    }
    $gitCmd=(Get-Command "git.exe").Source
    if (($null -eq $keyPath) -or [string]::IsNullOrEmpty($keyPath)) { 
        & $gitCmd clone $repoURL $InstallPath
    }
    else {
        $invertKeyPath=$keyPath.Replace('\','/')
        & $gitCmd clone $repoURL --config core.sshCommand="ssh -o StrictHostKeyChecking=no -i $invertKeyPath"
    }
}
function Copy-WebArchive {
    [CmdletBinding(DefaultParameterSetName='FilePathSet',HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory=$true, ParameterSetName = 'FilePathSet')]
        [Parameter(Mandatory=$true, ParameterSetName = 'DownloadPathSet')]
        [ValidateNotNullOrEmpty()][string]$Url,
        [Parameter(Mandatory=$true, ParameterSetName = 'FilePathSet')]
        [Parameter(Mandatory=$true, ParameterSetName = 'DownloadPathSet')]
        [ValidateNotNullOrEmpty()][string]$InstallPath,
        [Parameter(Mandatory=$true, ParameterSetName = 'FilePathSet')]
        [string]$FilePath,
        [Parameter(Mandatory=$true, ParameterSetName = 'DownloadPathSet')]
        [string]$DownloadsPath
    )
    if ($null -eq $FilePath) {
        if (! $(Try { Test-Path -ErrorAction SilentlyContinue $DownloadsPath } Catch { $false }) ) {
            $tooVerbose = New-Item -ItemType Directory -Force -Path $DownloadsPath
        }
        if ( $Url -match 'http.*\/(?<filename>[^/?]*)\??[^/]*' ){
            $FilePath="$DownloadsPath\$($matches["filename"])"
        }
        else {
            try {
                $fileRequest = [System.Net.WebRequest]::Create($Url)
                $fileRequest.AllowAutoRedirect=$false
                $fileResponse=$fileRequest.GetResponse()
                if ($fileResponse.StatusCode -eq "Found") {
                    $FilePath=[System.IO.Path]::GetFileName($fileResponse.GetResponseHeader("Location"))
                }
                else {
                    Write-Error "Unable to determine filename to store locally. Use -FilePath to specify."
                    return
                }
            }
            catch {
                Write-Error "Unable to determine filename to store locally. Use -FilePath to specify."
                return
            }
        }
    }
    if ($null -eq $FilePath) {
        throw "FilePath not set or unable to determine filename from URL."
    }
    if (Test-Path -ErrorAction SilentlyContinue $FilePath -PathType Container) {
        Write-Error "Folder at Path: $FilePath already exists! Canceling download and extract"
        return
    }
    else {
        if (Test-Path -ErrorAction SilentlyContinue $FilePath -PathType Leaf) {
            Write-Verbose "File exists, skipping download for Path: $FilePath."
        }
        else {
            try {
                $FileReq=Invoke-WebRequest -Uri $Url -OutFile $FilePath
                if ($FileReq.StatusCode -ge 400) {
                    Write-Error "Unable to download web archive from $Url to $FilePath. HTTP Status: $($FileReq.StatusDescription)Canceling download"
                    return
                }
            }
            catch {
                Write-Error "Unable to download web archive from $Url to $FilePath. Error: $_   Canceling download"
                return
            }
        }
    }
    if (Test-Path -ErrorAction SilentlyContinue $InstallPath -PathType Leaf) {
        Write-Verbose "Warning! Install Path not empty: $InstallPath `n Attempting to overwrite anyway."
        # Remove-Item $InstallPath -Recurse -Force
    }
    $tooVerbose=Expand-Archive -LiteralPath $FilePath -DestinationPath $InstallPath -Force
    Write-Verbose "Expand-Archive: $tooVerbose"
}
function Convert-HashtableToString {
    param (
        [Parameter(Mandatory = $true)][System.Collections.Hashtable] $Hashtable
    )
    $buildString = "@{"
    foreach ($key in $Hashtable.keys) {
        $val = $Hashtable[$key]
        if ($key -match "\s") {
            $buildString += "`"$key`"" + "=" + "`"$val`"" + ";"
        }
        else {
            $buildString += $key + "=" + "`"$val`"" + ";"
        }
    }
    $buildString += "}"
    return $buildString
}
function Install-NugetPackage {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $packageName,
        [string] $version,
        [string] $packageSource = "https://www.myget.org/F/ed-fi/",
        [string] $FilePath = "C:\Ed-Fi\Downloads",
        [string] $LogPath = "C:\Ed-Fi\Logs"
    )
    # Verify that the Downloads folder is present
    if (! $(Try { Test-Path -ErrorAction SilentlyContinue $FilePath } Catch { $false }) ) {
        $tooVerbose = New-Item -ItemType Directory -Force -Path $FilePath
    }    
    $downloadedPackagePath = Join-Path $FilePath "$packageName.$version"
    if (!(Get-Command "nuget.exe" -ErrorAction SilentlyContinue)) {
        Install-Choco "nuget.commandline"
        if(!(Test-Path -ErrorAction SilentlyContinue "C:\ProgramData\chocolatey\bin\nuget.exe")) {
            return "Error: Git not installed!"
        }
        else {
            $Env:Path += ";C:\ProgramData\chocolatey\bin"
            if ($null -eq (Get-Command "nuget.exe" -ErrorAction SilentlyContinue)) {
                return "Error: Failed to install Nuget"
            }
        }
    }
    $nugetPath=$(Get-Command "nuget.exe").Source
    $nugetCMD=Start-Process -Wait -FilePath $nugetPath -NoNewWindow -ArgumentList "install $packageName","-source $packageSource","-Version $version","-outputDirectory $FilePath","-NoCache" -RedirectStandardOutput "$LogPath\nuget_$($version)_log.txt" -RedirectStandardError "$LogPath\nuget_$($version)_err.txt"
    if ($nugetCMD.ExitCode -ne 0) {
        throw "Failed to install package $packageName $version"
    }
    return $downloadedPackagePath
}
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
# Ensure all prerequisites are installed.
# Region: Self Signed Certificate Functions
function Get-SelfSignedCertificate {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [string] $DnsName,
        [string] $CertName="localhost Self-Signed",
        [string] $FilePath="C:\Ed-Fi"
    )
    # Verify that the file folder is present
    if (! $(Try { Test-Path -ErrorAction SilentlyContinue $FilePath } Catch { $false }) ) {
        $tooVerbose = New-Item -ItemType Directory -Force -Path $FilePath
    }    
    # Returns the Certificate Thumbprint if successful
    # Stores Self-Signed Cert in Cert:\LocalMachine\My and then in Cert:\LocalMachine\Root to avoid problems with invalid cert chains
    # See if we already have it installed.
    $certificates = Get-ChildItem Cert:\LocalMachine\My
    foreach($cert in $certificates) {
        if ($cert.FriendlyName -eq $CertName) { 
            Write-Verbose "Found Self-Signed Cert Thumbprint: $($cert.Thumbprint)"
            return $cert
        }
    }
    #Create self signed certificate
    $hostnames = @("localhost")
    if (!([string]::IsNullOrEmpty($DnsName) -or ($DnsName -eq "localhost"))) {
        $hostnames += $DnsName
    }
    $cert = New-SelfSignedCertificate -DnsName $hostnames -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName $CertName -NotAfter $((Get-Date).AddYears(10)) -KeyExportPolicy 'Exportable' -KeyFriendlyName $CertName -KeyDescription "Self-signed certificate for localhost"
    $rootStore = new-object system.security.cryptography.X509Certificates.X509Store -argumentlist "Root", LocalMachine
    $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]"ReadWrite")
    $rootStore.Add($cert)
    Write-Verbose "Created Self-Signed Cert with Thumbprint: $($cert.Thumbprint)"
    return $cert
}
function Get-LetsEncSSLCert {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $DnsName,
        $CertName="Ed-Fi Solution Installer",
        $AdminEmail="techsupport@ed-fi.org",
        [string]$LogPath = "C:\Ed-Fi\Logs"
    )
    # Check for existing certificate first
    $certificates = Get-ChildItem Cert:\LocalMachine\WebHosting
    foreach($cert in $certificates) { 
        if($cert.Subject -eq "CN=$DnsName") { 
            $cert.FriendlyName=$CertName
            Write-Verbose "Found SSL Cert for $DnsName with Thumbprint: $($cert.Thumbprint)"
            return $cert
        } 
    }
    if (!(Get-Command "wacs" -ErrorAction SilentlyContinue)) {
        Install-Choco "win-acme"
    }
    try {
        # The Win-Acme client will do all of the work of calling the API, storing the certificate,
        # and adding it to the matching host entry in IIS
        Start-Process "wacs" -Wait -ArgumentList "--target iis --host $DnsName --accepttos --emailaddress $AdminEmail" -RedirectStandardOutput "$LogPath\winacme_ssl_cert_log.txt" -RedirectStandardError "$LogPath\winacme_ssl_cert_err.txt"
        Write-Verbose "Windows Acme Client Services completed SSL certificate request.`nCheck WACS log files for more info:`nwinacme_ssl_cert_log.txt`nwinacme_ssl_cert_err.txt"
    }
    catch {
        Write-Error "WACS failed to generate a certifcate from Lets Encrypt.  Error: $_ "
        return $null
    }
    $certificates = Get-ChildItem Cert:\LocalMachine\WebHosting
    if ($null -eq $certificates) {
        return $null
    }
    foreach($cert in $certificates) { 
        Write-Verbose "Found SSL Cert with Thumbprint: $($cert.Thumbprint)"
        if($cert.Subject -eq "CN=$DnsName") { 
            $cert.FriendlyName=$CertName
            Write-Verbose "Generated SSL Cert for $DnsName with Thumbprint: $($cert.Thumbprint)"
            return $cert
        }
    }
    return $null
}
function Get-SiteSSLCertificate {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [string] $DnsName,
        $iisConfig = @{ iisUser="IIS_IUSRS"; defaultSiteName="Default Web Site"; SiteName="Default Web Site"; defaultApplicationPool = "DefaultAppPool"; applicationPool = "DefaultAppPool"; integratedSecurityUser = "IIS APPPOOL\DefaultAppPool" }
    )
    $defaultSiteName = $iisConfig.defaultSiteName
    $SiteName = $iisConfig.SiteName
    $httpsBinding = $null
    if ([string]::IsNullOrEmpty($DnsName) -or ($DnsName -like "localhost*")) {
        $DnsName = "localhost"
    }
    # Check for a different Site Name than default
    if ([string]::IsNullOrEmpty($SiteName)) {
        # Must use default site name on localhost to avoid breaking things
        $SiteName = $defaultSiteName
        Write-Verbose "Using default (existing) IIS site: $SiteName"
    }
    # Look for and return an existing SSL binding for the given site name
    try {
        if ($httpsBinding=Get-IISSiteBinding -Name $SiteName -Protocol "https") {
            return $httpsBinding.CertificateHash
        }    
    }
    catch {
        Write-Verbose "`nIIS not yet configured for https on $SiteName `n"
        return $null
    }
}
function Enable-WebServerSSL {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [string] $InstallPath,
        [string] $HostDNS,
        [string] $AdminEmail = 'techsupport@ed-fi.org',
        $iisConfig = @{ iisUser="IIS_IUSRS"; defaultSiteName="Default Web Site"; SiteName="Ed-Fi"; defaultApplicationPool = "DefaultAppPool"; applicationPool = "DefaultAppPool"; integratedSecurityUser = "IIS APPPOOL\DefaultAppPool" }
    )
    $defaultSiteName = $iisConfig.defaultSiteName
    $SiteName = $iisConfig.SiteName
    $iisSite = $null
    $httpsBinding = $null
    Set-Location $InstallPath    
    if ([string]::IsNullOrEmpty($HostDNS) -or ($HostDNS -like "localhost*")) {
        $HostDNS = "localhost"
        # Must use default site name on localhost to avoid breaking things
        $SiteName = $defaultSiteName
        Write-Verbose "Using default (existing) IIS site: $SiteName"
    }
    # Check for a different Site Name than default
    if ([string]::IsNullOrEmpty($SiteName)) {
        $SiteName = $defaultSiteName
        Write-Verbose "Using default (existing) IIS site: $SiteName"
    }
    # Look for and return an existing SSL binding for the given site name
    try {
        if ($httpsBinding=Get-IISSiteBinding -Name $SiteName -Protocol "https" -ErrorAction SilentlyContinue) {
            Write-Verbose "`nIIS is already configured for https on $SiteName as $httpsBinding.`n  Quitting without changing SSL for IIS.`n"
            return $SiteName
        }    
    }
    catch {
        Write-Verbose "`nIIS not yet configured for https on $SiteName `n  Checking for IIS Site first.`n"
    }
    # No SSL binding found
    while ($null -eq $iisSite) {
        try {
            $iisSite=Get-IISSite $SiteName
        }
        catch {
            Write-Verbose "Site Name: $SiteName not found.`n  Creating new IIS Site."
        }
        if ($null -eq $iisSite) {
            try {
                $iisSite=New-IISSite -Name $SiteName -BindingInformation "*:80:$HostDNS" -PhysicalPath "$InstallPath\www"
            }
            catch {
                if ($SiteName -eq $defaultSiteName) { 
                    throw "No IIS $defaultSiteName `n  Unable to configure IIS for HTTP or HTTPS." 
                }
                Write-Verbose "Unable to create IIS Site Name: $SiteName `n  Switching to default site name: $defaultSiteName and trying again."
                $SiteName=$defaultSiteName
            }
        }
        else {
            Write-Verbose "Found existing IIS Site named: $SiteName at:$iisSite"
        }
    }
    #
    # Configure IIS to use Lets Encrypt SSL Cert or Self-Signed, if needed
    #
    # Get self-signed certificate for localhost needs
    $selfSignedCert = Get-SelfSignedCertificate -DnsName $HostDNS -CertName "localhost Self-Signed" -FilePath $InstallPath -Verbose:$VerbosePreference
    $newCert=$null
    $certStoreLocation = "Cert:\LocalMachine\WebHosting"
    # In case you passed in some variant of localhost somehow, don't go tryin to create a cert for that, not even a little bit.
    if ($HostDNS -eq "localhost") {
        $certStoreLocation = "Cert:\LocalMachine\My"
        try {
            # Stop the IIS Site while we fix SSL
            Stop-IISSite -Name $SiteName -Confirm:$false
            Write-Verbose "Command:`n New-IISSiteBinding -name `"$SiteName`" -BindingInformation `"*:443:*`" -protocol https -CertStoreLocation $certStoreLocation -CertificateThumbPrint `"$($selfSignedCert.Thumbprint)`"`n"
            $httpsBinding = New-IISSiteBinding -name "$SiteName" -BindingInformation "*:443:*" -protocol https -CertStoreLocation $certStoreLocation -CertificateThumbPrint "$($selfSignedCert.Thumbprint)"
        }
        catch {
            Write-Error "Error while binding IIS to $SiteName on https for localhost with Certificate:$selfSignedCert.`n Error: $_"
        }
        finally {
            # Restart IIS Site
            Start-IISSite -Name $SiteName
        }
    }
    else {
        # If missing, add a binding to the given hostname in case the system does not recognize that name as being local yet .. to make sure the Acme client will work
        #  and it shouldn't break the usual wildcard entry 
        $httpsBinding=$null
        try {
            $httpsBinding=Get-IISSiteBinding -Name $SiteName -BindingInformation "*:80:$HostDNS"  -ErrorAction SilentlyContinue
        }
        catch {
            Write-Verbose "No binding for host:$HostDNS for site:$SiteName `n  Attempting to bind."
        }
        if ($null -eq $httpsBinding) {
            try {
                Stop-IISSite -Name $SiteName -Confirm:$false
                Write-Verbose "Command:`n New-IISSiteBinding -name `"$SiteName`" -BindingInformation `"*:80:$HostDNS`" -protocol http`n"
                $httpsBinding = New-IISSiteBinding -name $SiteName -BindingInformation "*:80:$HostDNS" -protocol "http"
            }
            catch {
                Write-Verbose "Warning:`n Failed to set IIS binding for $HostDNS on http.`n Attempting to get LE cert anyway `n  Exception was: $_ `n"
            }
            finally {
                # Restart IIS Site
                Start-IISSite -Name $SiteName
            }
        }
        else {
            Write-Verbose "Found binding for host:$HostDNS on site:$SiteName"
        }
        # Obtain a free Let's Encrypt cert for given hostname
        $newCert = Get-LetsEncSSLCert -DnsName $HostDNS -CertName "Ed-Fi Solution Installer" -AdminEmail $AdminEmail -Verbose:$VerbosePreference
        # Attach the cert to port 443 on the given siteName # In case of a null cert from silent fail, we'll try to bind anyway with Self-Signed
        if ($null -ne $newCert) {
            try {
                Stop-IISSite -Name $SiteName -Confirm:$false
                Write-Verbose "Command:`n New-IISSiteBinding -name $SiteName -BindingInformation `"*:443:$HostDNS`" -protocol https -CertificateThumbPrint `"$($newCert.Thumbprint)`"  -CertStoreLocation $certStoreLocation`n"
                $httpsBinding = New-IISSiteBinding -name $SiteName -BindingInformation "*:443:$HostDNS" -protocol https -CertificateThumbPrint "$($newCert.Thumbprint)"  -CertStoreLocation $certStoreLocation
            }
            catch {
                Write-Error "Error while binding IIS to $SiteName on https for $HostDNS with Certificate:$($newCert.Thumbprint) `n Error: $_ `n"
            }
            finally {
                # Restart IIS Site
                Start-IISSite -Name $SiteName
            }
            if ($defaultSiteName -ne $SiteName) {
                # Now add trusted self-signed cert to localhost, may require some manual re-map in IIS Manager. 
                $certStoreLocation = "Cert:\LocalMachine\My"
                Write-Verbose "Command:`n New-IISSiteBinding -name $defaultSiteName -BindingInformation `"*:4443:localhost`" -protocol https -CertificateThumbPrint `"$($selfSignedCert.Thumbprint)`"  -CertStoreLocation $certStoreLocation`n"
                try {
                    $httpsBinding = New-IISSiteBinding -name $defaultSiteName -BindingInformation "*:4443:localhost" -protocol https -CertificateThumbPrint "$($selfSignedCert.Thumbprint)"  -CertStoreLocation $certStoreLocation
                }
                catch {
                    Write-Error "Error while binding IIS to $defaultSiteName on https for $HostDNS with self-signed certificate:$($selfSignedCert.Thumbprint) `n"
                }
            }
            else {
                Write-Verbose "Self-signed certificate was generated but is not active with an IIS site.`n Use the IIS Manager to select bindings to use it with as needed."
            }
            #
            # Add SPN for new DNS entry so that the IIS Server can support Windows Auth on that domain name
            $spnCmd = Get-Command "setspn.exe"
            if ($null -ne $spnCmd) {
                Start-Process $spnCmd.Source -Wait -ArgumentList "-A","HTTP/$HostDNS",$iisConfig.integratedSecurityUser
            }
        }
        else {
            try{
                Write-Verbose "Warning:`n Couldn't get Let's Encrypt certificate, will fallback to using self-signed cert for all hostnames on Site Name: $SiteName`n  This may cause http to fail to redirect!`n"
                Stop-IISSite -Name $SiteName -Confirm:$false
                $certStoreLocation = "Cert:\LocalMachine\My"
                Write-Verbose "Command:`n New-IISSiteBinding -name `"$SiteName`" -BindingInformation `"*:443:*`" -protocol https -CertStoreLocation $certStoreLocation -CertificateThumbPrint `"$($selfSignedCert.Thumbprint)`"`n"
                $httpsBinding = New-IISSiteBinding -name "$SiteName" -BindingInformation "*:443:*" -protocol https -CertStoreLocation $certStoreLocation -CertificateThumbPrint "$($selfSignedCert.Thumbprint)"
            }
            catch {
                Write-Error "Error while binding IIS to $SiteName on https for * (all hosts) with self-signed certificate:$($selfSignedCert.Thumbprint) `n Error: $_ `n"
            }
            finally {
                # Restart IIS Site
                Start-IISSite -Name $SiteName
            }
        }
    }
    Write-Verbose "IIS is configured for https on $SiteName as $httpsBinding`n "
    return $SiteName
}
function Enable-TCPonSQLInstance {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param ([string] $SQLINST = 'MSSQLSERVER') 
    #
    # Enable TCP on the default SQL instance.
    #
    Write-Verbose "Enabling TCP access for SQL Server instance: $SQLINST"
    $WMI = New-Object ('Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer')
    # NEED to update and test with $SQLINST, hardcoded for now
    $URI = "ManagedComputer[@Name='" + (get-item env:\computername).Value + "']/ServerInstance[@Name='" + $SQLINST + "']/ServerProtocol[@Name='Tcp']"
    $TCPBinding = $WMI.GetSmoObject($URI)
    # Turn on by setting to true and Alter-ing
    $TCPBinding.IsEnabled = $true
    $TCPBinding.Alter()
}
function Set-WeakPasswordComplexity { 
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param ([string] $FilePath="C:\Ed-Fi")
     # Verify that the file folder is present
     if (! $(Try { Test-Path -ErrorAction SilentlyContinue $FilePath } Catch { $false }) ) {
        $tooVerbose = New-Item -ItemType Directory -Force -Path $FilePath
    }  
    Write-Verbose "Allowing weak password complexity on Windows to prevent SQL Server from failing to login."
    # We have to disable password complexity so that SQL connections don't fail with default passwords
    # We need to set a strong password before re-enabling in Group Policy Editor 
    $secfile="$FilePath\secpol.cfg"
    $secdb="c:\windows\security\local.sdb"
    secedit /export /cfg $secfile
    (Get-Content $secfile).replace("PasswordComplexity = 1", "PasswordComplexity = 0") | Out-File $secfile
    secedit /configure /db $secdb /cfg $secfile /areas SECURITYPOLICY
    Remove-Item -force $secfile -confirm:$false
}
function Install-SqlServerModule {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param()
    # This "global" prereq is needed even when the user has configured a postgres install
    # 
    # A check within the RestApi.Databases package used by Databases.psm1 mentions the SqlServer
    # module types prior to checking for "SqlServer" or "Postgres" engine mode. When database
    # installation packages adaquately deal with this prerequisite themselves, this can be removed.
    if (-not (Get-Module -ListAvailable -Name SqlServer -ErrorAction SilentlyContinue)) {
        Install-Module SqlServer -Force -AllowClobber -Confirm:$false
    }
    Import-Module SqlServer
    try {
        # Force it to use the right version
        (Get-Command Restore-SqlDatabase).ImplementingType.Assembly
    }
    catch {
        Write-Error "Problem loading correct SQL Server Management Objects for db Restore.  Error: $_ "
    }
}
function Add-SQLUser {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [ValidateNotNullOrEmpty()][string]$UserName,
        $SQLServerName="."                              # Local machine by default
    )
    try {
        $SQLServer = New-Object Microsoft.SqlServer.Management.Smo.Server $SQLServerName
        $SqlLogins = $SQLServer.Logins
        if ($SqlLogins.Count -lt 1) {
            Write-Error "Unable to read any SQL Server logins. Please check your access to the instance"
            return $false
        }
        if (!($SqlLogins.Contains($UserName))) {
            Write-Verbose "Adding Login for User: $UserName to SQL Server: $SQLServerName"
            $SqlUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $SQLServer,$UserName
            $SqlUser.LoginType = [Microsoft.SqlServer.Management.Smo.LoginType]::WindowsUser
            $SqlUser.PasswordPolicyEnforced = $false
            $SqlUser.Create()
            Write-Verbose "Added User: $UserName to Logins for SQL Server: $SQLServerName"
        }
        else {
            Write-Verbose "Login already exists for UserName:$UserName"
        }
    }
    catch {
        Write-Error "Failed to add user: $UserName to SQL Server: $SQLServerName`n`n Error: $_"
        return $false
    }
    return $true
}
function Update-SQLUser {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [ValidateNotNullOrEmpty()][string]$UserName,
        [ValidateNotNullOrEmpty()][string]$OldUserName,
        $SQLServerName="."                      # Local machine by default
    )
    $SQLServer = New-Object Microsoft.SqlServer.Management.Smo.Server $SQLServerName
    $SqlLogins = $SQLServer.Logins
    if ($SqlLogins.Count -lt 1) {
        Write-Error "Unable to read any SQL Server logins. Please check your access to the instance"
        return $false
    }
    $SqlUser = $SqlLogins | Where-Object { $_.name -like $UserName }
    if ($null -ne $sqlUser -and $SqlUser.Count -gt 0) {
        Write-Error "Attempting to rename UserName: $OldUserName is unable to complete because UserName: $UserName already in Logins."
        return $false
    }
    $SqlUser = $SqlLogins | Where-Object { $_.name -like $OldUserName }
    if ($null -ne $sqlUser -and $SqlUser.Count -gt 0) {
        try {
            Write-Verbose "Renaming previous UserName: $OldUserName to new UserName: $UserName on SQL Server: $SQLServerName"
            $SqlUser.Rename($NewName)
            Write-Verbose "Renamed User: $UserName for SQL Server: $SQLServerName"
        }
        catch {
            Write-Error "Failed to rename User: $OldUserName to $UserName on server: $SQLServerName`n  If you recently changed the host name, you may need to reboot first."
            return $false
        }
        return $true
    }
    else {
        Write-Verbose "UserName: $OldUserName not found in SQL Logins"
        return $false
    }
}
function Add-UserSQLRole {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [ValidateNotNullOrEmpty()][string]$UserName,
        [string] $IntegratedSecurityRole = 'sysadmin',     # Should this be less powerful?
        [string] $SQLServerName = "."                      # Local machine by default
    )
    try {
        $SQLServer = New-Object Microsoft.SqlServer.Management.Smo.Server $SQLServerName
        Write-Verbose "Adding $UserName to $IntegratedSecurityRole on SQL Server: $SQLServerName"
        $serverRole = $SQLServer.Roles | Where-Object {$_.Name -eq $IntegratedSecurityRole}
        $serverRole.AddMember($UserName)
        Write-Verbose "Added User: $UserName to Role: $IntegratedSecurityRole for SQL Server: $SQLServerName"
    }
    catch {
        Write-Error "Failed to add user: $UserName to SQL Server role: $IntegratedSecurityRole on server: $SQLServerName`n`n Error: $_"
    }
}
function Add-SQLIntegratedSecurityUser {
    [CmdletBinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [ValidateNotNullOrEmpty()][string] $UserName,
        [string] $IntegratedSecurityRole,
        [string] $SQLServerName
    )
    $success = Add-SQLUser -UserName $UserName -SQLServerName $SQLServerName -Verbose:$VerbosePreference
    Add-UserSQLRole -UserName $UserName -IntegratedSecurityRole $IntegratedSecurityRole -SQLServerName $SQLServerName -Verbose:$VerbosePreference
}
function Update-SQLIntegratedSecurityUser {
    [CmdletBinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [ValidateNotNullOrEmpty()][string] $UserName,
        [ValidateNotNullOrEmpty()][string] $ComputerName,
        [ValidateNotNullOrEmpty()][string] $PreviousComputerName,
        [string] $IntegratedSecurityRole,
        [string] $SQLServerName = "."
    )
    Write-Verbose "Updating UserName:$UserName from: $PreviousComputerName to: $ComputerName"
    if (!($ComputerName -like $PreviousComputerName) -and ($UserName -like "$PreviousComputerName\*")) {
        Write-Warning "Username: $UserName includes previous computer name:$PreviousComputerName `n   Removing computer name from user name"
        $UserName=$UserName -Replace "$PreviousComputerName\\(?<user>.*)",'${user}'
        Write-Warning " !!  Changing the hostname and SQL Server logins will require the system to be rebooted before initial use.  !!"
    }
    if ((!($UserName -like "$ComputerName\*")) -and ($UserName -like "*\*")) {
        Write-Error "UserName: $UserName includes a different domain than the computer name. `n   Cmdlet will not attempt to rename domain users."
    }
    else {
        $success=$false
        if (!($ComputerName -like $PreviousComputerName)) {
            $NewName = $UserName
            if ($UserName -like "$ComputerName\*") {
                $JustName = $Username -Replace "$ComputerName\\(?<user>.*)",'${user}'
                $OldName = "$PreviousComputerName\$JustName"
            }
            else {
                $OldName = "$PreviousComputerName\$UserName"
                $NewName = "$ComputerName\$UserName"
            }
            if (!($NewName -like $OldName)) {
                Write-Verbose "Updating UserName:$OldName to UserName:$NewName on server:$SQLServerName"
                $success = Update-SQLUser -UserName $NewName -OldUserName $OldName -SQLServerName $SQLServerName -Verbose:$VerbosePreference    
            }    
        }
        if (!$success) {
            Write-Verbose "Adding UserName:$UserName to server:$SQLServerName"
            $success = Add-SQLUser -UserName $UserName -SQLServerName $SQLServerName -Verbose:$VerbosePreference
        }
    }
    Add-UserSQLRole -UserName $UserName -IntegratedSecurityRole $IntegratedSecurityRole -SQLServerName $SQLServerName -Verbose:$VerbosePreference
}
function Install-MSSQLserverExpress {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [string] $FilePath="C:\Ed-Fi\Downloads",
        [string] $MSSQLEURL="https://download.microsoft.com/download/8/4/c/84c6c430-e0f5-476d-bf43-eaaa222a72e0/SQLEXPR_x64_ENU.exe",
        [string] $SQLINST="MSSQLSERVER"
    )
    # Verify that the file folder is present
    if (! $(try { Test-Path -ErrorAction SilentlyContinue $FilePath } Catch { $false })) {
        $tooVerbose = New-Item -ItemType Directory -Force -Path $FilePath
    }
    #
    if (Test-Path -ErrorAction SilentlyContinue "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL") {
        $sqlInstances = Get-ChildItem "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names"
        Write-Verbose "SQL Server installation found with instances:`n $($sqlInstances|ForEach-Object {$_.Property}) `n"
        # Get SQL Server PowerShell support from the PS Gallery
        Install-SqlServerModule
        # Ensure TCP Connectivity is enabled
        $SQLINST=$sqlInstances[0].Property
        Enable-TCPonSQLInstance -SQLINST $SQLINST
        return $SQLINST
    }
    # No SQL instances found so we'll Install MS SQL Server Express 2019 with our special install config ini file
    #
    $InstINI = "$FilePath\SQLExprConfig.ini"
    # First try Chocolatey
    Install-Choco -Packages "sql-server-express" -InstallArguments "/IACCEPTSQLSERVERLICENSETERMS /Q /INSTANCEID=$SQLINST /INSTANCENAME=$SQLINST /ConfigurationFile=$InstINI"
    if (Test-Path -ErrorAction SilentlyContinue "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL") {
        $sqlInstances = Get-ChildItem "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names"
        Write-Verbose "SQL Server installation found with instances:`n $($sqlInstances|ForEach-Object {$_.Property}) `n"
        # Get SQL Server PowerShell support from the PS Gallery
        Install-SqlServerModule
        # Ensure TCP Connectivity is enabled
        $SQLINST=$sqlInstances[0].Property
        Enable-TCPonSQLInstance -SQLINST $SQLINST
        return $SQLINST
    }
    Write-Verbose "SQL Server Express installation by Chocolatey failed.  Attempting to download and install directly."
    #
    $MSSEFILE = "$FilePath\SQLEXPR_x64_ENU.exe"
    $MSSEPATH = "$FilePath\SQLEXPR_x64_ENU"
    $MSSESETUP = "$MSSEPATH\setup.exe"
    # Download, unpack, and install while setting the default instance name - will probably need to periodically refreshed until choco install works 
    if (! $(try { Test-Path -ErrorAction SilentlyContinue $MSSEFILE } Catch { $false }) ) {
        try {
            Write-Verbose "Downloading $MSSQLEURL to $MSSEFILE"
            Write-Progress -Activity "Downloading SQL Server Express" -Status "1% Complete:" -PercentComplete 1;
            Invoke-WebRequest -Uri $MSSQLEURL -OutFile $MSSEFILE
        }
        catch {
            Write-Error "Failed to download SQL Server Express from $MSSQLEURL and store in $MSSEFILE  Check URL and permission on path.  Error: $_"
        }
    }
    if ( $(try { Test-Path -ErrorAction SilentlyContinue $MSSEFILE } Catch { $false } ) ) {
        if (! $(Try { Test-Path -ErrorAction SilentlyContinue  $MSSESETUP } Catch { $false } ) ) {
            Write-Verbose "  Start-Process $MSSEFILE -wait -ArgumentList `"/q`",`"/x:$MSSEPATH`" -RedirectStandardOutput $MSSEPATH\extract_log.txt -RedirectStandardError $MSSEPATH\extract_error_log.txt"
            Write-Progress -Activity "Decompressing SQL Server Express install package" -Status "30% Complete:" -PercentComplete 30;
            Start-Process $MSSEFILE -wait -ArgumentList "/q","/x:$MSSEPATH" -RedirectStandardOutput $MSSEPATH\extract_log.txt -RedirectStandardError $MSSEPATH\extract_error_log.txt
        }
    }
    if ($(Try { Test-Path -ErrorAction SilentlyContinue $MSSESETUP } Catch { $false })) {
        Write-Verbose " Start-Process $MSSESETUP -wait -WorkingDirectory $MSSEPATH -RedirectStandardOutput $MSSEPATH\setup_log.txt -RedirectStandardError $MSSEPATH\setup_error_log.txt -ArgumentList `"/IACCEPTSQLSERVERLICENSETERMS`",`"/Q`",`"/INSTANCEID=$SQLINST`",`"/INSTANCENAME=$SQLINST`",`"/ConfigurationFile=$InstINI`""
        Write-Progress -Activity "Installing SQL Server Express" -Status "60% Complete:" -PercentComplete 60;
        Start-Process $MSSESETUP -wait -ArgumentList "/IACCEPTSQLSERVERLICENSETERMS","/Q","/INSTANCEID=$SQLINST","/INSTANCENAME=$SQLINST","/ConfigurationFile=$InstINI" -WorkingDirectory $MSSEPATH -RedirectStandardOutput $MSSEPATH\setup_log.txt -RedirectStandardError $MSSEPATH\setup_error_log.txt
    }

    if (!(Test-Path -ErrorAction SilentlyContinue "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL")) {
        throw "SQL Server failed to install, installation canceled" 
    }
    #
    Write-Progress -Activity "SQL Server Express installed" -Status "80% Complete:" -PercentComplete 80;
    Update-SessionEnvironment
    #
    Write-Progress -Activity "Installing PowerShell modules for SQL Server" -Status "85% Complete:" -PercentComplete 85;
    Install-SqlServerModule
    #
    # Use freshly installed MS SQL Server
    Write-Progress -Activity "Enabling TCP on default SQL Server instance" -Status "95% Complete:" -PercentComplete 95;
    Enable-TCPonSQLInstance -SQLINST $SQLINST
    return $SQLINST
}
function Initialize-Postgresql {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param ()   
    #
    # Check the Postgres install
    $psqlHome=Get-Command "psql.exe" -ErrorAction SilentlyContinue | ForEach-Object {$_.Source -Replace "\\bin\\psql.exe", ""}
    if (!$psqlHome) {
        $psqlInstall = Get-ChildItem -Path "C:\Program Files\PostgreSQL\*" -ErrorAction SilentlyContinue | Sort-Object -Property @{expression='Name'; descending=$true}
        if (!$psqlInstall) {
            Install-Choco "postgresql"
            $psqlInstall = Get-ChildItem -Path "C:\Program Files\PostgreSQL\*" | Sort-Object -Property @{expression='Name'; descending=$true}
        }
        $psqlHome = "C:\Program Files\PostgreSQL\" + $psqlInstall.Name
    }

    if (-not (Test-Path -ErrorAction SilentlyContinue $psqlHome)) {
        throw "Required Postgres path not found: $psqlHome"
    }

    Write-Verbose "Prepending $psqlHome to the PATH."
    $env:Path = "$psqlHome\bin;" + $env:Path
    if (!$Env:PGDATA) { $Env:PGDATA = $psqlHome + "\data" }
    if (!$Env:PGLOCALEDIR) { $Env:PGLOCALEDIR = $psqlHome + "\share\locale" }
    if (!$Env:PGPORT) { $Env:PGPORT = "5432" }
}
function Set-PermissionsOnPath {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory=$True)]$FilePath, 
        [Parameter(Mandatory=$True)]$User, 
        [Parameter(Mandatory=$True)]$Perms,
        $Inheritance
        )
    try 
    {
        $ACL = Get-Acl $FilePath
        $Account = New-Object System.Security.Principal.NTAccount($User)
        $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
        $AccessControlType =[System.Security.AccessControl.AccessControlType]::Allow
        # Use default inheritance if none specified
        if ($null -eq $Inheritance) {
            $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        }
        else {
            if ($Inheritance -like "ObjectInherit") {
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                # We won't propagate the inheritance of those entries that are applied to this folder only
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit
            }
            elseif ($Inheritance -like "ContainerInherit") {
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
            }
            else {
                # Fallback: just apply this to the path given and block both inheritance and propagation
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit
            }
        }
        if ($Perms -like "NoAccess") {  # This is meant to Deny CRUD
            $FileSystemRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Synchronize
            # First we have to remove inheritance while copying the existing rules in
            $ACL.SetAccessRuleProtection($true,$true)
            # Then, make that permanent before reloading the ACL
            Set-Acl $FilePath $ACL
            $ACL = Get-Acl $FilePath
            # This is mostly unused in a remove all except for the Account: 
            $FileSystemAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Account, $FileSystemRights, $InheritanceFlag, $PropagationFlag, $AccessControlType)
            # Now simply remove all ACL entries for this user/group
            $ACL.RemoveAccessRuleAll($FileSystemAccessRule)
        }
        else {
            $FileSystemRights = [System.Security.AccessControl.FileSystemRights]$Perms
            $FileSystemAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Account, $FileSystemRights, $InheritanceFlag, $PropagationFlag, $AccessControlType)
            $ACL.SetAccessRule($FileSystemAccessRule) # or $ACL.AddAccessRule($FileSystemAccessRule)
        }
        Set-Acl $FilePath $ACL
        Write-Verbose "Set permissions on path: $FilePath for user: $User to: $Perms"
    }
    catch {
        Write-Error "Unable to add user: $User to path: $FilePath with permissions: $Perms`n Error: $_"
    }
}
function Add-DesktopAppLinks {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        $AppURIs,
        $solName=$null
    )
    # Example of what to pass in
    # $AppLinks = @( 
    #               @{ name= "Link to a file"; type= "File"; URI="relative\\path\\file.ext" };
    #               @{ name= "WebLnk"; type= "URL"; URI="https://github.com/Ed-Fi-Alliance-OSS/Ed-Fi-ODS-AdminApp" }
    #             )
    #
    # Get Public Desktop to install links to Apps
    Write-Verbose "Adding Solution Links to Ed-Fi Solutions Folder on common Desktop"
    $pubDesktop=[Environment]::GetFolderPath("CommonDesktopDirectory")
    $EdFiSolFolder="$pubDesktop\Ed-Fi Solutions"
    if ($null -ne $solName) {
        $EdFiSolFolder="$pubDesktop\Ed-Fi Solutions\$solName"
    }
    $WScriptShell = New-Object -ComObject WScript.Shell
    if (! $(Try { Test-Path -ErrorAction SilentlyContinue $EdFiSolFolder } Catch { $false }) ) {
        $tooVerbose = New-Item -ItemType Directory -Force -Path $EdFiSolFolder 
    }
    # Add URLs to public desktop
    foreach ($appInstall in $AppURIs | Where-Object {$_.type -eq "URL"}) {
        $Shortcut = $WScriptShell.CreateShortcut("$EdFiSolFolder\$($appInstall.name).url")
        $targetURL = $appInstall.URI
        if (!($targetURL -like "http*")) {
            $targetURL = $targetURL -Replace "^","https://localhost/"
        }
        $Shortcut.TargetPath = $targetURL
        $Shortcut.Save()
    }
    # Add File Links to public desktop, these can be regular files or programs
    foreach ($appInstall in $AppURIs | Where-Object {$_.type -eq "File"}) {
        $Shortcut = $WScriptShell.CreateShortcut("$EdFiSolFolder\$($appInstall.name).lnk")
        $Shortcut.TargetPath = $appInstall.URI
        $Shortcut.Save()
    }
    # Add File Links to public desktop, these can be regular files or programs
    foreach ($appInstall in $AppURIs | Where-Object {$_.type -eq "App"}) {
        $Shortcut = $WScriptShell.CreateShortcut("$EdFiSolFolder\$($appInstall.name).lnk")
        $Shortcut.TargetPath = "$($appInstall.command) $($appInstall.appfile)"
        $Shortcut.Save()
    }
}
    function Add-WebAppLinks {
        [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
        param (
            $AppURIs,
            $DnsName="localhost",
            $SolutionName="Ed-Fi Tools",
            $WebPath="C:\Ed-Fi\www"
        )
        # Example of what to pass in
        # $appURLs = @( 
        #               @{ name= "Link to a file"; type= "File"; URI="relative\\path\\file.ext" };
        #               @{ name= "WebLnk"; type= "URL"; URI="https://github.com/Ed-Fi-Alliance-OSS/Ed-Fi-ODS-AdminApp" }
        #             )
        #
        Write-Verbose "Adding Solution Links to Ed-Fi Solutions website for local IIS homepage"
        $solHtmlFile="$WebPath\SolutionItems.html"
        if (! $(Try { Test-Path $solHtmlFile -ErrorAction SilentlyContinue } Catch { $false }) ) {
            if (! $(Try { Test-Path $EdFiWebDir -ErrorAction SilentlyContinue } Catch { $false }) ) {
                $tooVerbose = New-Item -ItemType Directory -Force -Path $WebPath
            }
            Set-Content $solHtmlFile ""
        }
        $solHtmlSections=@("")
        
        # Add regular URLs to section
        foreach ($appInstall in $AppURIs) {
            if ($appInstall.type -eq "URL") {
                $solHtmlSections+="<li><a href=`"$($appInstall.URI)`">$($appInstall.name)</a></li>`n"
            } elseif ($appInstall.type -eq "File") {
                $solHtmlSections+="<li><a href=`"file:$($appInstall.URI)`">$($appInstall.name)</a></li>`n"
            } elseif ($appInstall.type -eq "App") {
                $solHtmlSections+="<li><a href=`"file:$($appInstall.appfile)`">$($appInstall.name)</a></li>`n"
            } else {
                Write-Verbose "App link with type: $($appInstall.type)"
            }
        }
        $solTemplate =@"
        <li class="accordion-item is-active" data-accordion-item> <a href="#" class="accordion-title">$SolutionName</a>
            <div class="accordion-content" data-tab-content>
            <p><span style="font-weight: 400;">
                <ul>
                    $solHtmlSections
                </ul>
                </span></p>
            </div>
        </li>
"@
        Add-Content $solHtmlFile $solTemplate
        Write-Debug $solTemplate
    }
    function Publish-WebSite {
        [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
        param (
            $SolutionWebDir="C:\Ed-Fi\www",
            $VirtualDirectoryName="EdFi",
            $AppName="EdFiSolutions",
            $iisConfig=@{ iisUser="IIS_IUSRS"; SiteName = "Default Web Site"; applicationPool = "DefaultAppPool"; integratedSecurityUser = "IIS APPPOOL\DefaultAppPool" }
        )
        Write-Verbose "Generating Ed-Fi Solutions website for local IIS homepage"
        $solutionsHtml="$SolutionWebDir\SolutionItems.html"
        $headerHtml="$SolutionWebDir\SolutionHeader.html"
        $footerHtml="$SolutionWebDir\SolutionFooter.html"
        $indexHtml="$SolutionWebDir\index.html"
        Set-PermissionsOnPath -FilePath $SolutionWebDir -User $iisConfig.iisUser -Perms "ReadAndExecute"
        Get-Content -Path $headerHtml | Set-Content $indexHtml
        Get-Content -Path $solutionsHtml | Add-Content -Path $indexHtml
        Get-Content -Path $footerHtml | Add-Content -Path $indexHtml
        if ($null -eq (Get-WebApplication -Name $AppName)) {
            $tooVerbose = New-WebVirtualDirectory -Site $iisConfig.SiteName -Name $VirtualDirectoryName -PhysicalPath $SolutionWebDir -Force
            $tooVerbose = New-WebApplication -Name $AppName  -Site "$($iisConfig.SiteName)\$VirtualDirectoryName" -PhysicalPath $SolutionWebDir -ApplicationPool $($iisConfig.applicationPool) -Force    
        }
    }
    function Update-MSEdgeAssociations {
        [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
        param (
            $EdFiDir="C:\Ed-Fi",
            [string]$LogPath = "C:\Ed-Fi\Logs"
            )
        $AppAssocFile="$EdFiDir\LocalAppAssociations.xml"
        Start-Process -Wait Dism.exe "/Online /Export-DefaultAppAssociations:$AppAssocFile" -RedirectStandardOutput "$LogPath\dism-exp-log.txt" -RedirectStandardError "$LogPath\dism-exp-err.txt"
        $AppAssociations=New-Object XML
        $AppAssociations.Load($AppAssocFile)
        $AppSelections = $AppAssociations.SelectNodes("/DefaultAssociations/Association[@Identifier=""http"" or @Identifier=""https"" or @Identifier="".htm"" or @Identifier="".html"" or @Identifier="".url""]")
        foreach ($node in $AppSelections) {
            $node.ProgID="MSEdgeHTM"
            $node.ApplicationName="Microsoft Edge"
        }
        $AppAssociations.save($AppAssocFile)
        Start-Process Dism.exe "/online /import-defaultappassociations:$AppAssocFile" -RedirectStandardOutput "$LogPath\dism-imp-log.txt" -RedirectStandardError "$LogPath\dism-imp-err.txt"
    }
    function Install-Solutions {
        [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
        param (
            $Solutions,
            $DnsName,
            $GitPrefix,
            $DownloadPath,
            $WebPath,
            $EdFiDir="C:\Ed-Fi"
            )
        # Ex: Install-Solutions -Solutions $solutionsInstall -DnsName $DnsName -GitPrefix $GitPrefix -DownloadPath $downloadPath -WebPath $SolutionsWebRoot -EdFiDir $EdFiDir
        if ([string]::IsNullOrEmpty($WebPath)) {
            $WebPath="$EdFiDir\www"
        }
        foreach ($sol in $Solutions) {
            if ($sol.name -like "base*") {
                $sol.name="Ed-Fi Solution Starter Kit base"
            }
            Write-Verbose "Installing $($sol.name)"
            if (!([string]::IsNullOrEmpty($sol.chocoPackages))) {
                Install-Choco $sol.chocoPackages -Verbose:$VerbosePreference
            }
            if (!([string]::IsNullOrEmpty($sol.repo))) {
                if (!($sol.repo -like "http*")) {
                    $repoURL="https://$($GitPrefix)@$($sol.repo)"
                }
                else {
                    $repoURL=$sol.repo
                }
                Write-Verbose "Cloning solution repo from: $repoURL"
                Set-Location $EdFiDir
                Copy-GitRepo $repoURL $sol.installSubPath  -Verbose:$VerbosePreference   # Installs in subdir of current dir
            }
            if (!([string]::IsNullOrEmpty($sol.archive))) {
                Write-Verbose "Downloading solution arcive from: $($sol.archive) to $DownloadPath and extracting to $EdFiDir\$($sol.installSubPath)"
                Copy-WebArchive -Url $($sol.archive) -InstallPath "$EdFiDir\$($sol.installSubPath)" -DownloadsPath $DownloadPath -Verbose:$VerbosePreference
            }
            if(!(Test-Path -ErrorAction SilentlyContinue $sol.installSubPath)) {
                throw "Failed to install solution files! Check repo or archive settings`n Repo: $($sol.repo)`n Archive: $($sol.archive)"
            }
            if (!([string]::IsNullOrEmpty($sol.installer))) {
                # Pass in prefix and suffix to configure connections (db and API)
                & "$($sol.installSubPath)\$($sol.installer)" "Staging" $sol.EdFiVersion
            }
            foreach ($link in $sol.appLinks) {
                if ($link.type -eq "File") {
                    $link.URI = "$EdFiDir\$($sol.installSubPath)\$($link.URI)"
                }
                elseif (($link.type -eq "URL") -and !($link.URI -like "http*")) {
                    if ($link.URI -like "/*") {
                        $link.URI = $link.URI -Replace "^","https://$DnsName"
                    }
                    else {
                        $link.URI = $link.URI -Replace "^","https://$DnsName/"
                    }
                }
                elseif ($link.type -eq "App") {
                    $link.appfile = "$EdFiDir\$($sol.installSubPath)\$($link.appfile)"
                }
            }
            Add-DesktopAppLinks $sol.appLinks $sol.name -Verbose:$VerbosePreference
            # Add-WebAppLinks $sol.appLinks $sol.name $DnsName $SolutionWebRoot -Verbose:$VerbosePreference
            Add-WebAppLinks -AppURIs $sol.appLinks -DnsName $DnsName -SolutionName $sol.name -WebPath $WebPath -Verbose:$VerbosePreference
            Write-Verbose "Completed install of $($sol.name)"
        }
    }