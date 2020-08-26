[cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
param(
    [string] $config = "$PSScriptRoot\EdFiBaseConfig.json",
    [string] $solutions = "$PSScriptRoot\EdFiSolutionsConfig.json",
    [string] $DnsName,
    [string] $AdminEmail,
    [string] $DDNSUsername,
    [string] $DDNSPassword,
    [string] $EdFiDir,
    [string] $SolutionName
)
#Requires -Version 5
#Requires -RunAsAdministrator
Write-Verbose "Error action preference: $ErrorActionPreference"
#
# Some of these modules functions may need to be embedded directly until we can fetch the additional files from git
#
Import-Module "$PSScriptRoot\EdFiSolutionInstaller"
Import-Module "$PSScriptRoot\EdFiBinaryInstaller"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
#
$cfg = Get-Content $config | ConvertFrom-Json
$solcfg = Get-Content $solutions | ConvertFrom-Json
#
$EdFiDir = Get-ConfigParam $EdFiDir $cfg.EdFiDir "C:\Ed-Fi"
$downloadPath = Get-ConfigParam $null $cfg.DownloadPath "$EdFiDir\Downloads"
$SolutionWebRoot = Get-ConfigParam $null $cfg.SolutionWebRoot "$EdFiDir\www"
$DnsName = Get-ConfigParam $DnsName $cfg.DnsName "edfisolsrv"
$AdminEmail = Get-ConfigParam $AdminEmail $cfg.AdminEmail "techsupport@ed-fi.org"
$DDNSUsername = Get-ConfigParam $DDNSUsername $cfg.DDNSUsername
$DDNSPassword = Get-ConfigParam $DDNSPassword $cfg.DDNSPassword

# Totally insecure, I know.  Will need to work on this.
if (!([string]::IsNullOrEmpty($DDNSUsername) -or [string]::IsNullOrEmpty($DDNSPassword))) {
    [pscredential]$dynCredentials = New-Object System.Management.Automation.PSCredential $DDNSUsername,(ConvertTo-SecureString $DDNSPassword -AsPlainText -Force)
}
else {
    Write-Verbose "Either or both DDNSUsername and DDNSPassword are missing. Will skip Dynamic DNS update."
}
$SolutionsAppName = Get-ConfigParam $null $cfg.SolutionsAppName "Solutions"
# Ed-Fi Solution Builder Script for Windows Powershell
#
$GitPrefix = if (!([string]::IsNullOrEmpty($cfg.GitPAT))) {"$($cfg.GitPAT):x-oauth-basic"} else {"fcf5e80dbcf4d799efe01da2017f5add3af9bf55:x-oauth-basic"}
$hostOnly=$DnsName
if ($DnsName.IndexOf(".") -gt 1) {
    $hostOnly = $DnsName.Substring(0,$DnsName.IndexOf("."))
}
# $MSSQLEURL = if ($cfg.MSSQLEURL) {$cfg.MSSQLEURL} else {'https://download.microsoft.com/download/8/4/c/84c6c430-e0f5-476d-bf43-eaaa222a72e0/SQLEXPR_x64_ENU.exe'}
$MSSQLEURL = 'https://download.microsoft.com/download/8/4/c/84c6c430-e0f5-476d-bf43-eaaa222a72e0/SQLEXPR_x64_ENU.exe'
$SQLINST = Get-ConfigParam $null $cfg.MSSQLINST "MSSQLSERVER"
$PGSQLInstalled = $false
$iisConfig=@{               # Can be overridden but must include these 4 definitions
    iisUser="IIS_IUSRS";
    defaultSiteName="Default Web Site";
    applicationPool = "DefaultAppPool";
    integratedSecurityUser = "IIS APPPOOL\DefaultAppPool" }
#
# Install type is typically Staging for Populated Template ODS or Prodution for Minimal Template
$installType = Get-ConfigParam $null $cfg.installType "Staging"
Write-Verbose "Configuration params:`nEd-Fi Dir:`"$EdFiDir`"`ndownloadPath:`"$downloadPath`"`nSolutionWebRoot:`"$SolutionWebRoot`"`nDnsName:`"$DnsName`"`nAdminEmail:`"$AdminEmail`"`nDDNSUsername:`"$DDNSUsername`"`nDDNSPassword:`"$DDNSPassword`"`nSolutionsAppName:`"$SolutionsAppName`"`nGitPrefix:`"$GitPrefix`"`nSQLINST:`"$SQLINST`"`ninstallType:`"$installType`""
#
# Get our working directories, logs, and basic security settings
#
if (! $(Try { Test-Path $downloadPath.trim() } Catch { $false }) ) {
    New-Item -ItemType Directory -Force -Path $downloadPath
}
if (! $(Try { Test-Path "$SolutionWebRoot\*.html" } Catch { $false }) ) {
    # Relocate downloaded www directory only if no html files are present locally
    if ($(Try { Test-Path "$PSScriptRoot\www" } Catch { $false })) {
        Move-Item -Path "$PSScriptRoot\www" -Destination $SolutionWebRoot -Force
    }
}
Set-Location $EdFiDir
Start-Transcript -Path "$EdFiDir\solution-install.log"
#
# Get the hostname right
if (!("$Env:ComputerName" -like $hostOnly)) {
    Rename-Computer -NewName "$hostOnly" -Force
    Write-Verbose "Computer renamed to $hostOnly"
}
#
# Enable Windows features - Must haves
Enable-RequiredWindowsFeatures -Verbose:$VerbosePreference
Write-Verbose "Windows Features enabled"
#
# Install all core dependencies and important tools with Chocolatey Package Manager
#  can be tweaked in config as needed but all are required to be installed
$tooVerbose=Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force  -Verbose:$VerbosePreference
Write-Verbose "$tooVerbose"
Write-Verbose "Nuget package provider installed"
Install-Choco $cfg.dotnetcorePackage.package -Version $cfg.dotnetcorePackage.version  -Verbose:$VerbosePreference
Write-Verbose "Installed Package: $($cfg.dotnetcorePackage.package) Version: $($cfg.dotnetcorePackage.version)"
Install-Choco $cfg.baseChocoPackages  -Verbose:$VerbosePreference
Write-Verbose "Installed Packages $($cfg.baseChocoPackages)"
# Configure public DNS hostname and use it to get Lets Encrypt SSL Cert 
$hostIP=Get-ExternalIP -Verbose:$VerbosePreference
Write-Verbose "Host IP: $hostIP"
if (!([string]::IsNullOrEmpty($DnsName) -and ("edfisolsrv" -ne $DnsName))) {
    # Setting a hosts entry for the given name on loopback IP address to bypass DNS
    $hostsFilePath = "$($Env:WinDir)\system32\Drivers\etc\hosts"
    $hostsFile = Get-Content $hostsFilePath
    $escapedHostname = [Regex]::Escape($DnsName)
    $loopbackIP="127.0.0.1"
    if (!(($hostsFile) -match ".*$loopbackIP\s+$escapedHostname.*")) {
        Add-Content -Encoding UTF8  $hostsFilePath ("$loopbackIP".PadRight(20, " ") + "$DnsName")
    }
    Write-Verbose "Loopback address mapping to $DnsName added to Hosts file"
    #
    # Add hosts entries for all local ip addresses mapped to given name
    #$localIPAddresses = Get-NetIPAddress -AddressState Preferred -AddressFamily IPv4 | Select-Object IPAddress
    #foreach ($localIP in $localIPAddresses) {
    #    if (!(($hostsFile) -match ".*$localIP\s+$escapedHostname.*")) {
    #        Add-Content -Encoding UTF8  $hostsFilePath ("$localIP".PadRight(20, " ") + "$HostDNS")
    #    }
    #}
    #
    # Now update Dynamic DNS if credentials supplied
    if ($null -ne $dynCredentials) {
        Update-DynDNS -HostDNS $DnsName -IP $hostIP -Credentials $dynCredentials -Verbose:$VerbosePreference
        Start-Sleep -Seconds 2
        Write-Verbose "Dyn DNS name: $DnsName set to IP: $hostIP"
    }
}
else {
    # No DNS name given
    Write-Verbose "No proper DNS hostname given, setting DnsName to localhost"
    $DnsName = "localhost"
}
#
# Now install choice dependencies as listed in config, e.g. Postgres, and SQL Server Management Studio (SSMS)
# Note that SSMS is required if installing SQL Express
if (!([string]::IsNullOrEmpty($cfg.selectedChocoPackages))) { 
    Install-Choco $cfg.selectedChocoPackages -Verbose:$VerbosePreference
    $PGSQLInstalled = ([string]$cfg.selectedChocoPackages -like '*postgresql*')
    if ($PGSQLInstalled) {
        Initialize-Postgresql -Verbose:$VerbosePreference
        Write-Verbose "PostgreSQL installed and configured for use."
    }
}
#
# Install any additional user tools
#
if (!([string]::IsNullOrEmpty($cfg.optionalChocoPackages))) { 
    Install-Choco $cfg.optionalChocoPackages -Verbose:$VerbosePreference
    Write-Verbose "Installed packages: $($cfg.optionalChocoPackages)"
}
#
# Check and install SQL server if needed
$SQLINST = Install-MSSQLserverExpress -FilePath $downloadPath -MSSQLEURL $MSSQLEURL -SQLINST $SQLINST -Verbose:$VerbosePreference
Write-Verbose "SQL Server instance: $SQLINST"
#
# Get SSL working on IIS including Self-signed and LE certs
Enable-WebServerSSL -InstallPath $EdFiDir -HostDNS $DnsName -AdminEmail $AdminEmail -Verbose:$VerbosePreference
Write-Verbose "SSL configuration for IIS complete"
#
# Add IIS special integrated user to SQL Server login 
# Defaults: Add-IISUserSQLIntegratedSecurity -iisUser "IIS APPPOOL\DefaultAppPool" -IntegratedSecurityRole 'sysadmin' -SQLServerName "."
Add-UserSQLIntegratedSecurity -User $iisConfig.integratedSecurityUser
# Now get all of the Users group added to make this actually work
$LocalUsers=(Get-LocalGroupMember "Users" | Where-Object {$_.ObjectClass -match "User"}).Name
if (!(($null -eq $LocalUsers) -or ($LocalUsers.Count -eq 0)) {
    $LocalUsers | ForEach-Object { Add-UserSQLIntegratedSecurity -User $_ }
}
#
# Get the list of Solutions from the config file
$solutionsInstall = $solcfg.solutions | Where-Object {[string]::IsNullOrEmpty($SolutionName) -or $_.name -match $SolutionName}
if ($solutionsInstall.Count -eq 0) {
    Write-Verbose "No solutions found matching: $SolutionName `n Check your configuration file and verify the name given for -SolutionName."
    $SolutionName="base"
    $solutionsInstall = $cfg.solutions | Where-Object {$_.name -match $SolutionName}
}
# Select versions required by listed solutions
$EdFiVersions = $solutionsInstall | ForEach-Object {$_.EdFiVersion} | Sort-Object -Unique
# Now get needed versions of the ODS/API, Admin App, AMT, and Data Import installed
foreach ($ver in $EdFiVersions) {
    Write-Verbose "Installing Ed-Fi Suite with v$ver of ODS-API"
    Install-BaseEdFi $installType $ver $DnsName $EdFiDir $iisConfig -Verbose:$VerbosePreference
    Write-Verbose "Completed Ed-Fi Suite v$ver installation"
}
#
# Install current version of Data Import
Install-DataImport $EdFiDir $GitPrefix -Verbose:$VerbosePreference
Write-Verbose "Data Import NOT installed"
#
# Install all solutions listed
# Please edit the "solutions" section of the config file as needed
# Refer to Configuration guide:
foreach ($sol in $solutionsInstall) {
    if ($sol.name -eq "base") {
        $sol.name="Ed-Fi Solution Starter Kits"
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
        Copy-GitRepo $repoURL $sol.installSubPath  -Verbose:$VerbosePreference   # Installs in subdir of current dir
    }
    if (!([string]::IsNullOrEmpty($sol.archive))) {
        Write-Verbose "Downloading solution arcive from: $($sol.archive) to $downloadPath and extracting to $EdFiDir\$($sol.installSubPath)"
        Copy-WebArchive -Url $($sol.archive) -InstallPath "$EdFiDir\$($sol.installSubPath)" -DownloadsPath $downloadPath -Verbose:$VerbosePreference
    }
    if (!([string]::IsNullOrEmpty($sol.installer))) {
        # Pass in prefix and suffix to configure connections (db and API)
        & "$($sol.installSubPath)\$($sol.installer)" "Staging" $sol.EdFiVersion
    }
    foreach ($link in $sol.appLinks) {
        if ($link.type -eq "File") {
            $link.URI = "$EdFiDir\$($sol.installSubPath)\$($link.URI)"
        }
    }
    Add-DesktopAppLinks $sol.appLinks $sol.name -Verbose:$VerbosePreference
    # Add-WebAppLinks $sol.appLinks $sol.name $DnsName $SolutionWebRoot -Verbose:$VerbosePreference
    Add-WebAppLinks -AppURIs $sol.appLinks -DnsName $DnsName -SolutionName $sol.name -EdFiWebDir $SolutionWebRoot -Verbose:$VerbosePreference
    Write-Verbose "Completed install of $($sol.name)"
}
Write-Verbose "Building local web page for IIS on $SolutionWebRoot"
Publish-WebSite -SolutionWebDir $SolutionWebRoot -VirtualDirectoryName "EdFi" -AppName $SolutionsAppName -iisConfig $iisConfig -Verbose:$VerbosePreference
$LocalAppLinks = @(
    @{ name= "Ed-Fi Solutions Homepage"; type= "URL"; URI="/EdFi" }
    )
Add-DesktopAppLinks $LocalAppLinks ".."
Install-Module PSWindowsUpdate -Force
Add-WUServiceManager -MicrosoftUpdate -confirm:$false
$announcement = @"
***********************************************************************
*                                                                     *
* Your Ed-Fi Solution Installation is complete                        *
*                                                                     *
* See Solution installation details:                                  *
*                                                                     *
*   https://$DnsName/EdFi                                             *
*                                                                     *
* Beginning Windows Update to install security fixes/update in 10s    *
*  !!! Press CTRL-C to stop the update process !!!                    *
*                                                                     *
***********************************************************************
"@
Write-Host $announcement
if ($DnsName -eq $hostOnly) {
    Start-Process "https://localhost/EdFi"
}
else {
    Start-Process "https://$DnsName/EdFi"
}
Write-Verbose "Performing Windows Update"
Stop-Transcript
#
# Now force a full update
#
# Get-WindowsUpdate
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot
#
$announcement = @"
***********************************************************************
*                                                                     *
* Please reboot your system now to make sure all updates are applied  *
*                                                                     *
* Your Ed-Fi Solution Installation is complete                        *
*                                                                     *
* See Solution installation details:                                  *
*                                                                     *
*   https://$DnsName/$SolutionsAppName                                *
*                                                                     *
***********************************************************************
"@
Write-Host $announcement
