# SPDX-License-Identifier: Apache-2.0
# Licensed to the Ed-Fi Alliance under one or more agreements.
# The Ed-Fi Alliance licenses this file to you under the Apache License, Version 2.0.
# See the LICENSE and NOTICES files in the project root for more information.
#Requires -Version 5
#Requires -RunAsAdministrator
[cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
param(
    [string] $config = "$PSScriptRoot\config\EdFiBaseConfig.json",
    [string] $solutions = "$PSScriptRoot\config\EdFiSolutionsConfig.json",
    [string] $DnsName,
    [string] $AdminEmail,
    [string] $DDNSUrl,
    [string] $DDNSUsername,
    [string] $DDNSPassword,
    [string] $iisSiteName,
    [string] $InstallType,
    [string] $SolutionName,
    [string] $EdFiDir,
    [switch] $noui=$false
)
    <#
    .description
    The Ed-Fi Solution Installer prepares a single Windows environment, installs a complete Ed-Fi Suite of tools, and then installs the chosen solution and all listed pre-requisites.
    .parameter SolutionName
    A list of solution names, an empty string for all solutions, or "base" to install only a current Ed-Fi Suite
    .parameter InstallType
    The type of deployment to install: 'Demo' or 'Staging'
    .parameter AdminEmail
    An email address of the administrative contact.
    .parameter DnsName
    The DNS name chosen for this environment, or blank to use only localhost and self-signed certificates.
    .parameter DDNSUrl
    A provider URL for posting dynamic DNS updates from this system.
    .parameter DDNSUsername
    The Username required to authenticate with dynamic DNS provider.
    .parameter DDNSPassword
    The Username required to authenticate with dynamic DNS provider.
    .parameter iisSiteName
    Name to use for the IIS site of web apps to install, will be created if it doesn't exist.
    .parameter dbPassword
    Password to set for native database logins on PostgreSQL and MS SQL Server Express.
    .parameter config
    A JSON-formatted file containing configuration parameters. Any parameters listed on the command line will override parameters in this file. <See the Config.md for more info>.
    .parameter solutions
    A JSON-formatted list of solutions to install from. <See the Config.md for more info>.

    .EXAMPLE
    install.ps1 -DnsName "my.domain.org" -AdminEmail "admin@domain.org" -DDNSUrl "https://dynamicdns.com?name={DnsName}&ip={IP}" -DDNSUsername name -DDNSPassword "pass" -SolutionName <see solution config for list of names> -InstallDemo "Demo|Staging"
    #>

Write-Verbose "Error action preference: $ErrorActionPreference"
if ($noui) {
    $ProgressPreference = "SilentlyContinue"
    $ConfirmPreference = "None"
}
#
# Some of these modules functions may need to be embedded directly until we can fetch the additional files from git
#
Import-Module "$PSScriptRoot\modules\edfi-installconfig"
Import-Module "$PSScriptRoot\modules\edfi-netsetup"
Import-Module "$PSScriptRoot\modules\edfi-websetup"
Import-Module "$PSScriptRoot\modules\edfi-dbsrvsetup"
Import-Module "$PSScriptRoot\modules\EdFiSolutionInstaller"
Import-Module "$PSScriptRoot\modules\EdFiBinaryInstaller"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
#
$cfg = Get-Content $config | ConvertFrom-Json
$solcfg = Get-Content $solutions | ConvertFrom-Json
#
$EdFiDir = Get-ConfigParam $EdFiDir $cfg.EdFiDir "C:\Ed-Fi"
$downloadPath = Get-ConfigParam $null $cfg.DownloadPath "$EdFiDir\Downloads"
$SolutionWebRoot = Get-ConfigParam $null $cfg.SolutionWebRoot "$EdFiDir\www"
$LogPath = "$EdFiDir\Logs\install"
#
# Get our working directories, logs, and basic security settings
#
if (! $(Try { Test-Path $downloadPath -ErrorAction SilentlyContinue } Catch { $false }) ) {
    $tooVerbose = New-Item -ItemType Directory -Force -Path $downloadPath
}
# Copy installation ini files to downloads dir
Copy-Item -Path "$PSScriptRoot\config\*.ini" -Destination $downloadPath -Force
#
if (! $(Try { Test-Path "$SolutionWebRoot\*.html" -ErrorAction SilentlyContinue } Catch { $false }) ) {
    # Relocate downloaded www directory only if no html files are present locally
    if ($(Try { Test-Path "$PSScriptRoot\www" -ErrorAction SilentlyContinue } Catch { $false })) {
        Move-Item -Path "$PSScriptRoot\www" -Destination $SolutionWebRoot -Force
    }
}
if (! $(Try { Test-Path $LogPath -ErrorAction SilentlyContinue } Catch { $false }) ) {
    $tooVerbose = New-Item -ItemType Directory -Force -Path $LogPath
}
Set-Location $EdFiDir
Start-Transcript -Path "$LogPath\solution-install.log"
Write-Progress -Activity "Beginning installation" -Status "0% Complete:" -PercentComplete 0;
if (!$noui -and [string]::IsNullOrEmpty($SolutionName)) {
    $SolutionSelected=$solcfg.solutions | Select-Object name,Description,EdFiVersion,installSubPath,chocoPackages,repo | Out-GridView -OutputMode Single -Title "Select the solution you would like to install, or cancel for all"
    if (![string]::IsNullOrEmpty($SolutionSelected)) {
        $SolutionName = $SolutionSelected.name
    }
}

$DnsName = Get-ConfigParam $DnsName $cfg.DnsName
$AdminEmail = Get-ConfigParam $AdminEmail $cfg.AdminEmail "techsupport@ed-fi.org"
$DDNSUrl = Get-ConfigParam $DDNSUrl $cfg.DDNSUrl
$DDNSUsername = Get-ConfigParam $DDNSUsername $cfg.DDNSUsername
$DDNSPassword = Get-ConfigParam $DDNSPassword $cfg.DDNSPassword

# Totally insecure, I know.  Will need to work on this.
if (!([string]::IsNullOrEmpty($DDNSUsername) -or [string]::IsNullOrEmpty($DDNSPassword))) {
    [pscredential]$dynCredentials = New-Object System.Management.Automation.PSCredential $DDNSUsername,(ConvertTo-SecureString $DDNSPassword -AsPlainText -Force)
}
else {
    Write-Verbose "Either or both DDNSUsername and DDNSPassword are missing. Will skip Dynamic DNS update."
}
$SolutionsAppName = Get-ConfigParam $null $cfg.SolutionsAppName "EdFiSolutions"
# Ed-Fi Solution Builder Script for Windows Powershell
#
$GitPrefix = if (!([string]::IsNullOrEmpty($cfg.GitPAT))) {"$($cfg.GitPAT):x-oauth-basic"}
$OldComputerName="$Env:ComputerName"
$NewComputerName=$OldComputerName
if (!([string]::IsNullOrEmpty($DnsName))) {
    $NewComputerName=$DnsName
    if ($DnsName.IndexOf(".") -gt 1) {
        $NewComputerName = $DnsName.Substring(0,$DnsName.IndexOf("."))
    }
    else {
        Write-Warning "`nWARNING!  Removing given DnsName because the provided string has no periods and therefore cannot be a complete DNS name!`nContinuing without custom DNS name!`nPausing, use CTRL-C to cancel"
        Start-Sleep -Seconds 5
        $DnsName=$null
    }
}
# This can be updated in the config as MSSQLEURL as needed.
$MSSQLEURL = Get-ConfigParam $null $cfg.MSSQLEURL 'https://download.microsoft.com/download/8/4/c/84c6c430-e0f5-476d-bf43-eaaa222a72e0/SQLEXPR_x64_ENU.exe'
$SQLINST = Get-ConfigParam $null $cfg.MSSQLINST "MSSQLSERVER"
$MSSQLInstalled = $false
$PGSQLInstalled = $false
# Can be overridden but must include these definitions TODO: move to config file
$iisConfig=@{
    iisUser="IIS_IUSRS";
    defaultSiteName="Default Web Site";
    SiteName="Ed-Fi";
    defaultApplicationPool = "DefaultAppPool";
    applicationPool = "EdFiAppPool";
    integratedSecurityUser = "IIS APPPOOL\EdFiAppPool";
    defaultSecurityUser = "IIS APPPOOL\DefaultAppPool" 
}
$iisConfig.SiteName = Get-ConfigParam $iisSiteName $cfg.iisSiteName "Default Web Site"
#
# Install type is typically Staging for Populated Template ODS or Prodution for Minimal Template
$InstallType = Get-ConfigParam $InstallType $cfg.InstallType "Demo"
Write-Verbose "`n----------------`nConfiguration params:`nEd-Fi Dir:`"$EdFiDir`"`ndownloadPath:`"$downloadPath`"`nSolutionWebRoot:`"$SolutionWebRoot`"`nDnsName:`"$DnsName`"`nComputerName:`"$OldComputerName`"`nSuggestedComputerName:`"$NewComputerName`"`nAdminEmail:`"$AdminEmail`"`nDDNSUrl:`"$DDNSUrl`"`nDDNSUsername:`"$DDNSUsername`"`nDDNSPassword:`"$DDNSPassword`"`nSolutionsAppName:`"$SolutionsAppName`"`nGitPrefix:`"$GitPrefix`"`nSQLINST:`"$SQLINST`"`nInstallType:`"$InstallType`""
Write-Verbose "iisConfig: $(Convert-HashtableToString $iisConfig)`n----------------`n"
Write-Progress -Activity "Configuration parameters set. Adding DNS info to computer name..." -Status "1% Complete:" -PercentComplete 1;
#
# UI for options
#
#
#
if ($OldComputerName -notlike $NewComputerName) {
    $netdomCmd = (Get-Command "netdom.exe" -ErrorAction SilentlyContinue).Source
    Write-Warning "`nComputer name not like DNS name. Adding entry for DNS name to Windows Domain/Active Directory with netdom.exe `n  If you rename computer, be sure to update integrated security in database server.`n"
    Write-Verbose "To rename, use command: Rename-Computer -NewName `"$NewComputerName`" (-Force to force change)"
    Write-Verbose "Then, to add a DNS entry: $netdomCmd computername `"$NewComputerName`" /add:`"$DnsName`"`n"
    & $netdomCmd computername "$OldComputerName" /add:"$DnsName"
    Write-Verbose "Added DNS: $DnsName to WinDom/AD for Computer: $OldComputerName"
    $NewComputerName=$OldComputerName
}
Write-Progress -Activity "Computer name and DNS set. Installing required Windows Features..." -Status "2% Complete:" -PercentComplete 2;
#
# Enable Windows features - Must haves
Enable-RequiredWindowsFeatures -Verbose:$VerbosePreference
Write-Verbose "Windows Features enabled"
Write-Progress -Activity "Windows Features Enabled.  Installing nuget v2.8.5.201 ..." -Status "5% Complete:" -PercentComplete 5;

#
# Install all core dependencies and important tools with Chocolatey Package Manager
#  can be tweaked in config as needed but all are required to be installed
$tooVerbose=Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Verbose:$VerbosePreference
Write-Verbose "$tooVerbose"
Write-Verbose "Nuget package provider installed"
#
#
# Get the list of Solutions from the config file
#
Write-Progress -Activity "Nuget package installed. Discovering solutions and dependencies..." -Status "6% Complete:" -PercentComplete 6;
#
$solutionsInstall = $solcfg.solutions | Where-Object {([string]::IsNullOrEmpty($SolutionName) -and ($_.name -NotLike "base*")) -or ($_.name -match $SolutionName)}
Write-Verbose "Solution(s) chosen: $solutionsInstall"
if (($null -eq $solutionsInstall) -or ($solutionsInstall.Count -eq 0)) {
    if ($noui) {
        Write-Verbose "No solutions found matching: $SolutionName `n Check your configuration file and verify the name given for -SolutionName. `n Choosing base install and continuing."
        $SolutionName="base"
        $solutionsInstall = $solcfg.solutions | Where-Object {$_.name -match $SolutionName}    
        if ($null -eq $solutionsInstall) {
            throw "No Solutions Configured! Installation cannot continue please make sure your solutions configuration file is available."
        }
    }
    else {
        throw "Solution: $SolutionName not found!"
    }
}
# Select versions required by listed solutions
$EdFiVersions = $solutionsInstall | ForEach-Object {$_.EdFiVersion} | Sort-Object -Unique
#
# [System.Collections.Generic.List[PSCustomObject]]
[array]$preInstallPackages = Select-InstallPackages -globalPackages $cfg.preInstallPackages -solutions $solutionsInstall -sequence "pre" -Verbose:$VerbosePreference
[array]$dbInstallPackages = Select-InstallPackages -globalPackages $cfg.dbInstallPackages -solutions $solutionsInstall -sequence "db" -Verbose:$VerbosePreference
[array]$postInstallPackages = Select-InstallPackages -globalPackages $cfg.postInstallPackages -solutions $solutionsInstall -sequence "post" -Verbose:$VerbosePreference
if ($null -ne $preInstallPackages) {
    Write-Verbose "Pre-Install Packages:"
    foreach ($pkg in $preInstallPackages) { Write-Verbose $pkg }
}
else {
    Write-Verbose "No pre-install packages selected!"
}
# 
Write-Progress -Activity "Installing prereqisite software packages from Chocolatey..." -Status "7% Complete:" -PercentComplete 7;
Install-ChocolateyPackages -Packages $preInstallPackages -LogPath $LogPath -Verbose:$VerbosePreference
Write-Verbose "Installed Pre-installation Packages: $preInstallPackages"
Write-Progress -Activity "Essential software packages installed. Discovering IP address and updating Dynamic DNS (if enabled)" -Status "15% Complete:" -PercentComplete 15;
# Configure public DNS hostname and use it to get Lets Encrypt SSL Cert 
$hostIP=Get-ExternalIP -Verbose:$VerbosePreference
Write-Verbose "Host IP: $hostIP"
if (![string]::IsNullOrEmpty($DnsName) -and ($DnsName -ne "edfisolsrv")) {
    # Add the dns name to loopback address in servers hosts file to avoid any network vs web app config issues
    Add-NameToHostsFile $DnsName
    # Now update Dynamic DNS if credentials supplied   
    if ($null -ne $dynCredentials -and ![string]::IsNullOrEmpty($DDNSUrl)) {
        $updateDDNS=Update-DynDNS -HostDNS $DnsName -IP $hostIP -ProviderUrl $DDNSUrl -Credentials $dynCredentials -Verbose:$VerbosePreference
        if ($updateDDNS) {
            Start-Sleep -Seconds 2
            Write-Verbose "Dynamic DNS name: $DnsName set to IP: $hostIP"    
        }
        else {
            Write-Verbose "Dynamic DNS update failed.`n  You will need to update DNS manually and manually generate SSL certificates.`n "
        }
    }
}
else {
    # No DNS name given
    Write-Verbose "No proper DNS hostname given, setting DnsName to localhost"
    $DnsName = "localhost"
}
Write-Progress -Activity "IP Address assigned to Dynamic DNS. Installing database server packges from Chocolatey..." -Status "20% Complete:" -PercentComplete 20;
#
if ($null -ne $dbInstallPackages) {
    Write-Verbose "Db Install Packages:"
    foreach ($pkg in $dbInstallPackages) { Write-Verbose $pkg }
}
else {
    Write-Verbose "No db install packages selected!"
}
Write-Verbose "Install-ChocolateyPackages -Packages $dbInstallPackages -LogPath $LogPath -Verbose:$VerbosePreference"
Install-ChocolateyPackages -Packages $dbInstallPackages -LogPath $LogPath -Verbose:$VerbosePreference
foreach ($pkg in $dbInstallPackages) {
    $PGSQLInstalled = $PGSQLInstalled -or ($pkg.package -like "postgres*")
    $MSSQLInstalled = $MSSQLInstalled -or ($pkg.package -like "sql-server*")
}
if ($PGSQLInstalled) {
    Initialize-Postgresql -Verbose:$VerbosePreference
    Write-Verbose "PostgreSQL installed and configured for use."
}
if ($MSSQLInstalled) {
    $SQLINST=Get-MSSQLInstallation -Verbose:$VerbosePreference
    Write-Verbose "Microsoft SQL Server installed and ready for use."
}
#
# Check and install SQL server if needed
if ([string]::IsNullOrEmpty($SQLINST)) {
    Write-Verbose "Forcing SQL Server install ..."
    $SQLINST = Install-MSSQLserverExpress -FilePath $downloadPath -MSSQLEURL $MSSQLEURL -SQLINST $SQLINST -Verbose:$VerbosePreference
    Write-Verbose "SQL Server instance: $SQLINST"
}
#
Write-Progress -Activity "Database software packages installed." -Status "35% Complete:" -PercentComplete 35;
if ($InstallType -like "Demo") {
    # !!!!!
    # Weak passwords may not work for SQL Auth, so this step we'll weaken them on Demo machines.
    # This shouldn't be necessary for auto-generated passwords on most cloud provider builds
    # !!!!!
    Set-WeakPasswordComplexity -FilePath $downloadPath  -Verbose:$VerbosePreference
}
#
# Get SSL working on IIS including Self-signed and LE certs, will also setup new IIS Site and App Pool if specified.
# However, this returns the Site Name that was used (whether specified or default in case of trouble), so be sure and store that for later use.
$iisConfig.SiteName = Enable-WebServerSSL -InstallPath $EdFiDir -HostDNS $DnsName -AdminEmail $AdminEmail -iisConfig $iisConfig -Verbose:$VerbosePreference
Write-Verbose "IIS Site Name set to: $($iisConfig.SiteName)"
Write-Verbose "SSL configuration for IIS complete"
Write-Progress -Activity "IIS Configured for SSL" -Status "50% Complete:" -PercentComplete 50;
#
# Add IIS special integrated user to SQL Server login along with those in Users group for Demo mode
if (![string]::IsNullOrEmpty($SQLINST)) {
    Add-SQLIntegratedSecurityUser -UserName $iisConfig.integratedSecurityUser -IntegratedSecurityRole 'sysadmin' -SQLServerName "." -Verbose:$VerbosePreference
    # Now get all of the Users group (if Demo) members added to make this actually work
    if ($InstallType -like "Demo") {
        $LocalUsers=(@(Get-LocalGroupMember "Users") | Where-Object {$_.ObjectClass -like "User"}).Name
        foreach ($usr in $LocalUsers) {
            Update-SQLIntegratedSecurityUser -UserName $usr -ComputerName $NewComputerName -PreviousComputerName $OldComputerName -IntegratedSecurityRole 'sysadmin' -SQLServerName "." -Verbose:$VerbosePreference
        }
    }
    Write-Progress -Activity "Integrated Security configured" -Status "55% Complete:" -PercentComplete 55;    
}
#
# Now get needed versions of the ODS/API, Admin App, AMT, and Data Import installed
foreach ($ver in $EdFiVersions) {
    Write-Verbose "Installing Ed-Fi Suite with v$ver of ODS-API"
    Install-BaseEdFi $InstallType $ver $DnsName $EdFiDir $iisConfig -Verbose:$VerbosePreference
    Write-Verbose "Completed Ed-Fi Suite v$ver installation"
}
Write-Progress -Activity "Ed-FI Suite installed" -Status "60% Complete:" -PercentComplete 60;
#
# Install current version of Data Import
Install-DataImport $EdFiDir $GitPrefix -Verbose:$VerbosePreference
Write-Progress -Activity "Data Import" -Status "70% Complete:" -PercentComplete 70;
#
# Install all solutions listed
# Please edit the "solutions" section of the config file as needed
# Refer to Configuration guide:
Install-Solutions -Solutions $solutionsInstall -DnsName $DnsName -GitPrefix $GitPrefix -DownloadPath $downloadPath -EdFiDir $EdFiDir -WebPath $SolutionWebRoot -Verbose:$VerbosePreference
#
Write-Progress -Activity "Solutions installed" -Status "80% Complete:" -PercentComplete 80;
#
# Install any additional tools
#
if ($null -ne $postInstallPackages) {
    Write-Verbose "Post-Install Packages:"
    foreach ($pkg in $postInstallPackages) { Write-Verbose $pkg }
}
else {
    Write-Verbose "No post-install packages selected!"
}
Install-ChocolateyPackages -packages $postInstallPackages -LogPath $LogPath -Verbose:$VerbosePreference
#
# Look for MS Edge in the install to switch to it since IE is unworkable on Server
#
$MSEdgeInstalled = $false
foreach ($pkg in $preInstallPackages) {
    $MSEdgeInstalled = $MSEdgeInstalled -or ($pkg.package -like "*microsoft-edge*")
}
foreach ($pkg in $postInstallPackages) {
    $MSEdgeInstalled = $MSEdgeInstalled -or ($pkg.package -like "*microsoft-edge*")
}
if ($MSEdgeInstalled) {
    Write-Verbose "Found MS Edge, will use instead of IE"
    Update-MSEdgeAssociations -Verbose:$VerbosePreference
}
#
Write-Progress -Activity "Post-solution-install/optional software packages installed." -Status "90% Complete:" -PercentComplete 90;
#
Write-Verbose "Building local web page for IIS on $SolutionWebRoot"
Publish-WebSite -SolutionWebDir $SolutionWebRoot -VirtualDirectoryName "EdFi" -AppName $SolutionsAppName -iisConfig $iisConfig -Verbose:$VerbosePreference
$LocalAppLinks = @(
    @{ name= "Ed-Fi Solutions Homepage"; type= "URL"; URI="https://$DnsName/EdFi" }
    )
Add-DesktopAppLinks $LocalAppLinks ".."
Write-Verbose "Preparing for Windows Update"
Stop-Transcript
Install-Module PSWindowsUpdate -Force
Add-WUServiceManager -MicrosoftUpdate -confirm:$false
Write-Progress -Activity "Solution Homepage saved" -Status "95% Complete:" -PercentComplete 95;
Write-Verbose "Performing Windows Update"
#
# Now force a full update
#
# Get-WindowsUpdate
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot
Write-Progress -Activity "Updates installed" -Status "99% Complete:" -PercentComplete 99;

#
$announcement = @"
***************************************************************
*                                                             *
* Please reboot your system now to apply updates any updates  *
*                                                             *
* The Ed-Fi Solution Installation is complete                 *
*                                                             *
* See Solution installation packages here:                    *
*                                                             *
*   https://$DnsName/EdFi                                     *
*                                                             *
***************************************************************
"@
Write-Host $announcement
if ($DnsName -eq $NewComputerName) {
    Start-Process "https://localhost/EdFi"
}
else {
    Start-Process "https://$DnsName/EdFi"
}
