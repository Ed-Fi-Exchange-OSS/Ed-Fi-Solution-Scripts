[cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
param(
    [string] $config = "$PSScriptRoot\EdFiBaseConfig.json",
    [string] $solutions = "$PSScriptRoot\EdFiSolutionsConfig.json",
    [string] $DnsName,
    [string] $AdminEmail,
    [string] $DDNSUrl,
    [string] $DDNSUsername,
    [string] $DDNSPassword,
    [string] $InstallType,
    [string] $SolutionName,
    [string] $EdFiDir
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
#
# Get our working directories, logs, and basic security settings
#
if (! $(Try { Test-Path $downloadPath -ErrorAction SilentlyContinue } Catch { $false }) ) {
    $tooVerbose = New-Item -ItemType Directory -Force -Path $downloadPath
}
if (! $(Try { Test-Path "$SolutionWebRoot\*.html" -ErrorAction SilentlyContinue } Catch { $false }) ) {
    # Relocate downloaded www directory only if no html files are present locally
    if ($(Try { Test-Path "$PSScriptRoot\www" -ErrorAction SilentlyContinue } Catch { $false })) {
        Move-Item -Path "$PSScriptRoot\www" -Destination $SolutionWebRoot -Force
    }
}
Set-Location $EdFiDir
Start-Transcript -Path "$EdFiDir\solution-install.log"

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
$SolutionsAppName = Get-ConfigParam $null $cfg.SolutionsAppName "Solutions"
# Ed-Fi Solution Builder Script for Windows Powershell
#
$GitPrefix = if (!([string]::IsNullOrEmpty($cfg.GitPAT))) {"$($cfg.GitPAT):x-oauth-basic"} else {"a0aa5d5ea887d50871e16533fea58815343e6ee9:x-oauth-basic"}
$NewComputerName="edfisolsrv"
if (!([string]::IsNullOrEmpty($DnsName))) {
    $NewComputerName=$DnsName
    if ($DnsName.IndexOf(".") -gt 1) {
        $NewComputerName = $DnsName.Substring(0,$DnsName.IndexOf("."))
    }
    else {
        Write-Warning "WARNING!  Removing given DnsName because the provided string has no periods and therefore cannot be a complete DNS name!"
        $DnsName =$null
    }
}
# This can be updated in the config as MSSQLEURL as needed.
$MSSQLEURL = Get-ConfigParam $null $cfg.MSSQLEURL 'https://download.microsoft.com/download/8/4/c/84c6c430-e0f5-476d-bf43-eaaa222a72e0/SQLEXPR_x64_ENU.exe'
$SQLINST = Get-ConfigParam $null $cfg.MSSQLINST "MSSQLSERVER"
$PGSQLInstalled = $false
# Can be overridden but must include these definitions TODO: move to config file
$iisConfig=@{
    iisUser="IIS_IUSRS";
    defaultSiteName="Default Web Site";
    SiteName="Default Web Site";
    defaultApplicationPool = "DefaultAppPool";
    applicationPool = "DefaultAppPool";
    integratedSecurityUser = "IIS APPPOOL\DefaultAppPool" 
}
#
# Install type is typically Staging for Populated Template ODS or Prodution for Minimal Template
$InstallType = Get-ConfigParam $null $cfg.InstallType "Demo"
Write-Verbose "`n----------------`nConfiguration params:`nEd-Fi Dir:`"$EdFiDir`"`ndownloadPath:`"$downloadPath`"`nSolutionWebRoot:`"$SolutionWebRoot`"`nDnsName:`"$DnsName`"`newComputerName:`"$NewComputerName`"`nAdminEmail:`"$AdminEmail`"`nDDNSUrl:`"$DDNSUrl`"`nDDNSUsername:`"$DDNSUsername`"`nDDNSPassword:`"$DDNSPassword`"`nSolutionsAppName:`"$SolutionsAppName`"`nGitPrefix:`"$GitPrefix`"`nSQLINST:`"$SQLINST`"`nInstallType:`"$InstallType`""
Write-Verbose "iisConfig: $(Convert-HashtableToString $iisConfig)`n----------------`n"
#
# Save the old hostname for fixing install stuff. Then set the hostname right
$oldComputerName="$Env:ComputerName"
if (!($oldComputerName -like $NewComputerName)) {
#    Rename-Computer -NewName "$NewComputerName" -Force
    $netdomCmd = (Get-Command "netdom.exe" -ErrorAction SilentlyContinue).Source
#    & $netdomCmd computername "$NewComputerName" /add:"$DnsName"
    & $netdomCmd computername "$OldComputerName" /add:"$DnsName"
    Write-Verbose "Skipped Rename of Computer to $NewComputerName"
    $NewComputerName=$oldComputerName
}
#
# Enable Windows features - Must haves
Enable-RequiredWindowsFeatures -Verbose:$VerbosePreference
Write-Verbose "Windows Features enabled"
#
# Install all core dependencies and important tools with Chocolatey Package Manager
#  can be tweaked in config as needed but all are required to be installed
$tooVerbose=Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Verbose:$VerbosePreference
Write-Verbose "$tooVerbose"
Write-Verbose "Nuget package provider installed"
Install-Choco $cfg.dotnetcorePackage.package -Version $cfg.dotnetcorePackage.version -Verbose:$VerbosePreference
Write-Verbose "Installed Package: $($cfg.dotnetcorePackage.package) Version: $($cfg.dotnetcorePackage.version)"
Install-Choco $cfg.baseChocoPackages  -Verbose:$VerbosePreference
Write-Verbose "Installed Packages $($cfg.baseChocoPackages)"
# Configure public DNS hostname and use it to get Lets Encrypt SSL Cert 
$hostIP=Get-ExternalIP -Verbose:$VerbosePreference
Write-Verbose "Host IP: $hostIP"
if (![string]::IsNullOrEmpty($DnsName) -and ("edfisolsrv" -ne $DnsName)) {
    # Add the dns name to loopback address in servers hosts file to avoid any network vs web app config issues
    Add-NameToHostsFile $DnsName
    # Now update Dynamic DNS if credentials supplied   
    if ($null -ne $dynCredentials -and ![string]::IsNullOrEmpty($DDNSUrl)) {
        Update-DynDNS -HostDNS $DnsName -IP $hostIP -ProviderUrl $DDNSUrl -Credentials $dynCredentials -Verbose:$VerbosePreference
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
    if ([string]$cfg.optionalChocoPackages -like '*microsoft-edge*') {
        Update-MSEdgeAssociations -Verbose:$VerbosePreference
    }
}
#
# Check and install SQL server if needed
$SQLINST = Install-MSSQLserverExpress -FilePath $downloadPath -MSSQLEURL $MSSQLEURL -SQLINST $SQLINST -Verbose:$VerbosePreference
Write-Verbose "SQL Server instance: $SQLINST"
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
#
# Add IIS special integrated user to SQL Server login along with those in Users group for Demo mode
Add-SQLIntegratedSecurityUser -UserName $iisConfig.integratedSecurityUser -IntegratedSecurityRole 'sysadmin' -SQLServerName "." -Verbose:$VerbosePreference
# Now get all of the Users group (if Demo) members added to make this actually work
if ($InstallType -like "Demo") {
    $LocalUsers=(@(Get-LocalGroupMember "Users") | Where-Object {$_.ObjectClass -like "User"}).Name
    foreach ($usr in $LocalUsers) {
        Update-SQLIntegratedSecurityUser -UserName $usr -ComputerName $NewComputerName -PreviousComputerName $oldComputerName -IntegratedSecurityRole 'sysadmin' -SQLServerName "." -Verbose:$VerbosePreference
    }
}
#
# Get the list of Solutions from the config file
$solutionsInstall = $solcfg.solutions | Where-Object {[string]::IsNullOrEmpty($SolutionName) -or $_.name -match $SolutionName}
if (($null -eq $solutionsInstall) -or ($solutionsInstall.Count -eq 0)) {
    Write-Verbose "No solutions found matching: $SolutionName `n Check your configuration file and verify the name given for -SolutionName."
    $SolutionName="base"
    $solutionsInstall = $solcfg.solutions | Where-Object {$_.name -match $SolutionName}
}
if ($null -eq $solutionsInstall) {
    throw "No Solutions Configured! Installation cannot continue please make sure your solutions configuration file is available."
}
# Select versions required by listed solutions
$EdFiVersions = $solutionsInstall | ForEach-Object {$_.EdFiVersion} | Sort-Object -Unique
# Now get needed versions of the ODS/API, Admin App, AMT, and Data Import installed
foreach ($ver in $EdFiVersions) {
    Write-Verbose "Installing Ed-Fi Suite with v$ver of ODS-API"
    Install-BaseEdFi $InstallType $ver $DnsName $EdFiDir $iisConfig -Verbose:$VerbosePreference
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
        elseif (($link.type -eq "URL") -and !($link.URI -like "http*")) {
            if ($link.URL -like "/*") {
                $link.URI = $link.URI -Replace "^","https://$DnsName"
            }
            else {
                $link.URI = $link.URI -Replace "^","https://$DnsName/"
            }
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
    @{ name= "Ed-Fi Solutions Homepage"; type= "URL"; URI="https://$DnsName/EdFi" }
    )
Add-DesktopAppLinks $LocalAppLinks ".."
Write-Verbose "Preparing for Windows Update"
Stop-Transcript
Install-Module PSWindowsUpdate -Force
Add-WUServiceManager -MicrosoftUpdate -confirm:$false
$announcement = @"
***************************************************************
*                                                             *
*  Complete: Ed-Fi Solution Installation                      *
*  Begin: Windows Update                                      *
*           to install security fixes/updates                 *
*                                                             *
* See Solution installation packages while you wait:          *
*                                                             *
*   https://$DnsName/EdFi                                     *
*                                                             *
*  !!! You can press CTRL-C to stop the update process  !!!   *
*  !!!  if you prefer to update later.                  !!!   *
*                                                             *
***************************************************************
"@
Write-Host $announcement
Write-Verbose "Performing Windows Update"
#
# Now force a full update
#
# Get-WindowsUpdate
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot
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
