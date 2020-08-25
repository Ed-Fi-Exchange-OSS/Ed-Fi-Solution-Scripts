function Get-ConfigParam {
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
    param (
        $param,
        $configParam,
        $default=$null
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
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
    param ()
    $tooVerbose=Add-WindowsCapability -Online -Name OpenSSH.Client
    Write-Verbose "$tooVerbose"
    $tooVerbose=Install-WindowsFeature -name NET-Framework-45-Core,NET-Framework-45-ASPNET
    Write-Verbose "$tooVerbose"
    $tooVerbose=Install-WindowsFeature -name Web-Server,Web-Common-Http,Web-Windows-Auth,Web-Basic-Auth,Web-App-Dev,Web-Net-Ext45,Web-Asp-Net45,Web-ISAPI-Ext,Web-ISAPI-Filter -IncludeManagementTools
    Write-Verbose "$tooVerbose"
#    Install-WindowsFeature -name RSAT-AD-PowerShell
}
function Install-Choco {
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $Packages,
        [string] $Version,
        [string] $InstallPath = "C:\Ed-Fi"
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
    # Attempt choco installs of key pre-reqs and tools 
    #
    if ($Version) {
        # Will only work with one package at a time
        Write-Verbose "Installing package: $Packages version: $Version"
        Start-Process -Wait -FilePath $ChocoPath -ArgumentList "install",$Packages,"--version=$Version","-y","--no-progress" -NoNewWindow -RedirectStandardOutput "choco_$($Packages)_log.txt" -RedirectStandardError "choco_$($Packages)_err.txt"
    } else {
        Write-Verbose "Installing packages: $Packages"
        Start-Process -Wait -FilePath $ChocoPath -ArgumentList "upgrade",$Packages,"-y","--no-progress" -NoNewWindow -RedirectStandardOutput "choco_$($Packages.Substring(0,3))-set_log.txt" -RedirectStandardError "choco_$($Packages.Substring(0,3))-set_err.txt"
    }
    Update-SessionEnvironment
}
function Copy-GitRepo {
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $repoURL,
        [string] $InstallPath,
        [string] $keyPath
    )
    Write-Verbose "Cloning repo: $repoURL to $InstallPath"
    if (!(Get-Command "git.exe" -ErrorAction SilentlyContinue)) {
        Install-Choco "git"
        if(!(Test-Path "C:\Program Files\Git\cmd\git.exe")) {
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
    [CmdletBinding(DefaultParameterSetName='FilePathSet',HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
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
        if (! $(Try { Test-Path $DownloadsPath.trim() } Catch { $false }) ) {
            New-Item -ItemType Directory -Force -Path $DownloadsPath
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
    if (Test-Path $FilePath -PathType Container) {
        Write-Error "Folder at Path: $FilePath already exists! Canceling download and extract"
        return
    }
    else {
        if (Test-Path $FilePath -PathType Leaf) {
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
    if (Test-Path $InstallPath -PathType Leaf) {
        Write-Verbose "Warning! Install Path not empty: $InstallPath `n Attempting to overwrite anyway."
        # Remove-Item $InstallPath -Recurse -Force
    }
    $tooVerbose=Expand-Archive -LiteralPath $FilePath -DestinationPath $InstallPath -Force
    Write-Verbose "Expand-Archive: $tooVerbose"
}
function Install-NugetPackage {
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $packageName,
        [string] $version,
        [string] $packageSource = "https://www.myget.org/F/ed-fi/",
        [string] $FilePath = "C:\Ed-Fi\Downloads"
    )
    # Verify that the Downloads folder is present
    if (! $(Try { Test-Path $FilePath.trim() } Catch { $false }) ) {
        New-Item -ItemType Directory -Force -Path $FilePath
    }    
    $downloadedPackagePath = Join-Path $FilePath "$packageName.$version"
    if (!(Get-Command "nuget.exe" -ErrorAction SilentlyContinue)) {
        Install-Choco "nuget.commandline"
        if(!(Test-Path "C:\ProgramData\chocolatey\bin\nuget.exe")) {
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
    $nugetCMD=Start-Process -Wait -FilePath $nugetPath -NoNewWindow -ArgumentList "install $packageName","-source $packageSource","-Version $version","-outputDirectory $FilePath","-NoCache" -RedirectStandardOutput "nuget_$version_log.txt" -RedirectStandardError "nuget_$version_err.txt"
    if ($nugetCMD.ExitCode -ne 0) {
        throw "Failed to install package $packageName $version"
    }
    return $downloadedPackagePath
}
function Get-ExternalIP(){
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
    param ()
    try {
        $ExtIP = Invoke-WebRequest -Uri "https://showextip.azurewebsites.net/" -Method Get -TimeoutSec 10 -UseBasicParsing
    }
    catch { 
        Write-Error "Failed to discover public IP address.  Error: $_ "
        return $false
    } 
    $IPregex='(?<Address>(\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b))'
    if ($ExtIP.Content -Match $IPregex) {
        return $Matches.Address
    }
    else {
        Write-Error "Failed to parse IP address from showextip.  Error: $_ "
        return $false
    }
}
function Update-DynDNS {
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $HostDNS,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $IP,
        [pscredential]$Credentials
    )
    # Uses the REST interface for Dyn.com.
    if (!$IP) {
        $IP=Get-ExternalIP
    }
    # TODO: Special exception for my demo setup
    # Replacing demo.kerlick.com
    if ($HostDNS -eq "demo.kerlick.com") {
        $HostDNS="kerlickcp.dyndns.org"
    }
    try {
        "Updating DDNS for {0} with IP {1}" -f $HostDNS, $IP | Write-Verbose
        $Result = Invoke-RestMethod -Uri "https://members.dyndns.org/nic/update?hostname=$HostAddress&myip=$IP" -Credential $Credentials -UserAgent "EdFiAlliance SolutionBuilder"
        Write-Verbose "DDNS updated"
    }
    catch {
        Write-Error "Failed to update Dynamic DNS entry.  Error: $_ "
        return $false 
    }
    return $Result
}
# Ensure all prerequisites are installed.
# Region: Self Signed Certificate Functions
function Get-SelfSignedCertificate {
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
    param (
        [string] $DnsName,
        [string] $CertName="localhost Self-Signed",
        [string] $FilePath="C:\Ed-Fi"
    )
    # Verify that the file folder is present
    if (! $(Try { Test-Path $FilePath.trim() } Catch { $false }) ) {
        New-Item -ItemType Directory -Force -Path $FilePath
    }    
    # Returns the Certificate Thumbprint if successful
    # Stores Self-Signed Cert in Cert:\LocalMachine\My and then in Cert:\LocalMachine\Root to avoid problems with invalid cert chains
    # See if we already have it installed.
    $certificates = Get-ChildItem Cert:\LocalMachine\My
    foreach($cert in $certificates) {
        if ($cert.FriendlyName -eq $CertName) { 
            Write-Verbose "Found Self-Signed Cert Thumbprint: $($cert.Thumbprint)"
            return $cert.Thumbprint
        }
    }
    #Create self signed certificate
    $hostnames = @("localhost")
    if ([string]::IsNullOrEmpty($DnsName)) {
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
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $DnsName,
        $CertName="Ed-Fi Solution Installer",
        $AdminEmail="techsupport@ed-fi.org"
    )
    # Check for existing certificate first
    $certificates = Get-ChildItem Cert:\LocalMachine\WebHosting
    foreach($cert in $certificates) { 
        if($cert.Subject -eq "CN=$DnsName") { 
            $cert.FriendlyName=$CertName
            Write-Verbose "Found SSL Cert for $DnsName with Thumbprint: $($cert.Thumbprint)"
            return $cert.Thumbprint
        } 
    }
    if (!(Get-Command "wacs" -ErrorAction SilentlyContinue)) {
        Install-Choco "win-acme"
    }
    try {
        # The Win-Acme client will do all of the work of calling the API, storing the certificate,
        # and adding it to the matching host entry in IIS
        Start-Process "wacs" -Wait -ArgumentList "--target iis --host $DnsName --accepttos --emailaddress $AdminEmail" -RedirectStandardOutput "winacme_ssl_cert_log.txt" -RedirectStandardError "winacme_ssl_cert_err.txt"
        Write-Verbose "Windows Acme Client Services completed SSL certificate request.`nCheck WACS log files for more info:`nwinacme_ssl_cert_log.txt`nwinacme_ssl_cert_err.txt"
    }
    catch {
        Write-Error "WACS failed to generate a certifcate from Lets Encrypt.  Error: $_ "
        return
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
function Enable-WebServerSSL {
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
    param (
        [string] $InstallPath,
        [string] $HostDNS,
        [string] $AdminEmail='techsupport@ed-fi.org'
    )
    $defaultSiteName = "Default Web Site"
    $httpsBinding=$null
    #
    # Configure IIS to use Lets Encrypt SSL Cert or Self-Signed, if needed
    #
    Set-Location $InstallPath    
    if($httpsBinding=Get-IISSiteBinding -Name $defaultSiteName -Protocol "https") {
        Write-Verbose "`nIIS is already configured for https on $defaultSiteName as $httpsBinding.`n  Quitting without changing SSL for IIS.`n"
        return
    }
    # No SSL binding found
    # Get self-signed certificate for localhost needs
    $selfSignedCert = Get-SelfSignedCertificate -DnsName $HostDNS -CertName "localhost Self-Signed" -FilePath $InstallPath
    $newCert=$null
    $certStoreLocation = "Cert:\LocalMachine\WebHosting"
    # need to add the hostname binding to make sure the Acme client will work, and it shouldn't break the usual wildcard entry 
    if ([string]::IsNullOrEmpty($HostDNS) -or ($HostDNS -like "localhost")) {
        $HostDNS="localhost"
        $certStoreLocation = "Cert:\LocalMachine\My"
        try {
            # Stop the IIS Site while we fix SSL
            Stop-IISSite -Name $defaultSiteName
            Write-Verbose "Command:`n New-IISSiteBinding -name `"$defaultSiteName`" -BindingInformation `"*:443:*`" -protocol https -CertStoreLocation $certStoreLocation -CertificateThumbPrint `"$($selfSignedCert.Thumbprint)`"`n"
            $httpsBinding = New-IISSiteBinding -name "$defaultSiteName" -BindingInformation "*:443:*" -protocol https -CertStoreLocation $certStoreLocation -CertificateThumbPrint "$($selfSignedCert.Thumbprint)"
            return
        }
        catch {
            Write-Error "Error while binding IIS to $defaultSiteName on https for localhost with Certificate:$selfSignedCert.`n Error: $_"
        }
        finally {
            # Restart IIS Site
            Start-IISSite -Name $defaultSiteName
        }
    }
    # In case you passed in localhost, don't go tryin to create a cert for that, not even a little bit.
    if (!($HostDNS -like "*localhost*")) {
        # Add a binding to the given hostname in case the system does not recognize that name as being local yet
        try {
            New-IISSiteBinding -name $defaultSiteName -BindingInformation "*:80:$HostDNS" -protocol "http"
        }
        catch {
            Write-Verbose "Warning:`n Failed to set IIS binding for $HostDNS on http.`n Attempting to get LE cert anyway `n  Exception was: $_ `n"
        }
        # free Let's Encrypt cert for given hostname
        $newCert = Get-LetsEncSSLCert -DnsName $HostDNS -CertName "Ed-Fi Solution Installer" -AdminEmail $AdminEmail
        # In case of a null cert from silent fail, we'll try to bind anyway with Self-Signed
    }
    if ($null -ne $newCert) { 
        try {
            Write-Verbose "Command:`n New-IISSiteBinding -name $defaultSiteName -BindingInformation `"*:443:$HostDNS`" -protocol https -CertificateThumbPrint `"$($newCert.Thumbprint)`"  -CertStoreLocation $certStoreLocation`n"
            $httpsBinding = New-IISSiteBinding -name $defaultSiteName -BindingInformation "*:443:$HostDNS" -protocol https -CertificateThumbPrint "$($newCert.Thumbprint)"  -CertStoreLocation $certStoreLocation
        }
        catch {
            Write-Error "Error while binding IIS to $defaultSiteName on https for $HostDNS with Certificate:$LESignedCert `n Error: $_ `n"
        }
        try {
            # Now add trusted self-signed cert to localhost, may require some manual re-map in IIS Manager. 
            $certStoreLocation = "Cert:\LocalMachine\My"
            Write-Verbose "Command:`n New-IISSiteBinding -name $defaultSiteName -BindingInformation `"*:443:localhost`" -protocol https -CertificateThumbPrint `"$($selfSignedCert.Thumbprint)`"  -CertStoreLocation $certStoreLocation`n"
            $httpsBinding = New-IISSiteBinding -name $defaultSiteName -BindingInformation "*:443:localhost" -protocol https -CertificateThumbPrint "$($selfSignedCert.Thumbprint)"  -CertStoreLocation $certStoreLocation
        }
        catch {
            Write-Error "Error while binding IIS to $defaultSiteName on https for $HostDNS with Certificate:$LESignedCert `n Error: $_ `n"
        }
    }
    else {
        Write-Verbose "Warning:`n Couldn't get Let's Encrypt certificate, will fallback to using self-signed cert for localhost and DNS name if given`n"
        $certStoreLocation = "Cert:\LocalMachine\My"
        Write-Verbose "Command:`n New-IISSiteBinding -name `"$defaultSiteName`" -BindingInformation `"*:443:*`" -protocol https -CertStoreLocation $certStoreLocation -CertificateThumbPrint `"$($selfSignedCert.Thumbprint)`"`n"
        $httpsBinding = New-IISSiteBinding -name "$defaultSiteName" -BindingInformation "*:443:*" -protocol https -CertStoreLocation $certStoreLocation -CertificateThumbPrint "$($selfSignedCert.Thumbprint)"
    }
    #
    Write-Verbose "IIS is configured for https on $defaultSiteName as $httpsBinding`n "
}
function Enable-TCPonSQLInstance {
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
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
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
    param ([string] $FilePath="C:\Ed-Fi")
     # Verify that the file folder is present
     if (! $(Try { Test-Path $FilePath.trim() } Catch { $false }) ) {
        New-Item -ItemType Directory -Force -Path $FilePath
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
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
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
function Add-UserSQLIntegratedSecurity {
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
    param (
        $Username = "IIS APPPOOL\DefaultAppPool",
        $IntegratedSecurityRole = 'sysadmin',   # Should this be less powerful?
        $SQLServerName="."                      # Local machine by default
    )
    $server = New-Object Microsoft.SqlServer.Management.Smo.Server $SQLServerName
    if (!($server.Logins.Contains($Username))) {
        Write-Verbose "Adding $Username to $IntegratedSecurityRole on SQL Server: $SQLServerName"
        $SqlUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $server, $Username
        $SqlUser.LoginType = [Microsoft.SqlServer.Management.Smo.LoginType]::WindowsUser
        $sqlUser.PasswordPolicyEnforced = $false
        $SqlUser.Create()
        $serverRole = $server.Roles | Where-Object {$_.Name -eq $IntegratedSecurityRole}
        $serverRole.AddMember($Username)
        Write-Verbose "Added User: $Username to Role: $IntegratedSecurityRole for SQL Server: $SQLServerName"
    }
    else {
        Write-Verbose "User already configured for Integrated Security."
    }
}
function Install-MSSQLserverExpress {
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
    param (
        [string] $FilePath="C:\Ed-Fi\Downloads",
        [string] $MSSQLEURL="https://download.microsoft.com/download/8/4/c/84c6c430-e0f5-476d-bf43-eaaa222a72e0/SQLEXPR_x64_ENU.exe",
        [string] $SQLINST="MSSQLSERVER"
    )
    # Verify that the file folder is present
    if (! $(Try { Test-Path $FilePath.trim() } Catch { $false }) ) {
        New-Item -ItemType Directory -Force -Path $FilePath
    }    
    #
    if (Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL") {
        $sqlInstances = Get-ChildItem "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names"
        Write-Verbose "SQL Server installation found with instances:`n $($sqlInstances|ForEach-Object {$_.Property}) `n"
        # Get SQL Server PowerShell support from the PS Gallery
        Install-SqlServerModule
        # Ensure TCP Connectivity is enabled
        $SQLINST=$sqlInstances[0].Property
        Enable-TCPonSQLInstance -SQLINST $SQLINST
        return $SQLINST
    }
    # No SQL instances found.
    # Install MS SQL Server Express 2019
    # 
    $MSSEFILE = "$FilePath\SQLEXPR_x64_ENU.exe"
    $MSSEPATH = "$FilePath\SQLEXPR_x64_ENU"
    $MSSESETUP = "$MSSEPATH\setup.exe"
    # Download, unpack, and install while setting the default instance name - will probably need to periodically refreshed until choco install works 
    if (!$(Try { Test-Path $MSSEFILE.trim() } Catch { $false })) {
        try {
            Invoke-WebRequest -Uri $MSSQLEURL -OutFile $MSSEFILE
        }
        catch {
            Write-Error "Failed to download SQL Server Express from $MSSQLEURL and store in $MSSEFILE  Check URL and permission on path.  Error: $_"
        }
    }
    if (!$(Try { Test-Path $MSSEPATH.trim() } Catch { $false })) {
        Start-Process $MSSEFILE -wait -RedirectStandardOutput $MSSEPATH\extract_log.txt -RedirectStandardError $MSSEPATH\extract_error_log.txt -ArgumentList "/q","/x:$MSSEPATH"
    }
    if (!$(Try { Test-Path $MSSESETUP.trim() } Catch { $false })) {
        Start-Process $MSSEFILE -wait -RedirectStandardOutput $MSSEPATH\extract_log.txt -RedirectStandardError $MSSEPATH\extract_error_log.txt -ArgumentList "/q","/x:$MSSEPATH"
    }
    if (!$(Try { Test-Path $MSSESETUP.trim() } Catch { $false })) {
        Write-Verbose "$MSSESETUP not found after download and extract!"
        Write-Verbose "Failed to install SQL Server Express!"
        return
    }
    Start-Process $MSSEFILE -wait -WorkingDirectory $MSSEPATH -RedirectStandardOutput $MSSEPATH\setup_log.txt -RedirectStandardError $MSSEPATH\setup_error_log.txt -ArgumentList "/IACCEPTSQLSERVERLICENSETERMS","/Q","/ACTION=install","/INSTANCEID=$SQLINST","/INSTANCENAME=$SQLINST","/UPDATEENABLED=FALSE"
    #
    Update-SessionEnvironment
    # If SQL Express manual install failed, try Choco. 
    # This will use the default SQL Express instance name so we
    # change SQLINST 
    if (!(Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL")) {
        $SQLINST = "SQLEXPRESS"
        Install-Choco "sql-server-express"
    }
    if (!(Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL")) {
        throw "SQL Server failed to install, installation canceled" 
    }
        #
    Install-SqlServerModule
    #
    # Use freshly installed MS SQL Server
    Enable-TCPonSQLInstance -SQLINST $SQLINST
    # !!!!!
    # The default passwords may not work for SQL Auth, so this step we'll weaken them.
    # This shouldn't be necessary for auto-generated passwords on most cloud provider builds
    # !!!!!
    Set-WeakPasswordComplexity -FilePath $FilePath
    return $SQLINST
        #
}
function Initialize-Postgresql {
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
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

    if (-not (Test-Path $psqlHome)) {
        throw "Required Postgres path not found: $psqlHome"
    }

    Write-Verbose "Prepending $psqlHome to the PATH."
    $env:Path = "$psqlHome\bin;" + $env:Path
    if (!$Env:PGDATA) { $Env:PGDATA = $psqlHome + "\data" }
    if (!$Env:PGLOCALEDIR) { $Env:PGLOCALEDIR = $psqlHome + "\share\locale" }
    if (!$Env:PGPORT) { $Env:PGPORT = "5432" }
}
function Set-PermissionsOnPath {
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory=$True)]$FilePath, 
        [Parameter(Mandatory=$True)]$User, 
        [Parameter(Mandatory=$True)]$Perms
        )
    $ACL = Get-Acl $FilePath
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]"None"
    $AccessControlType =[System.Security.AccessControl.AccessControlType]::Allow
    $Account = New-Object System.Security.Principal.NTAccount($User)
    if ("NoAccess" -eq $Perms) {  # This is meant to Deny CRUD
        $FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify,ReadAndExecute"
        $FileSystemAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Account, $FileSystemRights, $InheritanceFlag, $PropagationFlag, $AccessControlType)
        $ACL.RemoveAccessRuleAll($FileSystemAccessRule)
    }
    else {
        $FileSystemRights = [System.Security.AccessControl.FileSystemRights]$Perms
        $FileSystemAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Account, $FileSystemRights, $InheritanceFlag, $PropagationFlag, $AccessControlType)
        $ACL.SetAccessRule($FileSystemAccessRule) # or $ACL.AddAccessRule($FileSystemAccessRule)
    }
    Set-Acl $FilePath $ACL
}
function Add-DesktopAppLinks {
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
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
    if (! $(Try { Test-Path $EdFiSolFolder } Catch { $false }) ) {
        New-Item -ItemType Directory -Force -Path $EdFiSolFolder 
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
}
    function Add-WebAppLinks {
        [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
        param (
            $AppURIs,
            $DnsName,
            $SolutionName="Ed-Fi Tools",
            $EdFiWebDir="C:\Ed-Fi\www"
        )
        # Example of what to pass in
        # $appURLs = @( 
        #               @{ name= "Link to a file"; type= "File"; URI="relative\\path\\file.ext" };
        #               @{ name= "WebLnk"; type= "URL"; URI="https://github.com/Ed-Fi-Alliance-OSS/Ed-Fi-ODS-AdminApp" }
        #             )
        #
        Write-Verbose "Adding Solution Links to Ed-Fi Solutions website for local IIS homepage"
        $solHtmlFile="$EdFiWebDir\SolutionItems.html"
        if (! $(Try { Test-Path $solHtmlFile } Catch { $false }) ) {
            if (! $(Try { Test-Path $solHtmlFile } Catch { $false }) ) {
                New-Item -ItemType Directory -Force -Path $EdFiWebDir
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
        [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
        param (
            $SolutionWebDir="C:\Ed-Fi\www",
            $VirtualDirectoryName="EdFiWWW",
            $AppName="EdFiSolutions",
            $iisConfig=@{ iisUser="IIS_IUSRS"; defaultSiteName="Default Web Site"; applicationPool = "DefaultAppPool"; integratedSecurityUser = "IIS APPPOOL\DefaultAppPool" }
        )
        Write-Verbose "Generating Ed-Fi Solutions website for local IIS homepage"
        $solutionsHtml="$SolutionWebDir\SolutionItems.html"
        $headerHtml="$SolutionWebDir\SolutionHeader.html"
        $footerHtml="$SolutionWebDir\SolutionFooter.html"
        $indexHtml="$SolutionWebDir\index.html"
        Set-PermissionsOnPath -Path $SolutionWebDir -User $iisConfig.iisUser -Perms "ReadAndExecute"
        Get-Content -Path $headerHtml | Set-Content $indexHtml
        Get-Content -Path $solutionsHtml | Add-Content -Path $indexHtml
        Get-Content -Path $footerHtml | Add-Content -Path $indexHtml
        if ($null -eq (Get-WebApplication -Name $AppName)) {
            New-WebVirtualDirectory -Site $iisConfig.defaultSiteName -Name $VirtualDirectoryName -PhysicalPath $SolutionWebDir -Force
            New-WebApplication -Name $AppName  -Site "$($iisConfig.defaultSiteName)\$VirtualDirectoryName" -PhysicalPath $SolutionWebDir -ApplicationPool $($iisConfig.applicationPool) -Force    
        }

    }